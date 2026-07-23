/* psa_its_transform_wolfcrypt.c
 *
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * This file is part of wolfPSA.
 *
 * wolfPSA is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * wolfPSA is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

/*
 * wolfCrypt-backed implementation of the Zephyr secure_storage ITS "transform"
 * module (CONFIG_SECURE_STORAGE_ITS_TRANSFORM_IMPLEMENTATION_CUSTOM).
 *
 * Zephyr's stock AEAD transform (subsys/secure_storage/src/its/transform/
 * aead.c) is hardwired to Mbed TLS core internals: it calls
 * psa_driver_wrapper_aead_encrypt/decrypt and mbedtls_platform_zeroize, which
 * are compiled only under CONFIG_MBEDTLS. Selecting the CUSTOM transform makes
 * secure_storage use this file instead, so a wolfPSA build links no Mbed TLS
 * symbol at all: all storage-path crypto runs through wolfCrypt.
 *
 * Provides confidentiality and integrity at rest with AES-256-GCM. The stored
 * layout is:
 *
 *   [ packed create_flags : 1 ][ nonce : 12 ][ ciphertext : data_len ][ tag : 16 ]
 *
 * so the transform adds NONCE + TAG = 28 bytes beyond the plaintext (the
 * create_flags byte is accounted separately by the secure_storage framing);
 * CONFIG_SECURE_STORAGE_ITS_TRANSFORM_OUTPUT_OVERHEAD must therefore be 28. The
 * per-entry key is derived from a device identifier (HW info when available)
 * salted with the entry UID, and the GCM AAD binds the create_flags and UID so
 * a stored record cannot be substituted across UIDs or flags. Unlike the
 * stock aead.c, this uses raw wolfCrypt (stack-local Aes) and never re-enters
 * the PSA keystore, so it is safe to run while a persistent key is mid-save.
 *
 * Security limits (see the "Security considerations" note in zephyr/README.md):
 * the device-id key derivation is not necessarily secret, and the transform has
 * no rollback protection. Production targets should provision a hardware-backed
 * key and, where replay matters, a monotonic anti-rollback mechanism.
 */

#include <wolfssl/wolfcrypt/settings.h>
#include <psa/crypto.h>   /* full PSA status/error set (secure_storage's psa/error.h is a subset) */
#include <zephyr/secure_storage/its/transform.h>

#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/wc_port.h>

#if defined(CONFIG_HWINFO)
#include <zephyr/drivers/hwinfo.h>
#endif

#define WOLFPSA_ITS_NONCE_SZ 12
#define WOLFPSA_ITS_TAG_SZ   16
#define WOLFPSA_ITS_KEY_SZ   32
#define WOLFPSA_ITS_FLAGS_SZ ((int)sizeof(secure_storage_packed_create_flags_t))

/* The overhead the app declares to secure_storage must match this transform.
 * The framing sizes the stored buffer as MAX_DATA + sizeof(create_flags) +
 * OUTPUT_OVERHEAD (see secure_storage/its/common.h), i.e. the flags byte is
 * counted separately, so OUTPUT_OVERHEAD covers only the nonce and tag. */
BUILD_ASSERT(CONFIG_SECURE_STORAGE_ITS_TRANSFORM_OUTPUT_OVERHEAD
    == WOLFPSA_ITS_NONCE_SZ + WOLFPSA_ITS_TAG_SZ,
    "CONFIG_SECURE_STORAGE_ITS_TRANSFORM_OUTPUT_OVERHEAD must be 28 "
    "(12-byte nonce + 16-byte AES-GCM tag) for the wolfCrypt ITS transform");

/* The stored layout puts create_flags in a single leading byte (stored_data[0],
 * read back at from_store); assert the packed type is actually one byte so the
 * framing and this transform stay in agreement if the Zephyr type ever changes. */
BUILD_ASSERT(sizeof(secure_storage_packed_create_flags_t) == 1,
    "the wolfCrypt ITS transform assumes a single-byte packed create_flags");

/* Serialized (padding-free, fixed little-endian) uid: 8-byte uid || 4-byte
 * caller_id. Key derivation and the GCM AAD hash/copy these discrete fields
 * rather than the raw secure_storage_its_uid_t object representation, so they
 * never depend on struct padding -- a persistent key stays decryptable across
 * compilers/ABIs (GCC happens to zero the padding, but the C standard does
 * not require it). */
#define WOLFPSA_ITS_UID_SZ 12

static void wolfpsa_its_serialize_uid(secure_storage_its_uid_t uid,
    byte out[WOLFPSA_ITS_UID_SZ])
{
    uint64_t id = (uint64_t)uid.uid;
    uint32_t caller = (uint32_t)uid.caller_id;
    int i;

    for (i = 0; i < 8; i++) {
        out[i] = (byte)(id >> (8 * i));
    }
    for (i = 0; i < 4; i++) {
        out[8 + i] = (byte)(caller >> (8 * i));
    }
}

/* Derive the per-entry AES-256 key: SHA-256(device-id || uid). The uid salt
 * gives every entry a distinct key. A device id is not a strong secret (it can
 * be readable, non-unique, or guessable), so production targets should provision
 * a hardware-backed key instead; see the README security note. On targets
 * without a HW device id (e.g. native_sim) a fixed constant is hashed instead:
 * this is functional but not secret, matching the caveat on Zephyr's own
 * device-id/uid key providers. When CONFIG_HWINFO is configured but the driver
 * returns no id, key derivation fails closed (PSA_ERROR_HARDWARE_FAILURE) rather
 * than silently falling back to a device-independent key. */
static psa_status_t wolfpsa_its_derive_key(secure_storage_its_uid_t uid,
    byte key[WOLFPSA_ITS_KEY_SZ])
{
    wc_Sha256 sha;
    byte uidbuf[WOLFPSA_ITS_UID_SZ];
    int rc;
#if defined(CONFIG_HWINFO)
    byte devid[16];
    ssize_t n;
#else
    /* ASCII bytes of "wolfPSA-its-key!" -- a fixed 16-byte domain-separation
     * seed used only when CONFIG_HWINFO is unavailable to supply a per-device
     * id. With no HWINFO the derived ITS key is not device-unique (the same
     * caveat Zephyr documents for its own fixed key provider). */
    static const byte fixed[16] = {
        0x77, 0x6f, 0x6c, 0x66, 0x50, 0x53, 0x41, 0x2d, /* "wolfPSA-" */
        0x69, 0x74, 0x73, 0x2d, 0x6b, 0x65, 0x79, 0x21  /* "its-key!" */
    };
#endif

    rc = wc_InitSha256(&sha);
    if (rc != 0) {
        return PSA_ERROR_GENERIC_ERROR;
    }

#if defined(CONFIG_HWINFO)
    n = hwinfo_get_device_id(devid, sizeof(devid));
    if (n > 0) {
        rc = wc_Sha256Update(&sha, devid, (word32)n);
    }
    else {
        /* CONFIG_HWINFO asked for a device-bound key but no device id is
         * available. Fail closed instead of silently deriving a
         * device-independent key that would weaken confidentiality at rest. */
        wc_ForceZero(devid, sizeof(devid));
        wc_Sha256Free(&sha);
        return PSA_ERROR_HARDWARE_FAILURE;
    }
    /* Scrub the device id from the stack once it has been hashed. */
    wc_ForceZero(devid, sizeof(devid));
#else
    rc = wc_Sha256Update(&sha, fixed, sizeof(fixed));
#endif

    if (rc == 0) {
        wolfpsa_its_serialize_uid(uid, uidbuf);
        rc = wc_Sha256Update(&sha, uidbuf, sizeof(uidbuf));
    }
    if (rc == 0) {
        rc = wc_Sha256Final(&sha, key);
    }
    wc_Sha256Free(&sha);

    return (rc == 0) ? PSA_SUCCESS : PSA_ERROR_GENERIC_ERROR;
}

/* Build the GCM additional-authenticated-data: create_flags || uid. This binds
 * a record to its UID and flags but carries no version or counter, so it does
 * not protect against rollback: an older ciphertext for the same UID still
 * authenticates. Anti-replay needs trusted monotonic state absent at this layer,
 * matching Zephyr's stock AEAD transform. See the README security note. */
static void wolfpsa_its_build_aad(secure_storage_packed_create_flags_t flags,
    secure_storage_its_uid_t uid,
    byte aad[WOLFPSA_ITS_FLAGS_SZ + WOLFPSA_ITS_UID_SZ])
{
    aad[0] = flags;
    wolfpsa_its_serialize_uid(uid, aad + WOLFPSA_ITS_FLAGS_SZ);
}

psa_status_t secure_storage_its_transform_to_store(
    secure_storage_its_uid_t uid, size_t data_len, const void *data,
    secure_storage_packed_create_flags_t create_flags,
    uint8_t stored_data[static SECURE_STORAGE_ITS_TRANSFORM_MAX_STORED_DATA_SIZE],
    size_t *stored_data_len)
{
    Aes aes;
    WC_RNG rng;
    byte key[WOLFPSA_ITS_KEY_SZ];
    byte aad[WOLFPSA_ITS_FLAGS_SZ + WOLFPSA_ITS_UID_SZ];
    byte *nonce = stored_data + WOLFPSA_ITS_FLAGS_SZ;
    byte *ct = nonce + WOLFPSA_ITS_NONCE_SZ;
    byte *tag = ct + data_len;
    psa_status_t status;
    int rc;
    int rng_init = 0;
    int aes_init = 0;

    status = wolfpsa_its_derive_key(uid, key);
    if (status != PSA_SUCCESS) {
        return status;
    }

    stored_data[0] = create_flags;
    wolfpsa_its_build_aad(create_flags, uid, aad);

    rc = wc_InitRng(&rng);
    if (rc == 0) {
        rng_init = 1;
        rc = wc_RNG_GenerateBlock(&rng, nonce, WOLFPSA_ITS_NONCE_SZ);
    }
    if (rc != 0) {
        status = PSA_ERROR_INSUFFICIENT_ENTROPY;
    }

    if (status == PSA_SUCCESS) {
        rc = wc_AesInit(&aes, NULL, INVALID_DEVID);
        if (rc == 0) {
            aes_init = 1;
            rc = wc_AesGcmSetKey(&aes, key, WOLFPSA_ITS_KEY_SZ);
        }
        if (rc == 0) {
            rc = wc_AesGcmEncrypt(&aes, ct, (const byte *)data, (word32)data_len,
                nonce, WOLFPSA_ITS_NONCE_SZ, tag, WOLFPSA_ITS_TAG_SZ,
                aad, (word32)sizeof(aad));
        }
        if (rc != 0) {
            status = PSA_ERROR_GENERIC_ERROR;
        }
    }

    if (aes_init) {
        wc_AesFree(&aes);
    }
    if (rng_init) {
        wc_FreeRng(&rng);
    }
    wc_ForceZero(key, sizeof(key));

    if (status == PSA_SUCCESS) {
        *stored_data_len = (size_t)WOLFPSA_ITS_FLAGS_SZ + WOLFPSA_ITS_NONCE_SZ
            + data_len + WOLFPSA_ITS_TAG_SZ;
    }
    return status;
}

psa_status_t secure_storage_its_transform_from_store(
    secure_storage_its_uid_t uid, size_t stored_data_len,
    const uint8_t stored_data[static SECURE_STORAGE_ITS_TRANSFORM_MAX_STORED_DATA_SIZE],
    size_t data_size, void *data, size_t *data_len,
    psa_storage_create_flags_t *create_flags)
{
    Aes aes;
    byte key[WOLFPSA_ITS_KEY_SZ];
    byte aad[WOLFPSA_ITS_FLAGS_SZ + WOLFPSA_ITS_UID_SZ];
    secure_storage_packed_create_flags_t flags;
    const byte *nonce;
    const byte *ct;
    const byte *tag;
    size_t ct_len;
    psa_status_t status;
    int rc;
    int aes_init = 0;

    if (stored_data_len < (size_t)WOLFPSA_ITS_FLAGS_SZ + WOLFPSA_ITS_NONCE_SZ
                          + WOLFPSA_ITS_TAG_SZ) {
        return PSA_ERROR_DATA_CORRUPT;
    }
    ct_len = stored_data_len - WOLFPSA_ITS_FLAGS_SZ - WOLFPSA_ITS_NONCE_SZ
             - WOLFPSA_ITS_TAG_SZ;
    if (ct_len > data_size) {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }

    flags = stored_data[0];
    nonce = stored_data + WOLFPSA_ITS_FLAGS_SZ;
    ct = nonce + WOLFPSA_ITS_NONCE_SZ;
    tag = ct + ct_len;

    status = wolfpsa_its_derive_key(uid, key);
    if (status != PSA_SUCCESS) {
        return status;
    }
    wolfpsa_its_build_aad(flags, uid, aad);

    rc = wc_AesInit(&aes, NULL, INVALID_DEVID);
    if (rc == 0) {
        aes_init = 1;
        rc = wc_AesGcmSetKey(&aes, key, WOLFPSA_ITS_KEY_SZ);
    }
    if (rc == 0) {
        rc = wc_AesGcmDecrypt(&aes, (byte *)data, ct, (word32)ct_len,
            nonce, WOLFPSA_ITS_NONCE_SZ, tag, WOLFPSA_ITS_TAG_SZ,
            aad, (word32)sizeof(aad));
    }

    if (aes_init) {
        wc_AesFree(&aes);
    }
    wc_ForceZero(key, sizeof(key));

    if (rc == AES_GCM_AUTH_E) {
        return PSA_ERROR_INVALID_SIGNATURE;
    }
    if (rc != 0) {
        return PSA_ERROR_GENERIC_ERROR;
    }

    *create_flags = flags;
    *data_len = ct_len;
    return PSA_SUCCESS;
}
