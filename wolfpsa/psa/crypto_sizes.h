/* crypto_sizes.h
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

#ifndef PSA_CRYPTO_SIZES_H
#define PSA_CRYPTO_SIZES_H

#include "psa/crypto_types.h"

#define PSA_BITS_TO_BYTES(bits) (((bits) + 7u) / 8u)
#define PSA_BYTES_TO_BITS(bytes) ((bytes) * 8u)
#define PSA_MAX_OF_THREE(a, b, c) ((a) <= (b) ? (b) <= (c) ? \
                                   (c) : (b) : (a) <= (c) ? (c) : (a))

#define PSA_ROUND_UP_TO_MULTIPLE(block_size, length) \
    (((length) + (block_size) - 1) / (block_size) * (block_size))


#define PSA_HASH_LENGTH(alg)                                        \
    (                                                               \
        PSA_ALG_HMAC_GET_HASH(alg) == PSA_ALG_MD5 ? 16u :           \
        PSA_ALG_HMAC_GET_HASH(alg) == PSA_ALG_RIPEMD160 ? 20u :     \
        PSA_ALG_HMAC_GET_HASH(alg) == PSA_ALG_SHA_1 ? 20u :         \
        PSA_ALG_HMAC_GET_HASH(alg) == PSA_ALG_SHA_224 ? 28u :       \
        PSA_ALG_HMAC_GET_HASH(alg) == PSA_ALG_SHA_256 ? 32u :       \
        PSA_ALG_HMAC_GET_HASH(alg) == PSA_ALG_SHA_384 ? 48u :       \
        PSA_ALG_HMAC_GET_HASH(alg) == PSA_ALG_SHA_512 ? 64u :       \
        PSA_ALG_HMAC_GET_HASH(alg) == PSA_ALG_SHA_512_224 ? 28u :   \
        PSA_ALG_HMAC_GET_HASH(alg) == PSA_ALG_SHA_512_256 ? 32u :   \
        PSA_ALG_HMAC_GET_HASH(alg) == PSA_ALG_SHA3_224 ? 28u :      \
        PSA_ALG_HMAC_GET_HASH(alg) == PSA_ALG_SHA3_256 ? 32u :      \
        PSA_ALG_HMAC_GET_HASH(alg) == PSA_ALG_SHA3_384 ? 48u :      \
        PSA_ALG_HMAC_GET_HASH(alg) == PSA_ALG_SHA3_512 ? 64u :      \
        PSA_ALG_HMAC_GET_HASH(alg) == PSA_ALG_ASCON_HASH256 ? 32u : \
        0u)


#define PSA_HASH_BLOCK_LENGTH(alg)                                  \
    (                                                               \
        PSA_ALG_HMAC_GET_HASH(alg) == PSA_ALG_MD5 ? 64u :           \
        PSA_ALG_HMAC_GET_HASH(alg) == PSA_ALG_RIPEMD160 ? 64u :     \
        PSA_ALG_HMAC_GET_HASH(alg) == PSA_ALG_SHA_1 ? 64u :         \
        PSA_ALG_HMAC_GET_HASH(alg) == PSA_ALG_SHA_224 ? 64u :       \
        PSA_ALG_HMAC_GET_HASH(alg) == PSA_ALG_SHA_256 ? 64u :       \
        PSA_ALG_HMAC_GET_HASH(alg) == PSA_ALG_SHA_384 ? 128u :      \
        PSA_ALG_HMAC_GET_HASH(alg) == PSA_ALG_SHA_512 ? 128u :      \
        PSA_ALG_HMAC_GET_HASH(alg) == PSA_ALG_SHA_512_224 ? 128u :  \
        PSA_ALG_HMAC_GET_HASH(alg) == PSA_ALG_SHA_512_256 ? 128u :  \
        PSA_ALG_HMAC_GET_HASH(alg) == PSA_ALG_SHA3_224 ? 144u :     \
        PSA_ALG_HMAC_GET_HASH(alg) == PSA_ALG_SHA3_256 ? 136u :     \
        PSA_ALG_HMAC_GET_HASH(alg) == PSA_ALG_SHA3_384 ? 104u :     \
        PSA_ALG_HMAC_GET_HASH(alg) == PSA_ALG_SHA3_512 ? 72u :      \
        0u)




#if defined(PSA_WANT_ALG_SHA3_224)
#define PSA_HMAC_MAX_HASH_BLOCK_SIZE 144u
#elif defined(PSA_WANT_ALG_SHA3_256)
#define PSA_HMAC_MAX_HASH_BLOCK_SIZE 136u
#elif defined(PSA_WANT_ALG_SHA_512)
#define PSA_HMAC_MAX_HASH_BLOCK_SIZE 128u
#elif defined(PSA_WANT_ALG_SHA_384)
#define PSA_HMAC_MAX_HASH_BLOCK_SIZE 128u
#elif defined(PSA_WANT_ALG_SHA3_384)
#define PSA_HMAC_MAX_HASH_BLOCK_SIZE 104u
#elif defined(PSA_WANT_ALG_SHA3_512)
#define PSA_HMAC_MAX_HASH_BLOCK_SIZE 72u
#elif defined(PSA_WANT_ALG_SHA_256)
#define PSA_HMAC_MAX_HASH_BLOCK_SIZE 64u
#elif defined(PSA_WANT_ALG_SHA_224)
#define PSA_HMAC_MAX_HASH_BLOCK_SIZE 64u
#else 
#define PSA_HMAC_MAX_HASH_BLOCK_SIZE 64u
#endif

#if defined(PSA_WANT_ALG_SHA_512) || defined(PSA_WANT_ALG_SHA3_512)
#define PSA_HASH_MAX_SIZE 64u
#elif defined(PSA_WANT_ALG_SHA_384) || defined(PSA_WANT_ALG_SHA3_384)
#define PSA_HASH_MAX_SIZE 48u
#elif defined(PSA_WANT_ALG_SHA_256) || defined(PSA_WANT_ALG_SHA3_256)
#define PSA_HASH_MAX_SIZE 32u
#elif defined(PSA_WANT_ALG_SHA_224) || defined(PSA_WANT_ALG_SHA3_224)
#define PSA_HASH_MAX_SIZE 28u
#else 
#define PSA_HASH_MAX_SIZE 20u
#endif




#define PSA_MAC_MAX_SIZE PSA_HASH_MAX_SIZE


#define PSA_AEAD_TAG_LENGTH(key_type, key_bits, alg)                        \
    (PSA_AEAD_NONCE_LENGTH(key_type, alg) != 0 ?                            \
     PSA_ALG_AEAD_GET_TAG_LENGTH(alg) :                                     \
     ((void) (key_bits), 0u))


#define PSA_AEAD_TAG_MAX_SIZE       16u
#define PSA_AEAD_MAX_PLAINTEXT_SIZE 4096u


#define PSA_VENDOR_RSA_MAX_KEY_BITS 4096u


#if defined(WOLFPSA_RSA_GEN_KEY_MIN_BITS)
#define PSA_VENDOR_RSA_GENERATE_MIN_KEY_BITS WOLFPSA_RSA_GEN_KEY_MIN_BITS
#else
#define PSA_VENDOR_RSA_GENERATE_MIN_KEY_BITS 1024
#endif


#if defined(PSA_WANT_DH_RFC7919_8192)
#define PSA_VENDOR_FFDH_MAX_KEY_BITS 8192u
#elif defined(PSA_WANT_DH_RFC7919_6144)
#define PSA_VENDOR_FFDH_MAX_KEY_BITS 6144u
#elif defined(PSA_WANT_DH_RFC7919_4096)
#define PSA_VENDOR_FFDH_MAX_KEY_BITS 4096u
#elif defined(PSA_WANT_DH_RFC7919_3072)
#define PSA_VENDOR_FFDH_MAX_KEY_BITS 3072u
#elif defined(PSA_WANT_DH_RFC7919_2048)
#define PSA_VENDOR_FFDH_MAX_KEY_BITS 2048u
#else
#define PSA_VENDOR_FFDH_MAX_KEY_BITS 0u
#endif


#if defined(PSA_WANT_ECC_SECP_R1_521)
#define PSA_VENDOR_ECC_MAX_CURVE_BITS 521u
#elif defined(PSA_WANT_ECC_BRAINPOOL_P_R1_512)
#define PSA_VENDOR_ECC_MAX_CURVE_BITS 512u
#elif defined(PSA_WANT_ECC_MONTGOMERY_448)
#define PSA_VENDOR_ECC_MAX_CURVE_BITS 448u
#elif defined(PSA_WANT_ECC_SECP_R1_384)
#define PSA_VENDOR_ECC_MAX_CURVE_BITS 384u
#elif defined(PSA_WANT_ECC_BRAINPOOL_P_R1_384)
#define PSA_VENDOR_ECC_MAX_CURVE_BITS 384u
#elif defined(PSA_WANT_ECC_SECP_R1_256)
#define PSA_VENDOR_ECC_MAX_CURVE_BITS 256u
#elif defined(PSA_WANT_ECC_SECP_K1_256)
#define PSA_VENDOR_ECC_MAX_CURVE_BITS 256u
#elif defined(PSA_WANT_ECC_BRAINPOOL_P_R1_256)
#define PSA_VENDOR_ECC_MAX_CURVE_BITS 256u
#elif defined(PSA_WANT_ECC_MONTGOMERY_255)
#define PSA_VENDOR_ECC_MAX_CURVE_BITS 255u
#else
#define PSA_VENDOR_ECC_MAX_CURVE_BITS 0u
#endif


#define PSA_TLS12_PSK_TO_MS_PSK_MAX_SIZE 128u


#define PSA_TLS12_ECJPAKE_TO_PMS_INPUT_SIZE 65u


#define PSA_TLS12_ECJPAKE_TO_PMS_DATA_SIZE 32u


#define PSA_VENDOR_PBKDF2_MAX_ITERATIONS 0xffffffffU


#define PSA_BLOCK_CIPHER_BLOCK_MAX_SIZE 16u


#define PSA_MAC_LENGTH(key_type, key_bits, alg)                                   \
    ((alg) & PSA_ALG_MAC_TRUNCATION_MASK ? PSA_MAC_TRUNCATED_LENGTH(alg) :        \
     PSA_ALG_IS_HMAC(alg) ? PSA_HASH_LENGTH(PSA_ALG_HMAC_GET_HASH(alg)) :         \
     PSA_ALG_IS_BLOCK_CIPHER_MAC(alg) ? PSA_BLOCK_CIPHER_BLOCK_LENGTH(key_type) : \
     ((void) (key_type), (void) (key_bits), 0u))


#define PSA_AEAD_ENCRYPT_OUTPUT_SIZE(key_type, alg, plaintext_length) \
    (PSA_AEAD_NONCE_LENGTH(key_type, alg) != 0 ?                      \
     (plaintext_length) + PSA_ALG_AEAD_GET_TAG_LENGTH(alg) :          \
     0u)


#define PSA_AEAD_ENCRYPT_OUTPUT_MAX_SIZE(plaintext_length)          \
    ((plaintext_length) + PSA_AEAD_TAG_MAX_SIZE)


#define PSA_AEAD_DECRYPT_OUTPUT_SIZE(key_type, alg, ciphertext_length) \
    (PSA_AEAD_NONCE_LENGTH(key_type, alg) != 0 &&                      \
     (ciphertext_length) > PSA_ALG_AEAD_GET_TAG_LENGTH(alg) ?      \
     (ciphertext_length) - PSA_ALG_AEAD_GET_TAG_LENGTH(alg) :      \
     0u)


#define PSA_AEAD_DECRYPT_OUTPUT_MAX_SIZE(ciphertext_length)     \
    (ciphertext_length)


#define PSA_AEAD_NONCE_LENGTH(key_type, alg) \
    (PSA_BLOCK_CIPHER_BLOCK_LENGTH(key_type) == 16 ? \
     PSA_ALG_AEAD_EQUAL(alg, PSA_ALG_CCM) ? 13u : \
     PSA_ALG_AEAD_EQUAL(alg, PSA_ALG_GCM) ? 12u : \
     0u : \
     (key_type) == PSA_KEY_TYPE_CHACHA20 && \
     PSA_ALG_AEAD_EQUAL(alg, PSA_ALG_CHACHA20_POLY1305) ? 12u : \
     (key_type) == PSA_KEY_TYPE_XCHACHA20 && \
     PSA_ALG_AEAD_EQUAL(alg, PSA_ALG_XCHACHA20_POLY1305) ? 24u : \
     (key_type) == PSA_KEY_TYPE_ASCON && \
     PSA_ALG_AEAD_EQUAL(alg, PSA_ALG_ASCON_AEAD128) ? 16u : \
     0u)


#define PSA_AEAD_NONCE_MAX_SIZE 24u



#define PSA_AEAD_UPDATE_OUTPUT_SIZE(key_type, alg, input_length)                             \
    (PSA_AEAD_NONCE_LENGTH(key_type, alg) != 0 ?                                             \
     PSA_ALG_IS_AEAD_ON_BLOCK_CIPHER(alg) ?                                              \
     PSA_ROUND_UP_TO_MULTIPLE(PSA_BLOCK_CIPHER_BLOCK_LENGTH(key_type), (input_length)) : \
     (input_length) : \
     0u)


#define PSA_AEAD_UPDATE_OUTPUT_MAX_SIZE(input_length)                           \
    (PSA_ROUND_UP_TO_MULTIPLE(PSA_BLOCK_CIPHER_BLOCK_MAX_SIZE, (input_length)))


#define PSA_AEAD_FINISH_OUTPUT_SIZE(key_type, alg) \
    (PSA_AEAD_NONCE_LENGTH(key_type, alg) != 0 &&  \
     PSA_ALG_IS_AEAD_ON_BLOCK_CIPHER(alg) ?    \
     PSA_BLOCK_CIPHER_BLOCK_LENGTH(key_type) : \
     0u)


#define PSA_AEAD_FINISH_OUTPUT_MAX_SIZE     (PSA_AEAD_MAX_PLAINTEXT_SIZE)


#define PSA_AEAD_VERIFY_OUTPUT_SIZE(key_type, alg) \
    (PSA_AEAD_NONCE_LENGTH(key_type, alg) != 0 &&  \
     PSA_ALG_IS_AEAD_ON_BLOCK_CIPHER(alg) ?    \
     PSA_BLOCK_CIPHER_BLOCK_LENGTH(key_type) : \
     0u)


#define PSA_AEAD_VERIFY_OUTPUT_MAX_SIZE     (PSA_AEAD_MAX_PLAINTEXT_SIZE)

#define PSA_RSA_MINIMUM_PADDING_SIZE(alg)                         \
    (PSA_ALG_IS_RSA_OAEP(alg) ?                                   \
     2u * PSA_HASH_LENGTH(PSA_ALG_RSA_OAEP_GET_HASH(alg)) + 1u :   \
     11u )


#define PSA_ECDSA_SIGNATURE_SIZE(curve_bits)    \
    (PSA_BITS_TO_BYTES(curve_bits) * 2u)


#define PSA_SIGN_OUTPUT_SIZE(key_type, key_bits, alg)        \
    (PSA_KEY_TYPE_IS_RSA(key_type) ? ((void) alg, PSA_BITS_TO_BYTES(key_bits)) : \
     PSA_KEY_TYPE_IS_ECC(key_type) ? PSA_ECDSA_SIGNATURE_SIZE(key_bits) : \
     PSA_KEY_TYPE_IS_ML_DSA(key_type) ? \
         ((void) alg, \
          (key_bits) == 128u ? 2420u : \
          (key_bits) == 192u ? 3309u : \
          (key_bits) == 256u ? 4627u : 0u) : \
     ((void) alg, 0u))

#define PSA_VENDOR_ECDSA_SIGNATURE_MAX_SIZE     \
    PSA_ECDSA_SIGNATURE_SIZE(PSA_VENDOR_ECC_MAX_CURVE_BITS)


#define PSA_SIGNATURE_MAX_SIZE      1

#if (defined(PSA_WANT_ALG_ECDSA) || defined(PSA_WANT_ALG_DETERMINISTIC_ECDSA)) && \
    (PSA_VENDOR_ECDSA_SIGNATURE_MAX_SIZE > PSA_SIGNATURE_MAX_SIZE)
#undef PSA_SIGNATURE_MAX_SIZE
#define PSA_SIGNATURE_MAX_SIZE      PSA_VENDOR_ECDSA_SIGNATURE_MAX_SIZE
#endif
#if (defined(PSA_WANT_ALG_RSA_PKCS1V15_SIGN) || defined(PSA_WANT_ALG_RSA_PSS)) && \
    (PSA_BITS_TO_BYTES(PSA_VENDOR_RSA_MAX_KEY_BITS) > PSA_SIGNATURE_MAX_SIZE)
#undef PSA_SIGNATURE_MAX_SIZE
#define PSA_SIGNATURE_MAX_SIZE      PSA_BITS_TO_BYTES(PSA_VENDOR_RSA_MAX_KEY_BITS)
#endif
#if (defined(PSA_WANT_KEY_TYPE_ML_DSA)) && (4627u > PSA_SIGNATURE_MAX_SIZE)
#undef PSA_SIGNATURE_MAX_SIZE
#define PSA_SIGNATURE_MAX_SIZE      4627u
#endif


#define PSA_ASYMMETRIC_ENCRYPT_OUTPUT_SIZE(key_type, key_bits, alg)     \
    (PSA_KEY_TYPE_IS_RSA(key_type) ?                                    \
     ((void) alg, PSA_BITS_TO_BYTES(key_bits)) :                         \
     0u)



#define PSA_ASYMMETRIC_ENCRYPT_OUTPUT_MAX_SIZE          \
    (PSA_BITS_TO_BYTES(PSA_VENDOR_RSA_MAX_KEY_BITS))


#define PSA_ASYMMETRIC_DECRYPT_OUTPUT_SIZE(key_type, key_bits, alg)     \
    (PSA_KEY_TYPE_IS_RSA(key_type) ?                                    \
     PSA_BITS_TO_BYTES(key_bits) - PSA_RSA_MINIMUM_PADDING_SIZE(alg) :  \
     0u)


#define PSA_ASYMMETRIC_DECRYPT_OUTPUT_MAX_SIZE          \
    (PSA_BITS_TO_BYTES(PSA_VENDOR_RSA_MAX_KEY_BITS))


#define PSA_KEY_EXPORT_ASN1_INTEGER_MAX_SIZE(bits)      \
    ((bits) / 8u + 5u)


#define PSA_KEY_EXPORT_RSA_PUBLIC_KEY_MAX_SIZE(key_bits)        \
    (PSA_KEY_EXPORT_ASN1_INTEGER_MAX_SIZE(key_bits) + 11u)


#define PSA_KEY_EXPORT_RSA_KEY_PAIR_MAX_SIZE(key_bits)   \
    (9u * PSA_KEY_EXPORT_ASN1_INTEGER_MAX_SIZE((key_bits) / 2u + 1u) + 14u)


#define PSA_KEY_EXPORT_DSA_PUBLIC_KEY_MAX_SIZE(key_bits)        \
    (PSA_KEY_EXPORT_ASN1_INTEGER_MAX_SIZE(key_bits) * 3u + 59u)


#define PSA_KEY_EXPORT_DSA_KEY_PAIR_MAX_SIZE(key_bits)   \
    (PSA_KEY_EXPORT_ASN1_INTEGER_MAX_SIZE(key_bits) * 3u + 75u)


#define PSA_KEY_EXPORT_ECC_PUBLIC_KEY_MAX_SIZE(key_bits)        \
    (2u * PSA_BITS_TO_BYTES(key_bits) + 1u)


#define PSA_KEY_EXPORT_ECC_KEY_PAIR_MAX_SIZE(key_bits)   \
    (PSA_BITS_TO_BYTES(key_bits))


#define PSA_KEY_EXPORT_FFDH_KEY_PAIR_MAX_SIZE(key_bits)   \
    (PSA_BITS_TO_BYTES(key_bits))


#define PSA_KEY_EXPORT_FFDH_PUBLIC_KEY_MAX_SIZE(key_bits)   \
    (PSA_BITS_TO_BYTES(key_bits))


#define PSA_EXPORT_KEY_OUTPUT_SIZE(key_type, key_bits)                                              \
    (PSA_KEY_TYPE_IS_UNSTRUCTURED(key_type) ? PSA_BITS_TO_BYTES(key_bits) :                         \
     PSA_KEY_TYPE_IS_DH(key_type) ? PSA_BITS_TO_BYTES(key_bits) :                                   \
     (key_type) == PSA_KEY_TYPE_RSA_KEY_PAIR ? PSA_KEY_EXPORT_RSA_KEY_PAIR_MAX_SIZE(key_bits) :     \
     (key_type) == PSA_KEY_TYPE_RSA_PUBLIC_KEY ? PSA_KEY_EXPORT_RSA_PUBLIC_KEY_MAX_SIZE(key_bits) : \
     (key_type) == PSA_KEY_TYPE_DSA_KEY_PAIR ? PSA_KEY_EXPORT_DSA_KEY_PAIR_MAX_SIZE(key_bits) :     \
     (key_type) == PSA_KEY_TYPE_DSA_PUBLIC_KEY ? PSA_KEY_EXPORT_DSA_PUBLIC_KEY_MAX_SIZE(key_bits) : \
     PSA_KEY_TYPE_IS_ECC_KEY_PAIR(key_type) ? PSA_KEY_EXPORT_ECC_KEY_PAIR_MAX_SIZE(key_bits) :      \
     PSA_KEY_TYPE_IS_ECC_PUBLIC_KEY(key_type) ? PSA_KEY_EXPORT_ECC_PUBLIC_KEY_MAX_SIZE(key_bits) :  \
     /* ML-DSA: key-pair export is the 32-byte seed; public key export by parameter set */          \
     (key_type) == PSA_KEY_TYPE_ML_DSA_KEY_PAIR ? 32u :                                             \
     (key_type) == PSA_KEY_TYPE_ML_DSA_PUBLIC_KEY ?                                                 \
         ((key_bits) == 128u ? 1312u :                                                              \
          (key_bits) == 192u ? 1952u :                                                              \
          (key_bits) == 256u ? 2592u : 0u) :                                                        \
     /* ML-KEM: key-pair export is the 64-byte seed; public key export by parameter set */          \
     (key_type) == PSA_KEY_TYPE_ML_KEM_KEY_PAIR ? 64u :                                             \
     (key_type) == PSA_KEY_TYPE_ML_KEM_PUBLIC_KEY ?                                                 \
         ((key_bits) == 512u  ?  800u :                                                             \
          (key_bits) == 768u  ? 1184u :                                                             \
          (key_bits) == 1024u ? 1568u : 0u) :                                                       \
     0u)


#define PSA_EXPORT_PUBLIC_KEY_OUTPUT_SIZE(key_type, key_bits)                           \
    (PSA_KEY_TYPE_IS_RSA(key_type) ? PSA_KEY_EXPORT_RSA_PUBLIC_KEY_MAX_SIZE(key_bits) : \
     PSA_KEY_TYPE_IS_ECC(key_type) ? PSA_KEY_EXPORT_ECC_PUBLIC_KEY_MAX_SIZE(key_bits) : \
     PSA_KEY_TYPE_IS_DH(key_type) ? PSA_BITS_TO_BYTES(key_bits) : \
     /* ML-DSA: both key-pair and public-key types export the public key bytes */        \
     PSA_KEY_TYPE_IS_ML_DSA(key_type) ?                                                 \
         ((key_bits) == 128u ? 1312u :                                                  \
          (key_bits) == 192u ? 1952u :                                                  \
          (key_bits) == 256u ? 2592u : 0u) :                                            \
     /* ML-KEM: both key-pair and public-key types export the public key bytes */        \
     PSA_KEY_TYPE_IS_ML_KEM(key_type) ?                                                 \
         ((key_bits) == 512u  ?  800u :                                                 \
          (key_bits) == 768u  ? 1184u :                                                 \
          (key_bits) == 1024u ? 1568u : 0u) :                                           \
     0u)


#define PSA_EXPORT_KEY_PAIR_MAX_SIZE            1

#if defined(PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_BASIC) && \
    (PSA_KEY_EXPORT_ECC_KEY_PAIR_MAX_SIZE(PSA_VENDOR_ECC_MAX_CURVE_BITS) > \
     PSA_EXPORT_KEY_PAIR_MAX_SIZE)
#undef PSA_EXPORT_KEY_PAIR_MAX_SIZE
#define PSA_EXPORT_KEY_PAIR_MAX_SIZE    \
    PSA_KEY_EXPORT_ECC_KEY_PAIR_MAX_SIZE(PSA_VENDOR_ECC_MAX_CURVE_BITS)
#endif
#if defined(PSA_WANT_KEY_TYPE_RSA_KEY_PAIR_BASIC) && \
    (PSA_KEY_EXPORT_RSA_KEY_PAIR_MAX_SIZE(PSA_VENDOR_RSA_MAX_KEY_BITS) > \
     PSA_EXPORT_KEY_PAIR_MAX_SIZE)
#undef PSA_EXPORT_KEY_PAIR_MAX_SIZE
#define PSA_EXPORT_KEY_PAIR_MAX_SIZE    \
    PSA_KEY_EXPORT_RSA_KEY_PAIR_MAX_SIZE(PSA_VENDOR_RSA_MAX_KEY_BITS)
#endif
#if defined(PSA_WANT_KEY_TYPE_DH_KEY_PAIR_BASIC) && \
    (PSA_KEY_EXPORT_FFDH_KEY_PAIR_MAX_SIZE(PSA_VENDOR_FFDH_MAX_KEY_BITS) > \
     PSA_EXPORT_KEY_PAIR_MAX_SIZE)
#undef PSA_EXPORT_KEY_PAIR_MAX_SIZE
#define PSA_EXPORT_KEY_PAIR_MAX_SIZE    \
    PSA_KEY_EXPORT_FFDH_KEY_PAIR_MAX_SIZE(PSA_VENDOR_FFDH_MAX_KEY_BITS)
#endif


#define PSA_EXPORT_PUBLIC_KEY_MAX_SIZE            1

#if defined(PSA_WANT_KEY_TYPE_ECC_PUBLIC_KEY) && \
    (PSA_KEY_EXPORT_ECC_PUBLIC_KEY_MAX_SIZE(PSA_VENDOR_ECC_MAX_CURVE_BITS) > \
     PSA_EXPORT_PUBLIC_KEY_MAX_SIZE)
#undef PSA_EXPORT_PUBLIC_KEY_MAX_SIZE
#define PSA_EXPORT_PUBLIC_KEY_MAX_SIZE    \
    PSA_KEY_EXPORT_ECC_PUBLIC_KEY_MAX_SIZE(PSA_VENDOR_ECC_MAX_CURVE_BITS)
#endif
#if defined(PSA_WANT_KEY_TYPE_RSA_PUBLIC_KEY) && \
    (PSA_KEY_EXPORT_RSA_PUBLIC_KEY_MAX_SIZE(PSA_VENDOR_RSA_MAX_KEY_BITS) > \
     PSA_EXPORT_PUBLIC_KEY_MAX_SIZE)
#undef PSA_EXPORT_PUBLIC_KEY_MAX_SIZE
#define PSA_EXPORT_PUBLIC_KEY_MAX_SIZE    \
    PSA_KEY_EXPORT_RSA_PUBLIC_KEY_MAX_SIZE(PSA_VENDOR_RSA_MAX_KEY_BITS)
#endif
#if defined(PSA_WANT_KEY_TYPE_DH_PUBLIC_KEY) && \
    (PSA_KEY_EXPORT_FFDH_PUBLIC_KEY_MAX_SIZE(PSA_VENDOR_FFDH_MAX_KEY_BITS) > \
     PSA_EXPORT_PUBLIC_KEY_MAX_SIZE)
#undef PSA_EXPORT_PUBLIC_KEY_MAX_SIZE
#define PSA_EXPORT_PUBLIC_KEY_MAX_SIZE    \
    PSA_KEY_EXPORT_FFDH_PUBLIC_KEY_MAX_SIZE(PSA_VENDOR_FFDH_MAX_KEY_BITS)
#endif
/* ML-DSA-87 public key (2592 bytes) dominates all classical public key sizes */
#if defined(PSA_WANT_KEY_TYPE_ML_DSA) && (2592u > PSA_EXPORT_PUBLIC_KEY_MAX_SIZE)
#undef PSA_EXPORT_PUBLIC_KEY_MAX_SIZE
#define PSA_EXPORT_PUBLIC_KEY_MAX_SIZE    2592u
#endif

#define PSA_EXPORT_KEY_PAIR_OR_PUBLIC_MAX_SIZE \
    ((PSA_EXPORT_KEY_PAIR_MAX_SIZE > PSA_EXPORT_PUBLIC_KEY_MAX_SIZE) ? \
     PSA_EXPORT_KEY_PAIR_MAX_SIZE : PSA_EXPORT_PUBLIC_KEY_MAX_SIZE)

/* PSA Crypto 1.4: alias for the max of key-pair and public-key export sizes */
#define PSA_EXPORT_ASYMMETRIC_KEY_MAX_SIZE  PSA_EXPORT_KEY_PAIR_OR_PUBLIC_MAX_SIZE


#define PSA_RAW_KEY_AGREEMENT_OUTPUT_SIZE(key_type, key_bits)   \
    ((PSA_KEY_TYPE_IS_ECC_KEY_PAIR(key_type) || \
      PSA_KEY_TYPE_IS_DH_KEY_PAIR(key_type)) ? PSA_BITS_TO_BYTES(key_bits) : 0u)


#define PSA_RAW_KEY_AGREEMENT_OUTPUT_MAX_SIZE       1

#if defined(PSA_WANT_ALG_ECDH) && \
    (PSA_BITS_TO_BYTES(PSA_VENDOR_ECC_MAX_CURVE_BITS) > PSA_RAW_KEY_AGREEMENT_OUTPUT_MAX_SIZE)
#undef PSA_RAW_KEY_AGREEMENT_OUTPUT_MAX_SIZE
#define PSA_RAW_KEY_AGREEMENT_OUTPUT_MAX_SIZE    PSA_BITS_TO_BYTES(PSA_VENDOR_ECC_MAX_CURVE_BITS)
#endif
#if defined(PSA_WANT_ALG_FFDH) && \
    (PSA_BITS_TO_BYTES(PSA_VENDOR_FFDH_MAX_KEY_BITS) > PSA_RAW_KEY_AGREEMENT_OUTPUT_MAX_SIZE)
#undef PSA_RAW_KEY_AGREEMENT_OUTPUT_MAX_SIZE
#define PSA_RAW_KEY_AGREEMENT_OUTPUT_MAX_SIZE    PSA_BITS_TO_BYTES(PSA_VENDOR_FFDH_MAX_KEY_BITS)
#endif


#if (defined(PSA_WANT_KEY_TYPE_AES) || defined(PSA_WANT_KEY_TYPE_ARIA) || \
    defined(PSA_WANT_KEY_TYPE_CAMELLIA) || defined(PSA_WANT_KEY_TYPE_CHACHA20))
#define PSA_CIPHER_MAX_KEY_LENGTH       32u
#else
#define PSA_CIPHER_MAX_KEY_LENGTH       0u
#endif


#define PSA_CIPHER_IV_LENGTH(key_type, alg) \
    (PSA_BLOCK_CIPHER_BLOCK_LENGTH(key_type) > 1 && \
     ((alg) == PSA_ALG_CTR || \
      (alg) == PSA_ALG_CFB || \
      (alg) == PSA_ALG_OFB || \
      (alg) == PSA_ALG_XTS || \
      (alg) == PSA_ALG_CBC_NO_PADDING || \
      (alg) == PSA_ALG_CBC_PKCS7) ? PSA_BLOCK_CIPHER_BLOCK_LENGTH(key_type) : \
     (key_type) == PSA_KEY_TYPE_CHACHA20 && \
     (alg) == PSA_ALG_STREAM_CIPHER ? 12u : \
     (alg) == PSA_ALG_CCM_STAR_NO_TAG ? 13u : \
     0u)


#define PSA_CIPHER_IV_MAX_SIZE 16u


#define PSA_CIPHER_ENCRYPT_OUTPUT_SIZE(key_type, alg, input_length)     \
    (alg == PSA_ALG_CBC_PKCS7 ?                                         \
     (PSA_BLOCK_CIPHER_BLOCK_LENGTH(key_type) != 0 ?                    \
      PSA_ROUND_UP_TO_MULTIPLE(PSA_BLOCK_CIPHER_BLOCK_LENGTH(key_type), \
                               (input_length) + 1u) +                   \
      PSA_CIPHER_IV_LENGTH((key_type), (alg)) : 0u) :                   \
     (PSA_ALG_IS_CIPHER(alg) ?                                          \
      (input_length) + PSA_CIPHER_IV_LENGTH((key_type), (alg)) :        \
      0u))


#define PSA_CIPHER_ENCRYPT_OUTPUT_MAX_SIZE(input_length)                \
    (PSA_ROUND_UP_TO_MULTIPLE(PSA_BLOCK_CIPHER_BLOCK_MAX_SIZE,          \
                              (input_length) + 1u) +                    \
     PSA_CIPHER_IV_MAX_SIZE)


#define PSA_CIPHER_DECRYPT_OUTPUT_SIZE(key_type, alg, input_length)     \
    (PSA_ALG_IS_CIPHER(alg) &&                                          \
     ((key_type) & PSA_KEY_TYPE_CATEGORY_MASK) == PSA_KEY_TYPE_CATEGORY_SYMMETRIC ? \
     (input_length) :                                                   \
     0u)


#define PSA_CIPHER_DECRYPT_OUTPUT_MAX_SIZE(input_length)    \
    (input_length)


#define PSA_CIPHER_UPDATE_OUTPUT_SIZE(key_type, alg, input_length)      \
    (PSA_ALG_IS_CIPHER(alg) ?                                           \
     (PSA_BLOCK_CIPHER_BLOCK_LENGTH(key_type) != 0 ?                    \
      (((alg) == PSA_ALG_CBC_PKCS7      ||                              \
        (alg) == PSA_ALG_CBC_NO_PADDING ||                              \
        (alg) == PSA_ALG_ECB_NO_PADDING) ?                              \
       PSA_ROUND_UP_TO_MULTIPLE(PSA_BLOCK_CIPHER_BLOCK_LENGTH(key_type), \
                                input_length) :                         \
       (input_length)) : 0u) :                                          \
     0u)


#define PSA_CIPHER_UPDATE_OUTPUT_MAX_SIZE(input_length)     \
    (PSA_ROUND_UP_TO_MULTIPLE(PSA_BLOCK_CIPHER_BLOCK_MAX_SIZE, input_length))


#define PSA_CIPHER_FINISH_OUTPUT_SIZE(key_type, alg)    \
    (PSA_ALG_IS_CIPHER(alg) ?                           \
     (alg == PSA_ALG_CBC_PKCS7 ?                        \
      PSA_BLOCK_CIPHER_BLOCK_LENGTH(key_type) :         \
      0u) :                                             \
     0u)


#define PSA_CIPHER_FINISH_OUTPUT_MAX_SIZE           \
    (PSA_BLOCK_CIPHER_BLOCK_MAX_SIZE)


/* --- KEM encapsulation output sizes (PSA 1.4 PQC extension) --- */

/** Sufficient ciphertext buffer size for psa_encapsulate().
 *
 * For ML-KEM the ciphertext size depends on the parameter set (key_bits):
 *   ML-KEM-512 (512)  ->  768 bytes
 *   ML-KEM-768 (768)  -> 1088 bytes
 *   ML-KEM-1024(1024) -> 1568 bytes
 */
#define PSA_ENCAPSULATE_CIPHERTEXT_SIZE(key_type, key_bits, alg)    \
    (PSA_KEY_TYPE_IS_ML_KEM(key_type) && (alg) == PSA_ALG_ML_KEM ? \
     ((key_bits) == 512u  ?  768u :                                 \
      (key_bits) == 768u  ? 1088u :                                 \
      (key_bits) == 1024u ? 1568u : 0u) :                           \
     0u)

/** Maximum ciphertext buffer size for psa_encapsulate(), for any supported
 *  key-encapsulation algorithm (ML-KEM-1024 dominates at 1568 bytes). */
#define PSA_ENCAPSULATE_CIPHERTEXT_MAX_SIZE 1568u


/* --- Key wrapping output sizes (PSA 1.4) --- */

/** Sufficient output buffer size for psa_wrap_key().
 *
 * For PSA_ALG_KW (AES Key Wrap, RFC 3394) the wrapped output is:
 *   ceil(export_size / 8) * 8 + 8
 * i.e. the plaintext (key export) rounded up to the next 8-byte boundary,
 * plus the 8-byte integrity check value prepended by KW.
 * For other/unknown algorithms the result is 0 (implementation must extend).
 */
#define PSA_WRAP_KEY_OUTPUT_SIZE(wrap_key_type, alg, key_type, key_bits)    \
    (((alg) == PSA_ALG_KW) ?                                                \
     ((void)(wrap_key_type),                                                \
      PSA_ROUND_UP_TO_MULTIPLE(8u,                                          \
          PSA_EXPORT_KEY_OUTPUT_SIZE(key_type, key_bits)) + 8u) :           \
     0u)

/** Sufficient output buffer size for psa_wrap_key() for any asymmetric
 *  key pair supported by this implementation.
 *
 * Computed as PSA_WRAP_KEY_OUTPUT_SIZE over the largest key-pair export:
 * RSA-4096 key pair (~2363 bytes) wrapped with AES-KW:
 *   ceil(2363/8)*8 + 8 = 2368 + 8 = 2376 bytes.
 * (ML-DSA seed = 32 bytes and ML-KEM seed = 64 bytes are much smaller.)
 */
#define PSA_WRAP_KEY_PAIR_MAX_SIZE                                          \
    (PSA_ROUND_UP_TO_MULTIPLE(8u, PSA_EXPORT_KEY_PAIR_MAX_SIZE) + 8u)


/* --- Hash suspend state sizes (PSA 1.4, spec-defined formulas) --- */

/** The size of the algorithm field in the psa_hash_suspend() output (bytes).
 *  This is a fixed 4-byte encoding of the algorithm identifier. */
#define PSA_HASH_SUSPEND_ALGORITHM_FIELD_LENGTH ((size_t)4)

/** The size of the input-length field in the psa_hash_suspend() output.
 *  Depends on the hash algorithm's internal counter width. */
#define PSA_HASH_SUSPEND_INPUT_LENGTH_FIELD_LENGTH(alg)                         \
    ((alg) == PSA_ALG_MD2 ? 1u :                                                \
     (alg) == PSA_ALG_MD4 || (alg) == PSA_ALG_MD5 ||                           \
     (alg) == PSA_ALG_RIPEMD160 || (alg) == PSA_ALG_SHA_1 ||                   \
     (alg) == PSA_ALG_SHA_224 || (alg) == PSA_ALG_SHA_256 ? 8u :               \
     (alg) == PSA_ALG_SHA_512 || (alg) == PSA_ALG_SHA_384 ||                   \
     (alg) == PSA_ALG_SHA_512_224 || (alg) == PSA_ALG_SHA_512_256 ? 16u :      \
     0u)

/** The size of the hash-state field in the psa_hash_suspend() output.
 *  Holds the intermediate chaining value of the hash. */
#define PSA_HASH_SUSPEND_HASH_STATE_FIELD_LENGTH(alg)                           \
    ((alg) == PSA_ALG_MD2 ? 64u :                                               \
     (alg) == PSA_ALG_MD4 || (alg) == PSA_ALG_MD5 ? 16u :                      \
     (alg) == PSA_ALG_RIPEMD160 || (alg) == PSA_ALG_SHA_1 ? 20u :              \
     (alg) == PSA_ALG_SHA_224 || (alg) == PSA_ALG_SHA_256 ? 32u :              \
     (alg) == PSA_ALG_SHA_512 || (alg) == PSA_ALG_SHA_384 ||                   \
     (alg) == PSA_ALG_SHA_512_224 || (alg) == PSA_ALG_SHA_512_256 ? 64u :      \
     0u)

/** PSA specification sizing formula for psa_hash_suspend(); this build
 *  returns PSA_ERROR_NOT_SUPPORTED for that API.
 *
 * Formula (spec-defined):
 *   PSA_HASH_SUSPEND_ALGORITHM_FIELD_LENGTH
 *   + PSA_HASH_SUSPEND_INPUT_LENGTH_FIELD_LENGTH(alg)
 *   + PSA_HASH_SUSPEND_HASH_STATE_FIELD_LENGTH(alg)
 *   + PSA_HASH_BLOCK_LENGTH(alg) - 1
 */
#define PSA_HASH_SUSPEND_OUTPUT_SIZE(alg)                                       \
    (PSA_HASH_SUSPEND_ALGORITHM_FIELD_LENGTH +                                  \
     PSA_HASH_SUSPEND_INPUT_LENGTH_FIELD_LENGTH(alg) +                          \
     PSA_HASH_SUSPEND_HASH_STATE_FIELD_LENGTH(alg) +                            \
     PSA_HASH_BLOCK_LENGTH(alg) - 1u)

/** Maximum suspend state size over all supported hash algorithms.
 *  SHA-512 / SHA-384 / SHA-512/224 / SHA-512/256 gives the largest output:
 *    4 (alg) + 16 (len) + 64 (state) + 128 (block) - 1 = 211 bytes. */
#define PSA_HASH_SUSPEND_OUTPUT_MAX_SIZE                                        \
    (PSA_HASH_SUSPEND_ALGORITHM_FIELD_LENGTH + 16u + 64u + 128u - 1u)

#endif
