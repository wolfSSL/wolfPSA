/* F-11570: PSA_ALG_PURE_EDDSA is context-free; a non-empty context must
 * be rejected. Before the fix, wolfpsa_check_context accepted a non-empty
 * context for PureEdDSA with an Ed448 key and the Ed448 backend then
 * signed/verified with it. A context-bearing EdDSA requires
 * PSA_ALG_EDDSA_CTX.
 *
 * PSA_ALG_PURE_EDDSA is a sign-message algorithm, so the context cases are
 * exercised through psa_sign_message_with_context() and
 * psa_verify_message_with_context() (the Ed448 backend enforces the
 * rejection on both the sign and the verify path).
 *
 * Standalone regression test. Build:
 *   gcc -o /tmp/psa_pure_eddsa_context_test \
 *       test/psa_server/psa_pure_eddsa_context_test.c \
 *       -I/opt/dev/src/wolfssl -I/opt/dev/src/wolfssl/wolfssl \
 *       -I/opt/dev/src/wolfPSA -I/opt/dev/src/wolfPSA/wolfpsa \
 *       -I/opt/dev/src/wolfPSA/src -I/opt/dev/src/wolfPSA/test/psa_server \
 *       /opt/dev/src/wolfPSA/libwolfpsa.a
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
#include <stdio.h>
#include <string.h>
#include <wolfpsa/psa/crypto.h>

static int test_pure_eddsa_rejects_context(void)
{
    psa_key_attributes_t attrs;
    psa_key_id_t key_id = PSA_KEY_ID_NULL;
    psa_status_t st;
    int rc = 0;
    uint8_t message[32];
    uint8_t signature[128];
    size_t signature_length = 0;
    const uint8_t context[] = "ctx";

    memset(message, 0xab, sizeof(message));

    attrs = psa_key_attributes_init();
    psa_set_key_type(&attrs,
                     PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_TWISTED_EDWARDS));
    psa_set_key_bits(&attrs, 448);
    psa_set_key_usage_flags(&attrs,
                            PSA_KEY_USAGE_SIGN_MESSAGE |
                            PSA_KEY_USAGE_VERIFY_MESSAGE);
    psa_set_key_algorithm(&attrs, PSA_ALG_PURE_EDDSA);
    psa_set_key_lifetime(&attrs, PSA_KEY_LIFETIME_VOLATILE);

    st = psa_generate_key(&attrs, &key_id);
    if (st != PSA_SUCCESS) {
        printf("FAIL generate Ed448 key: %d\n", (int)st);
        return 1;
    }

    /* PSA_ALG_PURE_EDDSA is context-free: a non-empty context must be
     * rejected with PSA_ERROR_INVALID_ARGUMENT. */
    st = psa_sign_message_with_context(key_id, PSA_ALG_PURE_EDDSA,
                                       message, sizeof(message),
                                       context, sizeof(context) - 1,
                                       signature, sizeof(signature),
                                       &signature_length);
    if (st != PSA_ERROR_INVALID_ARGUMENT) {
        printf("FAIL pure_eddsa non-empty context: expected "
               "PSA_ERROR_INVALID_ARGUMENT (%d), got %d\n",
               (int)PSA_ERROR_INVALID_ARGUMENT, (int)st);
        rc = 1;
    } else   {
        printf("PASS pure_eddsa non-empty context rejected\n");
    }

    /* A zero-length context is still accepted (PureEdDSA with no context),
     * and the resulting signature verifies with the same empty context. */
    st = psa_sign_message_with_context(key_id, PSA_ALG_PURE_EDDSA,
                                       message, sizeof(message),
                                       context, 0,
                                       signature, sizeof(signature),
                                       &signature_length);
    if (st != PSA_SUCCESS) {
        printf("FAIL pure_eddsa zero context: expected PSA_SUCCESS, got %d\n",
               (int)st);
        rc = 1;
    }
    else   {
        printf("PASS pure_eddsa zero context accepted (sig %zu bytes)\n",
               signature_length);

        st = psa_verify_message_with_context(key_id, PSA_ALG_PURE_EDDSA,
                                             message, sizeof(message),
                                             context, 0,
                                             signature, signature_length);
        if (st != PSA_SUCCESS) {
            printf("FAIL pure_eddsa zero-context verify: expected "
                   "PSA_SUCCESS, got %d\n", (int)st);
            rc = 1;
        }
        else   {
            printf("PASS pure_eddsa zero-context verify\n");
        }

        /* Verification is context-free too: a non-empty context must be
         * rejected with PSA_ERROR_INVALID_ARGUMENT. */
        st = psa_verify_message_with_context(key_id, PSA_ALG_PURE_EDDSA,
                                             message, sizeof(message),
                                             context,
                                             sizeof(context) - 1,
                                             signature, signature_length);
        if (st != PSA_ERROR_INVALID_ARGUMENT) {
            printf("FAIL pure_eddsa non-empty context verify: expected "
                   "PSA_ERROR_INVALID_ARGUMENT (%d), got %d\n",
                   (int)PSA_ERROR_INVALID_ARGUMENT, (int)st);
            rc = 1;
        }
        else   {
            printf("PASS pure_eddsa non-empty context verify rejected\n");
        }
    }

    psa_destroy_key(key_id);
    return rc;
}

static int test_pure_eddsa_sign_output_size(psa_key_bits_t bits)
{
    const psa_key_type_t type =
        PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_TWISTED_EDWARDS);
    psa_key_attributes_t attrs = psa_key_attributes_init();
    psa_key_id_t key_id = PSA_KEY_ID_NULL;
    psa_status_t st;
    uint8_t message[32];
    uint8_t signature[128];
    size_t signature_length = 0;

    memset(message, 0xab, sizeof(message));
    psa_set_key_type(&attrs, type);
    psa_set_key_bits(&attrs, bits);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_SIGN_MESSAGE);
    psa_set_key_algorithm(&attrs, PSA_ALG_PURE_EDDSA);

    st = psa_generate_key(&attrs, &key_id);
    if (st == PSA_SUCCESS) {
        st = psa_sign_message(key_id, PSA_ALG_PURE_EDDSA,
                              message, sizeof(message), signature,
                              PSA_SIGN_OUTPUT_SIZE(type, bits,
                                                   PSA_ALG_PURE_EDDSA),
                              &signature_length);
        psa_destroy_key(key_id);
    }
    if (st != PSA_SUCCESS) {
        printf("FAIL pure_eddsa %u-bit sign into PSA_SIGN_OUTPUT_SIZE: %d\n",
               (unsigned)bits, (int)st);
        return 1;
    }
    printf("PASS pure_eddsa %u-bit sign into PSA_SIGN_OUTPUT_SIZE\n",
           (unsigned)bits);
    return 0;
}

int main(void)
{
    int rc;
    psa_status_t st = psa_crypto_init();
    if (st != PSA_SUCCESS) {
        printf("psa_crypto_init failed: %d\n", (int)st);
        return 1;
    }
    rc = test_pure_eddsa_rejects_context();
    rc |= test_pure_eddsa_sign_output_size(255);
    rc |= test_pure_eddsa_sign_output_size(448);
    if (rc == 0) {
        printf("psa_pure_eddsa_context_test: all tests passed\n");
    }
    return rc;
}
