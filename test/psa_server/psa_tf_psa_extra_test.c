/* psa_tf_psa_extra_test.c
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

#include <wolfpsa/psa/crypto.h>
#include <mbedtls/platform_util.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define WOLFPSA_TEST_PERSISTENT_ID 0x0000a5f0

static int failures;

static void expect_status(const char *label, psa_status_t status,
                          psa_status_t expected)
{
    if (status != expected) {
        printf("FAIL %s: status=%d expected=%d\n", label, (int)status,
               (int)expected);
        failures++;
    }
}

static psa_status_t import_raw_key(psa_key_lifetime_t lifetime,
                                   psa_key_id_t id, psa_key_id_t *key)
{
    static const uint8_t data[16] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };
    psa_key_attributes_t attrs = psa_key_attributes_init();

    psa_set_key_type(&attrs, PSA_KEY_TYPE_RAW_DATA);
    psa_set_key_bits(&attrs, 128);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_EXPORT);
    psa_set_key_lifetime(&attrs, lifetime);
    if (lifetime != PSA_KEY_LIFETIME_VOLATILE) {
        psa_set_key_id(&attrs, id);
    }

    return psa_import_key(&attrs, data, sizeof(data), key);
}

/* Freeing destroys volatile keys, keeps persistent keys and allows another
 * psa_crypto_init(). */
static void test_crypto_free(void)
{
    psa_key_attributes_t attrs = psa_key_attributes_init();
    psa_key_id_t volatile_key = PSA_KEY_ID_NULL;
    psa_key_id_t persistent_key = PSA_KEY_ID_NULL;
    uint8_t buf[16];

    mbedtls_psa_crypto_free();
    expect_status("random before init", psa_generate_random(buf, sizeof(buf)),
                  PSA_ERROR_BAD_STATE);

    expect_status("init", psa_crypto_init(), PSA_SUCCESS);
    expect_status("import volatile",
                  import_raw_key(PSA_KEY_LIFETIME_VOLATILE, 0, &volatile_key),
                  PSA_SUCCESS);
    expect_status("import persistent",
                  import_raw_key(PSA_KEY_LIFETIME_PERSISTENT,
                                 WOLFPSA_TEST_PERSISTENT_ID, &persistent_key),
                  PSA_SUCCESS);

    mbedtls_psa_crypto_free();
    expect_status("random after free", psa_generate_random(buf, sizeof(buf)),
                  PSA_ERROR_BAD_STATE);
    expect_status("attributes after free",
                  psa_get_key_attributes(volatile_key, &attrs),
                  PSA_ERROR_BAD_STATE);

    expect_status("init after free", psa_crypto_init(), PSA_SUCCESS);
    expect_status("random after reinit", psa_generate_random(buf, sizeof(buf)),
                  PSA_SUCCESS);
    expect_status("volatile key after reinit",
                  psa_get_key_attributes(volatile_key, &attrs),
                  PSA_ERROR_INVALID_HANDLE);
    psa_reset_key_attributes(&attrs);
    expect_status("persistent key after reinit",
                  psa_get_key_attributes(persistent_key, &attrs),
                  PSA_SUCCESS);
    psa_reset_key_attributes(&attrs);
    expect_status("destroy persistent", psa_destroy_key(persistent_key),
                  PSA_SUCCESS);

    mbedtls_psa_crypto_free();
    mbedtls_psa_crypto_free();
    expect_status("random after second free",
                  psa_generate_random(buf, sizeof(buf)), PSA_ERROR_BAD_STATE);
}

static void test_svc_key_id(void)
{
    mbedtls_svc_key_id_t key = mbedtls_svc_key_id_make(0, 5);
    mbedtls_svc_key_id_t null_key = MBEDTLS_SVC_KEY_ID_INIT;

    if (MBEDTLS_SVC_KEY_ID_GET_KEY_ID(key) != 5 ||
            !mbedtls_svc_key_id_equal(key, 5) ||
            mbedtls_svc_key_id_equal(key, null_key) ||
            mbedtls_svc_key_id_is_null(key) ||
            !mbedtls_svc_key_id_is_null(null_key)) {
        printf("FAIL svc_key_id helpers\n");
        failures++;
    }
}

static void test_zeroize(void)
{
    uint8_t buf[32];
    size_t i;

    memset(buf, 0xa5, sizeof(buf));
    mbedtls_platform_zeroize(buf, sizeof(buf));
    for (i = 0; i < sizeof(buf); i++) {
        if (buf[i] != 0) {
            printf("FAIL zeroize: byte %u not zero\n", (unsigned)i);
            failures++;
            break;
        }
    }

    mbedtls_platform_zeroize(NULL, 0);
}

int main(void)
{
    /* Fresh persistent store, removed on success. */
    char dir[] = "/tmp/wolfpsa_tf_psa_extra_XXXXXX";

    if (mkdtemp(dir) == NULL) {
        printf("psa_tf_psa_extra_test: mkdtemp failed\n");
        return 1;
    }
    if (setenv("WOLFPSA_TOKEN_PATH", dir, 1) != 0) {
        printf("psa_tf_psa_extra_test: setenv failed\n");
        (void)rmdir(dir);
        return 1;
    }

    test_crypto_free();
    test_svc_key_id();
    test_zeroize();

    if (failures != 0) {
        printf("PSA TF-PSA-Crypto extensions test: FAIL (%d)\n", failures);
        return 1;
    }

    (void)rmdir(dir);
    printf("PSA TF-PSA-Crypto extensions test: OK\n");
    return 0;
}
