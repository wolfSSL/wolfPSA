/* psa_tf_psa_threading_test.c
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

/* Mutexes and condition variables through the TF-PSA-Crypto 1.x API, and PSA
 * calls from several threads at once, as MBEDTLS_THREADING_C promises. */

#include <stdio.h>
#include <string.h>

#include <psa/crypto.h>
#include <mbedtls/threading.h>

#define THREADS 4
#define ROUNDS 10000
#define KEYS 100

static mbedtls_threading_mutex_t lock;
static mbedtls_threading_condition_variable_t ready;
static mbedtls_threading_condition_variable_t start;
static int counter;
static int waiting;
static int go;
/* A thread returns its address on failure */
static int failed;

static int StartThreads(pthread_t* t, void* (*f)(void*))
{
    int n;

    for (n = 0; n < THREADS; n++) {
        if (pthread_create(&t[n], NULL, f, NULL) != 0) {
            break;
        }
    }
    return n;
}

/* All n threads started and none failed */
static int JoinThreads(pthread_t* t, int n)
{
    void* ret;
    int ok = (n == THREADS);
    int i;

    for (i = 0; i < n; i++) {
        if (pthread_join(t[i], &ret) != 0 || ret != NULL) {
            ok = 0;
        }
    }
    return ok;
}

/* A zeroed or freed mutex fails, and a second free does nothing */
static int MutexUsage(void)
{
    mbedtls_threading_mutex_t m;
    int ok;

    memset(&m, 0, sizeof(m));
    ok = mbedtls_mutex_lock(&m) == MBEDTLS_ERR_THREADING_USAGE_ERROR;
    mbedtls_mutex_free(&m);
    mbedtls_mutex_init(&m);
    ok = ok && mbedtls_mutex_lock(&m) == 0 && mbedtls_mutex_unlock(&m) == 0;
    mbedtls_mutex_free(&m);
    mbedtls_mutex_free(&m);
    return ok &&
        mbedtls_mutex_unlock(&m) == MBEDTLS_ERR_THREADING_USAGE_ERROR;
}

static void* Count(void* arg)
{
    int i;

    (void)arg;
    for (i = 0; i < ROUNDS; i++) {
        if (mbedtls_mutex_lock(&lock) != 0) {
            return &failed;
        }
        counter++;
        if (mbedtls_mutex_unlock(&lock) != 0) {
            return &failed;
        }
    }
    return NULL;
}

static int Counter(void)
{
    pthread_t t[THREADS];

    return JoinThreads(t, StartThreads(t, Count)) &&
        counter == THREADS * ROUNDS;
}

/* Signals ready, then waits for the broadcast of start */
static void* Wait(void* arg)
{
    int ret;

    (void)arg;
    ret = mbedtls_mutex_lock(&lock);
    if (ret == 0) {
        waiting++;
        ret = mbedtls_condition_variable_signal(&ready);
        while (ret == 0 && !go) {
            ret = mbedtls_condition_variable_wait(&start, &lock);
        }
        (void)mbedtls_mutex_unlock(&lock);
    }
    return (ret == 0) ? NULL : &failed;
}

static int CondVar(void)
{
    pthread_t t[THREADS];
    int n;
    int ret;

    n = StartThreads(t, Wait);
    ret = mbedtls_mutex_lock(&lock);
    if (ret == 0) {
        while (ret == 0 && waiting < n) {
            ret = mbedtls_condition_variable_wait(&ready, &lock);
        }
        go = 1;
        if (ret == 0) {
            ret = mbedtls_condition_variable_broadcast(&start);
        }
        (void)mbedtls_mutex_unlock(&lock);
    }
    return JoinThreads(t, n) && ret == 0;
}

/* Volatile keys in the shared key store */
static void* Keys(void* arg)
{
    static const unsigned char key[16] = { 0 };
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_attributes_t got = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t id;
    psa_status_t status = PSA_SUCCESS;
    int i;

    (void)arg;
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_ENCRYPT);
    psa_set_key_algorithm(&attr, PSA_ALG_ECB_NO_PADDING);
    psa_set_key_type(&attr, PSA_KEY_TYPE_AES);
    for (i = 0; i < KEYS && status == PSA_SUCCESS; i++) {
        status = psa_import_key(&attr, key, sizeof(key), &id);
        if (status == PSA_SUCCESS) {
            status = psa_get_key_attributes(id, &got);
            if (status == PSA_SUCCESS &&
                    psa_get_key_type(&got) != PSA_KEY_TYPE_AES) {
                status = PSA_ERROR_CORRUPTION_DETECTED;
            }
            psa_reset_key_attributes(&got);
            if (psa_destroy_key(id) != PSA_SUCCESS) {
                status = PSA_ERROR_CORRUPTION_DETECTED;
            }
        }
    }
    return (status == PSA_SUCCESS) ? NULL : &failed;
}

static int KeyStore(void)
{
    pthread_t t[THREADS];

    return JoinThreads(t, StartThreads(t, Keys));
}

int main(void)
{
    static const struct {
        const char* name;
        int (*f)(void);
    } cases[] = {
        { "mutex usage errors", MutexUsage },
        { "mutex, a counter shared by the threads", Counter },
        { "condition variable, signal and broadcast", CondVar },
        { "PSA keys in each thread", KeyStore }
    };
    size_t i;
    int fails = 0;

    if (psa_crypto_init() != PSA_SUCCESS) {
        printf("FAIL: psa_crypto_init\n");
        return 1;
    }
    mbedtls_mutex_init(&lock);
    if (mbedtls_condition_variable_init(&ready) != 0 ||
            mbedtls_condition_variable_init(&start) != 0) {
        printf("FAIL: mbedtls_condition_variable_init\n");
        return 1;
    }
    for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        if (cases[i].f()) {
            printf("PASS: %s\n", cases[i].name);
        }
        else {
            printf("FAIL: %s\n", cases[i].name);
            fails++;
        }
    }
    mbedtls_condition_variable_free(&start);
    mbedtls_condition_variable_free(&ready);
    mbedtls_mutex_free(&lock);
    mbedtls_psa_crypto_free();
    return (fails == 0) ? 0 : 1;
}
