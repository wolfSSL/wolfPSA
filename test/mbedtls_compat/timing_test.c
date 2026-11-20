/* timing_test.c
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

/* Mbed TLS 4.x timers and mbedtls_ms_time(). The first two cases are from
 * test_suite_timing, the last two from test_suite_platform. */

#include <stdio.h>
#include <string.h>
#include <time.h>

#include <mbedtls/platform_time.h>
#include <mbedtls/timing.h>

#define INT_MS 100
#define FIN_MS 200
/* Upper bound for a wait, in case a delay never passes */
#define MAX_WAIT_MS 5000
/* Sleep between reads of the timer */
#define NAP_MS 2

static void Nap(long ms)
{
    struct timespec ts;

    ts.tv_sec = ms / 1000;
    ts.tv_nsec = (ms % 1000) * 1000000L;
    (void)nanosleep(&ts, NULL);
}

/* Reset writes the time, which is not 0 */
static int GetTimer(void)
{
    struct mbedtls_timing_hr_time t;
    static const struct mbedtls_timing_hr_time zero;

    memset(&t, 0, sizeof(t));
    return mbedtls_timing_get_timer(&t, 1) == 0 &&
        memcmp(&t, &zero, sizeof(t)) != 0 &&
        mbedtls_timing_get_timer(&t, 0) < MAX_WAIT_MS;
}

static int DelayZero(void)
{
    mbedtls_timing_delay_context ctx;

    mbedtls_timing_set_delay(&ctx, 0, 0);
    return mbedtls_timing_get_delay(&ctx) == -1 &&
        mbedtls_timing_get_final_delay(&ctx) == 0;
}

/* In ms, not s or us: time() moves on by the time 1100 ms have passed */
static int FollowsTime(void)
{
    struct mbedtls_timing_hr_time t;
    unsigned long long ms;
    time_t start = time(NULL);
    time_t now;

    (void)mbedtls_timing_get_timer(&t, 1);
    do {
        Nap(NAP_MS);
        ms = mbedtls_timing_get_timer(&t, 0);
        now = time(NULL);
    } while (ms < 1100 && now - start < MAX_WAIT_MS / 1000);
    return ms >= 1100 && now - start >= 1;
}

/* 0, then 1 after INT_MS, then 2 after FIN_MS, by t started just before */
static int Delays(void)
{
    mbedtls_timing_delay_context ctx;
    struct mbedtls_timing_hr_time t;
    unsigned long long elapsed;
    int last;
    int now;
    int ok;

    (void)mbedtls_timing_get_timer(&t, 1);
    mbedtls_timing_set_delay(&ctx, INT_MS, FIN_MS);
    last = mbedtls_timing_get_delay(&ctx);
    ok = last == 0 && mbedtls_timing_get_final_delay(&ctx) == FIN_MS;
    while (ok && last != 2) {
        Nap(NAP_MS);
        now = mbedtls_timing_get_delay(&ctx);
        elapsed = mbedtls_timing_get_timer(&t, 0);
        ok = now >= last && elapsed < MAX_WAIT_MS &&
            (now < 1 || elapsed >= INT_MS) && (now < 2 || elapsed >= FIN_MS);
        last = now;
    }
    return ok;
}

/* A delay of 0 cancels the one running */
static int Cancel(void)
{
    mbedtls_timing_delay_context ctx;

    mbedtls_timing_set_delay(&ctx, INT_MS, FIN_MS);
    mbedtls_timing_set_delay(&ctx, INT_MS, 0);
    return mbedtls_timing_get_delay(&ctx) == -1 &&
        mbedtls_timing_get_final_delay(&ctx) == 0;
}

static int NullArgs(void)
{
    mbedtls_timing_set_delay(NULL, INT_MS, FIN_MS);
    return mbedtls_timing_get_timer(NULL, 1) == 0 &&
        mbedtls_timing_get_timer(NULL, 0) == 0 &&
        mbedtls_timing_get_delay(NULL) == -1 &&
        mbedtls_timing_get_final_delay(NULL) == 0;
}

/* In ms, not s or us: at least the time slept, and not far over it */
static int DelayMs(void)
{
    mbedtls_ms_time_t start = mbedtls_ms_time();
    mbedtls_ms_time_t elapsed;

    Nap(INT_MS);
    elapsed = mbedtls_ms_time() - start;
    return elapsed >= INT_MS && elapsed < INT_MS + MAX_WAIT_MS;
}

static int Seconds(void)
{
    mbedtls_time_t t = 0;
    mbedtls_time_t now = mbedtls_time(&t);

    return now != (mbedtls_time_t)-1 && now == t;
}

static const struct {
    const char* name;
    int (*test)(void);
} cases[] = {
    { "get timer", GetTimer },
    { "delay 0ms", DelayZero },
    { "milliseconds", FollowsTime },
    { "delays", Delays },
    { "cancel", Cancel },
    { "NULL arguments", NullArgs },
    { "delay milliseconds", DelayMs },
    { "get seconds", Seconds }
};

int main(void)
{
    size_t i;
    int fails = 0;

    for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        if (cases[i].test()) {
            printf("PASS: %s\n", cases[i].name);
        }
        else {
            printf("FAIL: %s\n", cases[i].name);
            fails++;
        }
    }
    return (fails == 0) ? 0 : 1;
}
