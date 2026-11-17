/* psa_trace.h
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

#ifndef WOLFPSA_PSA_TRACE_H
#define WOLFPSA_PSA_TRACE_H

#ifdef WOLFPSA_NO_TRACE

static inline void wolfpsa_trace(const char* fmt, ...)
{
    (void)fmt;
}

#else

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>

static inline void wolfpsa_trace(const char* fmt, ...)
{
    const char* enabled = getenv("WOLFPSA_TRACE");
    va_list args;

    if (enabled == NULL || enabled[0] == '\0') {
        return;
    }

    va_start(args, fmt);
    fputs("wolfpsa: ", stderr);
    vfprintf(stderr, fmt, args);
    fputc('\n', stderr);
    va_end(args);
}

#endif /* WOLFPSA_NO_TRACE */

#endif /* WOLFPSA_PSA_TRACE_H */
