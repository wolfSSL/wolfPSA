/* psa_store.h
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

#ifndef WOLFPSA_STORE_H
#define WOLFPSA_STORE_H

#include <stddef.h>

#define WOLFPSA_STORE_KEY            0x00

/* Shared return codes for the wolfPSA_Store_* backend interface below.
 * Backends (psa_store_posix.c, psa_store_zephyr.c, custom vaults) must use
 * these so callers in psa_key_storage.c interpret results consistently. */
#define WOLFPSA_STORE_OK             0
#define WOLFPSA_STORE_NOT_AVAILABLE  (-4)
#define WOLFPSA_STORE_IO_ERROR       (-5)

/*
 * Opens access to location to read/write PSA data.
 *
 * @param [in]   type   Type of data to be stored. See WOLFPSA_STORE_* above.
 * @param [in]   id1    Numeric identifier 1.
 * @param [in]   id2    Numeric identifier 2.
 * @param [in]   read   1 when opening for read and 0 for write.
 * @param [out]  store  Return pointer to context data.
 * @return  0 on success.
 * @return  -4 when data not available.
 * @return  Other value to indicate failure.
 */
int wolfPSA_Store_Open(int type, unsigned long id1, unsigned long id2, int read,
    void** store);

/*
 * Opens access to location to read/write PSA data with extra size hint.
 *
 * @param [in]   type        Type of data to be stored. See WOLFPSA_STORE_* above.
 * @param [in]   id1         Numeric identifier 1.
 * @param [in]   id2         Numeric identifier 2.
 * @param [in]   read        1 when opening for read and 0 for write.
 * @param [in]   variableSz  Additional size needed for type (needed on write).
 * @param [out]  store       Return pointer to context data.
 * @return  0 on success.
 * @return  -4 when data not available.
 * @return  Other value to indicate failure.
 */
int wolfPSA_Store_OpenSz(int type, unsigned long id1, unsigned long id2, int read,
    int variableSz, void** store);

/*
 * Removes stored data from the specified location.
 *
 * @param [in]  type   Type of data to be removed. See WOLFPSA_STORE_* above.
 * @param [in]  id1    Numeric identifier 1.
 * @param [in]  id2    Numeric identifier 2.
 * @return  0 on success.
 * @return  -4 when data not available.
 * @return  Other value to indicate failure.
 */
int wolfPSA_Store_Remove(int type, unsigned long id1, unsigned long id2);

/*
 * Closes access to location being read or written.
 *
 * @param [in]  store  Context for operation.
 */
void wolfPSA_Store_Close(void* store);

/*
 * Reads a specific number of bytes into buffer.
 *
 * @param [in]       store   Context for operation.
 * @param [in, out]  buffer  Buffer to hold data read.
 * @param [in]       len     Length of data required.
 * @return  Length of data read into buffer.
 * @return  -ve to indicate failure.
 */
int wolfPSA_Store_Read(void* store, unsigned char* buffer, int len);

/*
 * Writes a specific number of bytes from buffer.
 *
 * @param [in]  store   Context for operation.
 * @param [in]  buffer  Data to write.
 * @param [in]  len     Length of data to write.
 * @return  Length of data written into buffer.
 * @return  -ve to indicate failure.
 */
int wolfPSA_Store_Write(void* store, unsigned char* buffer, int len);

#endif /* WOLFPSA_STORE_H */
