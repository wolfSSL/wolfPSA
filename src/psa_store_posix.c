/* psa_store_posix.c
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

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>

#if !defined(WOLFPSA_CUSTOM_STORE)

#include <psa_store.h>
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/wc_port.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

#include <errno.h>
#include <string.h>

#if !defined(_WIN32) && !defined(_MSC_VER)
    #include <sys/stat.h>
    #include <unistd.h>
    #include <fcntl.h>
    #include <time.h>
#endif

/* WOLFPSA_STORE_NOT_AVAILABLE / WOLFPSA_STORE_IO_ERROR come from psa_store.h. */
#define WOLFPSA_STORE_MAX_PATH        256

#if defined(_WIN32) || defined(_MSC_VER)
    #define WOLFPSA_MKDIR(path) _mkdir(path)
#else
    #define WOLFPSA_MKDIR(path) mkdir((path), 0700)
#endif

typedef struct WOLFPSA_FileStoreCtx {
    XFILE file;
    int   is_write;
    int   has_temp;
    int   write_failed;
    char  final_name[WOLFPSA_STORE_MAX_PATH];
    char  temp_name[WOLFPSA_STORE_MAX_PATH];
} WOLFPSA_FileStoreCtx;

static void wolfPSA_StoreAbortTemp(WOLFPSA_FileStoreCtx* ctx)
{
    if (ctx != NULL && ctx->has_temp) {
        remove(ctx->temp_name);
        ctx->has_temp = 0;
    }
}

static int wolfPSA_StoreCommitTemp(WOLFPSA_FileStoreCtx* ctx)
{
    int ret = 0;

    if (ctx == NULL || ctx->has_temp == 0) {
        return 0;
    }

#if defined(_WIN32) || defined(_MSC_VER)
    if (!MoveFileExA(ctx->temp_name, ctx->final_name,
                     MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        ret = WOLFPSA_STORE_IO_ERROR;
    }
#else
    if (rename(ctx->temp_name, ctx->final_name) != 0) {
        ret = WOLFPSA_STORE_IO_ERROR;
    }
#endif

    if (ret == 0) {
        ctx->has_temp = 0;
    }

    return ret;
}

static int wolfPSA_StoreValidateDir(const char* dirPath)
{
#if defined(_WIN32) || defined(_MSC_VER)
    DWORD attrs;

    attrs = GetFileAttributesA(dirPath);
    if (attrs == INVALID_FILE_ATTRIBUTES) {
        return WOLFPSA_STORE_IO_ERROR;
    }
    if ((attrs & FILE_ATTRIBUTE_DIRECTORY) == 0 ||
        (attrs & FILE_ATTRIBUTE_REPARSE_POINT) != 0) {
        return WOLFPSA_STORE_IO_ERROR;
    }
    return 0;
#else
    struct stat st;

    if (lstat(dirPath, &st) != 0) {
        return WOLFPSA_STORE_IO_ERROR;
    }
    if (!S_ISDIR(st.st_mode)) {
        return WOLFPSA_STORE_IO_ERROR;
    }
#ifdef S_ISLNK
    if (S_ISLNK(st.st_mode)) {
        return WOLFPSA_STORE_IO_ERROR;
    }
#endif
    return 0;
#endif
}

static int wolfPSA_StoreEnsureDir(const char* dirPath)
{
    int ret;

    if (dirPath == NULL || dirPath[0] == '\0') {
        return WOLFPSA_STORE_IO_ERROR;
    }

    ret = wolfPSA_StoreValidateDir(dirPath);
    if (ret == 0) {
        return 0;
    }

    if (WOLFPSA_MKDIR(dirPath) == 0) {
        return wolfPSA_StoreValidateDir(dirPath);
    }

    if (errno == EEXIST) {
        return wolfPSA_StoreValidateDir(dirPath);
    }

    return WOLFPSA_STORE_IO_ERROR;
}

static int wolfPSA_StoreCreateTempFile(WOLFPSA_FileStoreCtx* ctx,
    const char* dirPath)
{
    if (ctx == NULL) {
        return WOLFPSA_STORE_IO_ERROR;
    }

#if defined(_WIN32) || defined(_MSC_VER)
    char templateBuf[WOLFPSA_STORE_MAX_PATH];
    int ret;
    int fd;

    ret = XSNPRINTF(templateBuf, sizeof(templateBuf),
        "%s/psa_tmp_%08lx_%08lx_XXXXXX", dirPath,
        (unsigned long)_getpid(), (unsigned long)GetTickCount());
    if (ret <= 0 || ret >= (int)sizeof(templateBuf)) {
        return WOLFPSA_STORE_IO_ERROR;
    }

    if (_mktemp_s(templateBuf, sizeof(templateBuf)) != 0) {
        return WOLFPSA_STORE_IO_ERROR;
    }

    fd = _open(templateBuf, _O_CREAT | _O_EXCL | _O_BINARY | _O_WRONLY,
               _S_IREAD | _S_IWRITE);
    if (fd == -1) {
        return WOLFPSA_STORE_IO_ERROR;
    }

    ctx->file = _fdopen(fd, "wb");
    if (ctx->file == NULL) {
        _close(fd);
        _unlink(templateBuf);
        return WOLFPSA_STORE_IO_ERROR;
    }

    {
        size_t copy_len = XSTRLEN(templateBuf);
        if (copy_len >= sizeof(ctx->temp_name)) {
            copy_len = sizeof(ctx->temp_name) - 1;
        }
        XMEMCPY(ctx->temp_name, templateBuf, copy_len);
        ctx->temp_name[copy_len] = '\0';
    }
    ctx->has_temp = 1;

    return 0;
#else
    char templateBuf[WOLFPSA_STORE_MAX_PATH];
    int fd;
    int ret;

    ret = XSNPRINTF(templateBuf, sizeof(templateBuf),
        "%s/psa_tmp_%08lx_%08lx_XXXXXX", dirPath,
        (unsigned long)getpid(), (unsigned long)time(NULL));
    if (ret <= 0 || ret >= (int)sizeof(templateBuf)) {
        return WOLFPSA_STORE_IO_ERROR;
    }

    fd = mkstemp(templateBuf);
    if (fd < 0) {
        return WOLFPSA_STORE_IO_ERROR;
    }

    if (fchmod(fd, S_IRUSR | S_IWUSR) != 0) {
        close(fd);
        unlink(templateBuf);
        return WOLFPSA_STORE_IO_ERROR;
    }

    ctx->file = fdopen(fd, "wb");
    if (ctx->file == NULL) {
        close(fd);
        unlink(templateBuf);
        return WOLFPSA_STORE_IO_ERROR;
    }

    {
        size_t copy_len = XSTRLEN(templateBuf);
        if (copy_len >= sizeof(ctx->temp_name)) {
            copy_len = sizeof(ctx->temp_name) - 1;
        }
        XMEMCPY(ctx->temp_name, templateBuf, copy_len);
        ctx->temp_name[copy_len] = '\0';
    }
    ctx->has_temp = 1;

    return 0;
#endif
}

static int wolfPSA_Store_Name(int type, unsigned long id1, unsigned long id2,
    char* name, int nameLen)
{
    int ret = 0;
    const char* str = NULL;
    enum { WOLFPSA_STORE_SUFFIX_RESERVE = 48 };

    str = XGETENV("WOLFPSA_TOKEN_PATH");

    if (str == NULL) {
#ifdef WOLFPSA_DEFAULT_TOKEN_PATH
        str = WC_STRINGIFY(WOLFPSA_DEFAULT_TOKEN_PATH);
#else
        /* Default to local store path for sandboxed testing. */
        str = "./.store";
#endif
    }

    if (str == NULL) {
        return -1;
    }
    if (nameLen <= WOLFPSA_STORE_SUFFIX_RESERVE) {
        return -1;
    }
    if (XSTRLEN(str) > (size_t)(nameLen - WOLFPSA_STORE_SUFFIX_RESERVE - 1)) {
        return -1;
    }

    switch (type) {
        case WOLFPSA_STORE_KEY:
            ret = XSNPRINTF(name, nameLen, "%s/psa_key_%016lx_%016lx", str,
                    id1, id2);
            break;
        default:
            ret = -1;
            break;
    }

    return ret;
}

int wolfPSA_Store_Remove(int type, unsigned long id1, unsigned long id2)
{
    int ret;
    const char* str = NULL;
    char name[WOLFPSA_STORE_MAX_PATH] = "\0";

    str = XGETENV("WOLFPSA_NO_STORE");
    if (str != NULL) {
        return WOLFPSA_STORE_NOT_AVAILABLE;
    }

    ret = wolfPSA_Store_Name(type, id1, id2, name, sizeof(name));
    if (ret > 0 && ret < (int)sizeof(name)) {
        ret = 0;
    }
    else if (ret != 0) {
        ret = -1;
    }

    if (ret == 0) {
        ret = remove(name);
        if (ret != 0 && errno == ENOENT) {
            ret = WOLFPSA_STORE_NOT_AVAILABLE;
        }
    }

    return ret;
}

int wolfPSA_Store_OpenSz(int type, unsigned long id1, unsigned long id2, int read,
    int variableSz, void** store)
{
    int ret = 0;
    const char* str = NULL;
    WOLFPSA_FileStoreCtx* ctx = NULL;
    char name[WOLFPSA_STORE_MAX_PATH] = "\0";

    str = XGETENV("WOLFPSA_NO_STORE");
    if (str != NULL) {
        return WOLFPSA_STORE_NOT_AVAILABLE;
    }

    ret = wolfPSA_Store_Name(type, id1, id2, name, sizeof(name));
    if (ret > 0 && ret < (int)sizeof(name)) {
        ret = 0;
    }
    else if (ret != 0) {
        ret = -1;
    }

    if (ret == 0) {
        ctx = (WOLFPSA_FileStoreCtx*)XMALLOC(sizeof(*ctx), NULL,
            DYNAMIC_TYPE_TMP_BUFFER);
        if (ctx == NULL) {
            ret = MEMORY_E;
        }
    }

    if (ret == 0) {
        char dirPath[WOLFPSA_STORE_MAX_PATH];
        const char* lastSlash = NULL;
        size_t nameLen = XSTRLEN(name);
        size_t i;

        XMEMSET(ctx, 0, sizeof(*ctx));
        ctx->file = XBADFILE;
        ctx->is_write = (read == 0);

        {
            size_t finalLen = XSTRLEN(name);
            if (finalLen >= sizeof(ctx->final_name)) {
            ret = WOLFPSA_STORE_IO_ERROR;
            }
            else {
                XMEMCPY(ctx->final_name, name, finalLen + 1);
            }
        }

        if (ret == 0 && read) {
            ctx->file = XFOPEN(name, "rb");
            if (ctx->file == NULL) {
                ret = WOLFPSA_STORE_NOT_AVAILABLE;
            }
        }
        else if (ret == 0) {
            for (i = 0; i < nameLen; i++) {
                if (name[i] == '/' || name[i] == '\\') {
                    lastSlash = &name[i];
                }
            }

            if (lastSlash == NULL) {
                ret = WOLFPSA_STORE_IO_ERROR;
            }
            else {
                int dirLen = (int)(lastSlash - name);

                if (dirLen <= 0 || dirLen >= (int)sizeof(dirPath)) {
                    ret = WOLFPSA_STORE_IO_ERROR;
                }
                else {
                    XMEMCPY(dirPath, name, dirLen);
                    dirPath[dirLen] = '\0';

                    ret = wolfPSA_StoreEnsureDir(dirPath);
                    if (ret == 0) {
                        ret = wolfPSA_StoreCreateTempFile(ctx, dirPath);
                    }
                }
            }
        }
    }

    if (ret == 0 && (ctx->file == NULL || ctx->file == XBADFILE)) {
        ret = WOLFPSA_STORE_IO_ERROR;
    }

    if (ret == 0) {
        *store = ctx;
    }
    else if (ctx != NULL) {
        if (ctx->file != NULL && ctx->file != XBADFILE) {
            XFCLOSE(ctx->file);
        }
        if (ctx->has_temp) {
            wolfPSA_StoreAbortTemp(ctx);
        }
        XFREE(ctx, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        ctx = NULL;
    }

    (void)variableSz;
    return ret;
}

int wolfPSA_Store_Open(int type, unsigned long id1, unsigned long id2, int read,
    void** store)
{
    return wolfPSA_Store_OpenSz(type, id1, id2, read, 0, store);
}

void wolfPSA_Store_Close(void* store)
{
    WOLFPSA_FileStoreCtx* ctx = (WOLFPSA_FileStoreCtx*)store;

    if (ctx != NULL) {
        int commitRet = 0;

        if (ctx->file != XBADFILE && ctx->file != NULL) {
            XFCLOSE(ctx->file);
            ctx->file = XBADFILE;
        }

        if (ctx->is_write && ctx->has_temp && ctx->write_failed == 0) {
            commitRet = wolfPSA_StoreCommitTemp(ctx);
            if (commitRet != 0) {
                wolfPSA_StoreAbortTemp(ctx);
            }
        }
        else if (ctx->has_temp) {
            wolfPSA_StoreAbortTemp(ctx);
        }

        XMEMSET(ctx, 0, sizeof(*ctx));
        XFREE(ctx, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }
}

int wolfPSA_Store_Read(void* store, unsigned char* buffer, int len)
{
    int ret = BUFFER_E;
    WOLFPSA_FileStoreCtx* ctx = (WOLFPSA_FileStoreCtx*)store;

    if (ctx != NULL && ctx->file != XBADFILE && ctx->file != NULL) {
        ret = (int)XFREAD(buffer, 1, len, ctx->file);
    }

    return ret;
}

int wolfPSA_Store_Write(void* store, unsigned char* buffer, int len)
{
    int ret = BUFFER_E;
    WOLFPSA_FileStoreCtx* ctx = (WOLFPSA_FileStoreCtx*)store;

    if (ctx != NULL && ctx->file != XBADFILE && ctx->file != NULL) {
        ret = (int)XFWRITE(buffer, 1, len, ctx->file);
        if (ret == len) {
            if (XFFLUSH(ctx->file) != 0) {
                ctx->write_failed = 1;
                ret = WOLFPSA_STORE_IO_ERROR;
            }
        }
        else {
            ctx->write_failed = 1;
        }
    }

    return ret;
}

#endif /* !WOLFPSA_CUSTOM_STORE */
