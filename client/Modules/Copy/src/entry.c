#include <windows.h>
#include "../../RemoteOps/CS-Remote-OPs-BOF/src/common/bofdefs.h"
#include "../../RemoteOps/CS-Remote-OPs-BOF/src/common/base.c"

DECLSPEC_IMPORT BOOL  WINAPI KERNEL32$CopyFileA(LPCSTR, LPCSTR, BOOL);
DECLSPEC_IMPORT DWORD WINAPI KERNEL32$GetFileAttributesA(LPCSTR);

void *memcpy(void *dest, const void *src, size_t n) { return MSVCRT$memcpy(dest, src, n); }
void *memset(void *s, int c, size_t n)              { MSVCRT$memset(s, c, n); return s; }

void go(char *args, int len)
{
    datap parser;
    char *src = NULL, *dst = NULL;
    int   srcLen = 0, dstLen = 0;
    char  finalDst[MAX_PATH];
    int   fdLen = 0, i;
    DWORD dstAttrs;
    BOOL  dstIsDir;

    bofstart();

    BeaconDataParse(&parser, args, len);
    src = BeaconDataExtract(&parser, &srcLen);
    dst = BeaconDataExtract(&parser, &dstLen);

    if (!src || !dst || srcLen <= 1 || dstLen <= 1)
    {
        internal_printf("[-] Missing source or destination path\n");
        printoutput(TRUE);
        return;
    }

    /* If destination is an existing directory, append basename(src). */
    dstAttrs = KERNEL32$GetFileAttributesA(dst);
    dstIsDir = (dstAttrs != INVALID_FILE_ATTRIBUTES) &&
               (dstAttrs & FILE_ATTRIBUTE_DIRECTORY);

    if (dstIsDir)
    {
        const char *base = src;
        for (i = 0; src[i] != '\0'; i++)
            if (src[i] == '\\' || src[i] == '/')
                base = &src[i + 1];

        for (i = 0; dst[i] != '\0' && fdLen < MAX_PATH - 1; i++)
            finalDst[fdLen++] = dst[i];
        if (fdLen > 0 &&
            finalDst[fdLen - 1] != '\\' && finalDst[fdLen - 1] != '/' &&
            fdLen < MAX_PATH - 1)
            finalDst[fdLen++] = '\\';
        for (i = 0; base[i] != '\0' && fdLen < MAX_PATH - 1; i++)
            finalDst[fdLen++] = base[i];
        finalDst[fdLen] = '\0';
    }
    else
    {
        for (i = 0; dst[i] != '\0' && fdLen < MAX_PATH - 1; i++)
            finalDst[fdLen++] = dst[i];
        finalDst[fdLen] = '\0';
    }

    if (KERNEL32$CopyFileA(src, finalDst, FALSE))
    {
        internal_printf("[+] Copied: %s -> %s\n", src, finalDst);
    }
    else
    {
        DWORD err = KERNEL32$GetLastError();
        internal_printf("[-] Copy failed: %s -> %s (error %lu)\n", src, finalDst, err);
        if (err == ERROR_FILE_NOT_FOUND)
            internal_printf("    Source file not found\n");
        else if (err == ERROR_PATH_NOT_FOUND)
            internal_printf("    Destination path not found\n");
        else if (err == ERROR_ACCESS_DENIED)
            internal_printf("    Access denied\n");
        else if (err == ERROR_SHARING_VIOLATION)
            internal_printf("    Sharing violation (file in use)\n");
    }

    printoutput(TRUE);
}
