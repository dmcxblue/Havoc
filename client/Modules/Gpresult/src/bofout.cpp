/*
 * Buffered output engine (see include/bofout.h).
 * Moved out of entry.cpp so the domain sweep can share the same
 * single-flush output contract.
 */

#include <windows.h>
#include <stdarg.h>

extern "C" {
#include "beacon.h"

    DECLSPEC_IMPORT void*  __cdecl MSVCRT$calloc(size_t n, size_t s);
    DECLSPEC_IMPORT void   __cdecl MSVCRT$free(void* p);
    DECLSPEC_IMPORT void*  __cdecl MSVCRT$memcpy(void* d, const void* s, size_t n);
    DECLSPEC_IMPORT int    __cdecl MSVCRT$vsnprintf(char* d, size_t n, const char* fmt, va_list arg);
}

#include "bofout.h"

static char* g_out    = (char*)1;
static int   g_outLen = 1;

void bof_flush(void)
{
    if (g_out != NULL && g_out != (char*)1 && g_outLen > 0)
        BeaconOutput(CALLBACK_OUTPUT, g_out, g_outLen);
    g_outLen = 0;
    if (g_out != NULL && g_out != (char*)1)
        g_out[0] = '\0';
}

void bof_printf(const char* fmt, ...)
{
    va_list ap;
    char    tmp[2048];
    int     n, remaining, toCopy;
    if (g_out == NULL || g_out == (char*)1) return;
    va_start(ap, fmt);
    n = MSVCRT$vsnprintf(tmp, sizeof(tmp), fmt, ap);
    va_end(ap);
    if (n <= 0) return;
    if (n >= (int)sizeof(tmp)) n = (int)sizeof(tmp) - 1;
    if (g_outLen + n >= OUTBUFSIZE) bof_flush();
    remaining = OUTBUFSIZE - g_outLen - 1;
    toCopy    = (n < remaining) ? n : remaining;
    MSVCRT$memcpy(g_out + g_outLen, tmp, (size_t)toCopy);
    g_outLen += toCopy;
    g_out[g_outLen] = '\0';
}

void bof_output_init(void)
{
    g_out    = (char*)MSVCRT$calloc(OUTBUFSIZE, 1);
    g_outLen = 0;
    if (g_out) g_out[0] = '\0';
}

void bof_output_done(void)
{
    if (g_out && g_out != (char*)1)
        MSVCRT$free(g_out);
    g_out    = (char*)1;
    g_outLen = 1;
}
