/*
 * bof_output.c — BOF replacement for mimikatz's kull_m_output.c.
 *
 * Every mimikatz module logs through kprintf(); this redirects that single
 * choke point to a growable UTF-8 buffer instead of a console. Output is
 * flushed to Beacon in ONE BeaconOutput() call via bof_output_flush(), so the
 * operator sees a single "Received Output" chunk instead of one per line.
 * We compile this INSTEAD of modules/kull_m_output.c (which needs stdio/FILE).
 *
 * Requires: crt_shim.c (memcpy), beacon.h (BeaconOutput), kernel32
 *           (LocalAlloc/LocalFree/WideCharToMultiByte).
 */
#include "kull_m_output.h"
#include "bofdefs.h"

/* Route through library-qualified DFR paths so CoffeeLdr resolves them via
 * LoadLibrary+GetProcAddress. We call ntdll's _vsnwprintf/_vsnprintf directly
 * (always exported by ntdll) to avoid the msvcrt-lazy-resolve dance in crt_shim,
 * which can crash before printing if any dependency is unresolvable. */
DECLSPEC_IMPORT int WINAPI KERNEL32$WideCharToMultiByte(UINT, DWORD, LPCWCH, int, LPSTR, int, LPCCH, LPBOOL);
DECLSPEC_IMPORT int __cdecl NTDLL$_vsnwprintf(wchar_t*, size_t, const wchar_t*, va_list);
DECLSPEC_IMPORT int __cdecl NTDLL$_vsnprintf(char*, size_t, const char*, va_list);
#undef  WideCharToMultiByte
#define WideCharToMultiByte KERNEL32$WideCharToMultiByte

/* provided by crt_shim.c (pure-C, no msvcrt dependency) */
void* __cdecl memcpy(void* dest, const void* src, size_t n);

/* tentatively-defined in kull_m_output.h; provide here as the single owner */
FILE*    logfile = NULL;
wchar_t* outputBuffer = NULL;
size_t   outputBufferElements = 0, outputBufferElementsPosition = 0;

/* tentative in globals.h; give them a single strong definition so no
 * SHN_COMMON symbols leak into the BOF object. */
DWORD MIMIKATZ_NT_MAJOR_VERSION = 0;
DWORD MIMIKATZ_NT_MINOR_VERSION = 0;
DWORD MIMIKATZ_NT_BUILD_NUMBER = 0;

/* ---- growable UTF-8 output buffer ------------------------------------ */
static char*  bof_outbuf = NULL;
static SIZE_T bof_outlen = 0;
static SIZE_T bof_outcap = 0;

static void bof_out_append(const char* data, int len) {
    if (!data || len <= 0) return;
    if (bof_outlen + (SIZE_T)len + 1 > bof_outcap) {
        SIZE_T newcap = bof_outcap ? bof_outcap * 2 : 16384;
        while (newcap < bof_outlen + (SIZE_T)len + 1) newcap *= 2;
        char* nb = (char*)LocalAlloc(LPTR, newcap);
        if (!nb) return;
        if (bof_outbuf && bof_outlen) memcpy(nb, bof_outbuf, bof_outlen);
        if (bof_outbuf) LocalFree(bof_outbuf);
        bof_outbuf = nb;
        bof_outcap = newcap;
    }
    memcpy(bof_outbuf + bof_outlen, data, len);
    bof_outlen += (SIZE_T)len;
    bof_outbuf[bof_outlen] = 0;
}

/* narrow printf — same idea as kprintf but for char* formats (diagnostics). */
void bof_printf(const char* format, ...) {
    char buf[4096];
    va_list args;
    int n;

    if (!format) return;
    va_start(args, format);
    n = NTDLL$_vsnprintf(buf, sizeof(buf), format, args);
    va_end(args);
    if (n < 0) n = (int)sizeof(buf) - 1;
    if (n > (int)sizeof(buf) - 1) n = (int)sizeof(buf) - 1;
    bof_out_append(buf, n);
}

/* send everything buffered so far in a single BeaconOutput() call. */
void bof_output_flush(void) {
    if (bof_outbuf && bof_outlen > 0) {
        BeaconOutput(CALLBACK_OUTPUT, bof_outbuf, (int)bof_outlen);
        bof_outlen = 0;
        bof_outbuf[0] = 0;
    }
}

void kprintf(PCWCHAR format, ...) {
    wchar_t wbuf[4096];
    char    mb[8192];
    va_list args;
    int     n, cch;

    if (!format) return;

    va_start(args, format);
    n = NTDLL$_vsnwprintf(wbuf, 4096, format, args);
    va_end(args);

    if (n < 0) n = 4095;    /* truncated */
    if (n == 0) return;
    wbuf[n] = L'\0';

    cch = WideCharToMultiByte(CP_UTF8, 0, wbuf, n, mb, sizeof(mb), NULL, NULL);
    if (cch > 0) bof_out_append(mb, cch);
}

void kprintf_inputline(PCWCHAR format, ...) {
    va_list args;
    va_start(args, format);
    kprintf(format, args);
    va_end(args);
}

BOOL kull_m_output_file(PCWCHAR file) {
    /* no file logging in a BOF; NULL (close) succeeds, open fails */
    return (file == NULL) ? TRUE : FALSE;
}

void kull_m_output_init(void) {
    /* nothing to do — no console/codepage in a BOF */
}

void kull_m_output_clean(void) {
    /* nothing to do */
}
