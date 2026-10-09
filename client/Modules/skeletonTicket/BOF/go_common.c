/*
 * go_common.c — arg parsing + NT version helpers shared by the BOFs.
 */
#include "go_common.h"
#include "globals.h"          /* MIMIKATZ_NT_* */
#include "kull_m_output.h"    /* kprintf / output init */

DECLSPEC_IMPORT void WINAPI NTDLL$RtlGetNtVersionNumbers(DWORD*, DWORD*, DWORD*);
#define RtlGetNtVersionNumbers NTDLL$RtlGetNtVersionNumbers

/* DFR: Havoc's CoffeeLdr does not resolve unqualified __imp_MultiByteToWideChar.
 * Route it through the library-qualified KERNEL32$ path. */
DECLSPEC_IMPORT int WINAPI KERNEL32$MultiByteToWideChar(UINT, DWORD, LPCCH, int, LPWSTR, int);
#undef  MultiByteToWideChar
#define MultiByteToWideChar KERNEL32$MultiByteToWideChar

void bof_get_nt_version(void) {
    RtlGetNtVersionNumbers(&MIMIKATZ_NT_MAJOR_VERSION, &MIMIKATZ_NT_MINOR_VERSION, &MIMIKATZ_NT_BUILD_NUMBER);
    MIMIKATZ_NT_BUILD_NUMBER &= 0x00007fff;
}

/*
 * Convert a UTF-8 arg blob into a wide argv[] (mimics CommandLineToArgvW:
 * space/tab separated, double-quote grouping). The returned pointer owns one
 * contiguous block; free with bof_argv_free().
 */
wchar_t** bof_argv_from_utf8(const char* utf8, int len, int* argc_out) {
    wchar_t* wide;
    wchar_t* block;
    wchar_t** argv;
    wchar_t* widestart;
    wchar_t* p;
    int nw, argc = 0, tok = 0, i;
    size_t ptrsize, widesize;

    *argc_out = 0;
    if (!utf8 || len == 0) return NULL;
    if (len < 0) len = (int)strlen(utf8);

    nw = MultiByteToWideChar(CP_UTF8, 0, utf8, len, NULL, 0);
    if (nw <= 0) return NULL;

    wide = (wchar_t*)LocalAlloc(LPTR, ((size_t)nw + 1) * sizeof(wchar_t));
    if (!wide) return NULL;
    MultiByteToWideChar(CP_UTF8, 0, utf8, len, wide, nw);
    wide[nw] = L'\0';

    /* count tokens */
    p = wide;
    while (*p) {
        while (*p == L' ' || *p == L'\t') p++;
        if (!*p) break;
        argc++;
        if (*p == L'"') { p++; while (*p && *p != L'"') p++; if (*p) p++; }
        else { while (*p && *p != L' ' && *p != L'\t') p++; }
    }

    ptrsize  = ((size_t)argc + 1) * sizeof(wchar_t*);
    widesize = ((size_t)nw + 1) * sizeof(wchar_t);

    /* one block: [hidden block ptr][argv array][wide buffer] */
    block = (wchar_t*)LocalAlloc(LPTR, sizeof(wchar_t*) + ptrsize + widesize);
    if (!block) { LocalFree(wide); return NULL; }

    argv      = (wchar_t**)((char*)block + sizeof(wchar_t*));
    widestart = (wchar_t*)((char*)argv + ptrsize);
    *((void**)block) = block;          /* hidden pointer for bof_argv_free */

    for (i = 0; i <= nw; i++) widestart[i] = wide[i];
    LocalFree(wide);

    p = widestart;
    while (*p && tok < argc) {
        while (*p == L' ' || *p == L'\t') p++;
        if (!*p) break;
        if (*p == L'"') {
            p++;
            argv[tok++] = (wchar_t*)p;
            while (*p && *p != L'"') p++;
            if (*p) *p++ = L'\0';
        } else {
            argv[tok++] = (wchar_t*)p;
            while (*p && *p != L' ' && *p != L'\t') p++;
            if (*p) *p++ = L'\0';
        }
    }
    argv[argc] = NULL;

    *argc_out = argc;
    return argv;
}

void bof_argv_free(wchar_t** argv) {
    if (!argv) return;
    LocalFree(((void**)argv)[-1]);
}
