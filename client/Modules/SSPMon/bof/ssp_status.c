// ssp_status.c — point-in-time posture check: registration, DLL on disk,
// log presence + capture count. Read-only; no args.
#include "ssp_bof.h"

DECLSPEC_EXPORT void go(char* args, int len)
{
    (void)args; (void)len;
    wchar_t b[24];

    // 1. registry
    HKEY k;
    DWORD type = 0, sz = 0;
    SSP_OutA("[*] Lsa\\Security Packages: ");
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, SSP_REG_KEY, 0, KEY_QUERY_VALUE, &k) == ERROR_SUCCESS)
    {
        if (RegQueryValueExW(k, SSP_REG_VALUE, NULL, &type, NULL, &sz) == ERROR_SUCCESS && type == REG_MULTI_SZ && sz >= 4)
        {
            BYTE buf[512];
            if (sz > sizeof(buf)) sz = sizeof(buf);
            if (RegQueryValueExW(k, SSP_REG_VALUE, NULL, &type, buf, &sz) == ERROR_SUCCESS)
            {
                wchar_t* w = (wchar_t*)buf;
                while (*w) { SSP_OutW(w); SSP_OutA(" "); w += lstrlenW(w) + 1; }
                SSP_OutA("\n");
            }
            else SSP_OutA("<query failed>\n");
        }
        else SSP_OutA("<absent or empty>\n");
        RegCloseKey(k);
    }
    else { SSP_OutA("<key open failed — need admin>\n"); }

    // 2. RunAsPPL
    DWORD ppl = 0;
    if (SSP_RegGetDword(SSP_REG_PPL, &ppl))
    {
        SSP_OutA("[*] RunAsPPL = "); SSP_U64ToDecW(ppl, b); SSP_OutW(b); SSP_OutA("\n");
    }
    else SSP_OutA("[*] RunAsPPL = <unset>\n");

    // 3. DLL on disk
    wchar_t dllPath[MAX_PATH];
    if (SSP_Expand(SSP_DLL_PATH, dllPath, MAX_PATH))
    {
        HANDLE f = CreateFileW(dllPath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
        if (f != INVALID_HANDLE_VALUE)
        {
            DWORD hi = 0, lo = GetFileSize(f, &hi);
            CloseHandle(f);
            SSP_OutA("[*] System32\\sspmon2.dll present, size = "); SSP_U64ToDecW(((unsigned long long)hi << 32) | lo, b); SSP_OutW(b); SSP_OutA("\n");
        }
        else SSP_OutA("[*] System32\\sspmon2.dll ABSENT\n");
    }

    // 4. log + capture count
    wchar_t logPath[MAX_PATH];
    if (SSP_Expand(SSP_LOG_PATH, logPath, MAX_PATH))
    {
        HANDLE f = CreateFileW(logPath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
        if (f == INVALID_HANDLE_VALUE) { SSP_OutA("[*] Temp\\ssp.log ABSENT (no captures yet)\n"); return; }
        DWORD hi = 0, lo = GetFileSize(f, &hi);
        // count capture lines: scan for "v=2 " occurrences (2-byte aligned)
        DWORD size = lo;
        char* buf = (char*)HeapAlloc(GetProcessHeap(), 0, size ? size : 1);
        DWORD got = 0, hits = 0;
        if (buf && ReadFile(f, buf, size, &got, NULL))
        {
            for (DWORD i = 0; i + 8 <= got; i++)
                if (buf[i]=='v' && buf[i+1]==0 && buf[i+2]=='=' && buf[i+3]==0 && buf[i+4]=='2' && buf[i+5]==0 && buf[i+6]==' ' && buf[i+7]==0)
                    hits++;
        }
        if (buf) HeapFree(GetProcessHeap(), 0, buf);
        CloseHandle(f);
        SSP_OutA("[*] Temp\\ssp.log: "); SSP_U64ToDecW(((unsigned long long)hi << 32) | lo, b); SSP_OutW(b);
        SSP_OutA(" bytes, "); SSP_U64ToDecW(hits, b); SSP_OutW(b); SSP_OutA(" v2 capture lines\n");
    }
}
