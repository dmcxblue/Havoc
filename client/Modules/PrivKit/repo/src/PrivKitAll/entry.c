#include <windows.h>
#include <winsvc.h>
#include <sddl.h>

#ifdef BOF
#include "bofdefs.h"

void *__cdecl memcpy(void *dest, const void *src, size_t n)
{
    return MSVCRT$memcpy(dest, src, n);
}

void *__cdecl memset(void *dest, int c, size_t n)
{
    MSVCRT$memset(dest, c, n);
    return dest;
}
#endif

/* =========================================================
   1. AlwaysInstallElevated
   ========================================================= */
void CheckAlwaysInstallElevated(void)
{
    internal_printf("\n=== [1/10] AlwaysInstallElevated ===\n");
    HKEY hKey = NULL;
    DWORD val = 0, sz = sizeof(DWORD);
    int hklm = 0, hkcu = 0;

    if (ADVAPI32$RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Policies\\Microsoft\\Windows\\Installer",
        0, KEY_READ, &hKey) == ERROR_SUCCESS)
    {
        if (ADVAPI32$RegQueryValueExA(hKey, "AlwaysInstallElevated",
            NULL, NULL, (LPBYTE)&val, &sz) == ERROR_SUCCESS && val == 1)
            hklm = 1;
        ADVAPI32$RegCloseKey(hKey);
    }

    val = 0; sz = sizeof(DWORD);
    if (ADVAPI32$RegOpenKeyExA(HKEY_CURRENT_USER,
        "SOFTWARE\\Policies\\Microsoft\\Windows\\Installer",
        0, KEY_READ, &hKey) == ERROR_SUCCESS)
    {
        if (ADVAPI32$RegQueryValueExA(hKey, "AlwaysInstallElevated",
            NULL, NULL, (LPBYTE)&val, &sz) == ERROR_SUCCESS && val == 1)
            hkcu = 1;
        ADVAPI32$RegCloseKey(hKey);
    }

    if (hklm && hkcu)
        internal_printf("  [!] VULNERABLE: AlwaysInstallElevated is set in HKLM and HKCU\n");
    else
        internal_printf("  [-] Not vulnerable\n");
}

/* =========================================================
   2. Unquoted Service Paths
   ========================================================= */
void CheckUnquotedServicePaths(void)
{
    internal_printf("\n=== [2/10] Unquoted Service Paths ===\n");
    SC_HANDLE hSCM = ADVAPI32$OpenSCManagerA(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
    if (!hSCM) {
        internal_printf("  [-] Cannot open SCM\n");
        return;
    }

    DWORD needed = 0, count = 0, resume = 0;
    ADVAPI32$EnumServicesStatusA(hSCM, SERVICE_WIN32, SERVICE_STATE_ALL,
        NULL, 0, &needed, &count, &resume);

    LPBYTE buf = (LPBYTE)KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), 0, needed);
    if (!buf) { ADVAPI32$CloseServiceHandle(hSCM); return; }

    int found = 0;
    if (ADVAPI32$EnumServicesStatusA(hSCM, SERVICE_WIN32, SERVICE_STATE_ALL,
        (LPENUM_SERVICE_STATUSA)buf, needed, &needed, &count, &resume))
    {
        LPENUM_SERVICE_STATUSA svc = (LPENUM_SERVICE_STATUSA)buf;
        for (DWORD i = 0; i < count; i++)
        {
            SC_HANDLE hSvc = ADVAPI32$OpenServiceA(hSCM, svc[i].lpServiceName,
                SERVICE_QUERY_CONFIG);
            if (!hSvc) continue;

            DWORD cfgSz = 0;
            ADVAPI32$QueryServiceConfigA(hSvc, NULL, 0, &cfgSz);
            LPQUERY_SERVICE_CONFIGA cfg = (LPQUERY_SERVICE_CONFIGA)
                KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), 0, cfgSz);
            if (cfg && ADVAPI32$QueryServiceConfigA(hSvc, cfg, cfgSz, &cfgSz))
            {
                if (cfg->lpBinaryPathName &&
                    cfg->lpBinaryPathName[0] != '"' &&
                    MSVCRT$strchr(cfg->lpBinaryPathName, ' ') &&
                    MSVCRT$_stricmp(cfg->dwStartType == SERVICE_AUTO_START ? "auto" : "", "") == 0 + 1 - 1)
                {
                    char *p = cfg->lpBinaryPathName;
                    if (MSVCRT$_stricmp(p, "") != 0 &&
                        p[0] != '"' &&
                        MSVCRT$strchr(p, ' ') != NULL)
                    {
                        char upper[4] = {0};
                        for (int k = 0; k < 3 && p[k]; k++)
                            upper[k] = (char)MSVCRT$toupper(p[k]);
                        if (MSVCRT$strcmp(upper, "C:\\") == 0 ||
                            MSVCRT$strcmp(upper, "D:\\") == 0)
                        {
                            internal_printf("  [!] %s -> %s\n",
                                svc[i].lpServiceName, p);
                            found++;
                        }
                    }
                }
            }
            if (cfg) KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, cfg);
            ADVAPI32$CloseServiceHandle(hSvc);
        }
    }
    KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, buf);
    ADVAPI32$CloseServiceHandle(hSCM);
    if (!found)
        internal_printf("  [-] No unquoted service paths found\n");
}

/* =========================================================
   3. Modifiable Services (weak DACL)
   ========================================================= */
void CheckModifiableServices(void)
{
    internal_printf("\n=== [3/10] Modifiable Services ===\n");
    SC_HANDLE hSCM = ADVAPI32$OpenSCManagerA(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
    if (!hSCM) {
        internal_printf("  [-] Cannot open SCM\n");
        return;
    }

    DWORD needed = 0, count = 0, resume = 0;
    ADVAPI32$EnumServicesStatusA(hSCM, SERVICE_WIN32, SERVICE_STATE_ALL,
        NULL, 0, &needed, &count, &resume);

    LPBYTE buf = (LPBYTE)KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), 0, needed);
    if (!buf) { ADVAPI32$CloseServiceHandle(hSCM); return; }

    int found = 0;
    if (ADVAPI32$EnumServicesStatusA(hSCM, SERVICE_WIN32, SERVICE_STATE_ALL,
        (LPENUM_SERVICE_STATUSA)buf, needed, &needed, &count, &resume))
    {
        LPENUM_SERVICE_STATUSA svc = (LPENUM_SERVICE_STATUSA)buf;
        for (DWORD i = 0; i < count; i++)
        {
            SC_HANDLE hSvc = ADVAPI32$OpenServiceA(hSCM, svc[i].lpServiceName,
                SERVICE_CHANGE_CONFIG | SERVICE_START);
            if (hSvc)
            {
                internal_printf("  [!] Modifiable: %s (can change config + start)\n",
                    svc[i].lpServiceName);
                ADVAPI32$CloseServiceHandle(hSvc);
                found++;
                if (found > 20) {
                    internal_printf("  ... (truncated, >20 modifiable services)\n");
                    break;
                }
            }
        }
    }
    KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, buf);
    ADVAPI32$CloseServiceHandle(hSCM);
    if (!found)
        internal_printf("  [-] No modifiable services found\n");
}

/* =========================================================
   4. AutoLogon Credentials
   ========================================================= */
void CheckAutoLogon(void)
{
    internal_printf("\n=== [4/10] AutoLogon Credentials ===\n");
    HKEY hKey = NULL;
    char val[256] = {0};
    DWORD sz;
    int found = 0;

    if (ADVAPI32$RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
        0, KEY_READ, &hKey) == ERROR_SUCCESS)
    {
        sz = sizeof(val);
        if (ADVAPI32$RegQueryValueExA(hKey, "DefaultUserName",
            NULL, NULL, (LPBYTE)val, &sz) == ERROR_SUCCESS && val[0])
        {
            internal_printf("  DefaultUserName:  %s\n", val);
            found = 1;
        }

        MSVCRT$memset(val, 0, sizeof(val)); sz = sizeof(val);
        if (ADVAPI32$RegQueryValueExA(hKey, "DefaultPassword",
            NULL, NULL, (LPBYTE)val, &sz) == ERROR_SUCCESS && val[0])
        {
            internal_printf("  DefaultPassword:  %s\n", val);
            found = 1;
        }

        MSVCRT$memset(val, 0, sizeof(val)); sz = sizeof(val);
        if (ADVAPI32$RegQueryValueExA(hKey, "DefaultDomainName",
            NULL, NULL, (LPBYTE)val, &sz) == ERROR_SUCCESS && val[0])
        {
            internal_printf("  DefaultDomainName: %s\n", val);
        }

        MSVCRT$memset(val, 0, sizeof(val)); sz = sizeof(val);
        if (ADVAPI32$RegQueryValueExA(hKey, "AutoAdminLogon",
            NULL, NULL, (LPBYTE)val, &sz) == ERROR_SUCCESS && val[0] == '1')
        {
            internal_printf("  AutoAdminLogon:   Enabled\n");
        }

        ADVAPI32$RegCloseKey(hKey);
    }

    if (!found)
        internal_printf("  [-] No AutoLogon credentials found\n");
}

/* =========================================================
   5. Modifiable Scheduled Tasks (check task folder)
   ========================================================= */
void CheckScheduledTasks(void)
{
    internal_printf("\n=== [5/10] Writable Scheduled Task Files ===\n");
    char taskPath[MAX_PATH] = {0};
    KERNEL32$ExpandEnvironmentStringsA("%SystemRoot%\\System32\\Tasks", taskPath, MAX_PATH);

    char search[MAX_PATH + 4] = {0};
    MSVCRT$sprintf(search, "%s\\*", taskPath);

    WIN32_FIND_DATAA fd;
    HANDLE hFind = KERNEL32$FindFirstFileA(search, &fd);
    if (hFind == INVALID_HANDLE_VALUE) {
        internal_printf("  [-] Cannot enumerate task folder\n");
        return;
    }

    int found = 0;
    do {
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;

        char full[MAX_PATH * 2] = {0};
        MSVCRT$sprintf(full, "%s\\%s", taskPath, fd.cFileName);

        HANDLE hFile = KERNEL32$CreateFileA(full, GENERIC_WRITE, 0, NULL,
            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile != INVALID_HANDLE_VALUE) {
            internal_printf("  [!] Writable task file: %s\n", fd.cFileName);
            KERNEL32$CloseHandle(hFile);
            found++;
        }
    } while (KERNEL32$FindNextFileA(hFind, &fd) && found < 20);
    KERNEL32$FindClose(hFind);

    if (!found)
        internal_printf("  [-] No writable scheduled task files found\n");
}

/* =========================================================
   6. Writable PATH directories
   ========================================================= */
void CheckWritablePath(void)
{
    internal_printf("\n=== [6/10] Writable PATH Directories ===\n");
    char pathEnv[4096] = {0};
    DWORD len = KERNEL32$GetEnvironmentVariableA("PATH", pathEnv, sizeof(pathEnv));
    if (len == 0) {
        internal_printf("  [-] Cannot read PATH\n");
        return;
    }

    int found = 0;
    char *token = MSVCRT$strtok(pathEnv, ";");
    while (token)
    {
        char testFile[MAX_PATH + 32] = {0};
        MSVCRT$sprintf(testFile, "%s\\__privkit_test__.tmp", token);
        HANDLE hFile = KERNEL32$CreateFileA(testFile, GENERIC_WRITE, 0, NULL,
            CREATE_NEW, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_DELETE_ON_CLOSE, NULL);
        if (hFile != INVALID_HANDLE_VALUE) {
            internal_printf("  [!] Writable: %s\n", token);
            KERNEL32$CloseHandle(hFile);
            found++;
        }
        token = MSVCRT$strtok(NULL, ";");
    }

    if (!found)
        internal_printf("  [-] No writable PATH directories found\n");
}

/* =========================================================
   7. UAC Settings
   ========================================================= */
void CheckUACSettings(void)
{
    internal_printf("\n=== [7/10] UAC Settings ===\n");
    HKEY hKey = NULL;
    if (ADVAPI32$RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
        0, KEY_READ, &hKey) != ERROR_SUCCESS)
    {
        internal_printf("  [-] Cannot read UAC registry key\n");
        return;
    }

    DWORD val = 0, sz = sizeof(DWORD);
    if (ADVAPI32$RegQueryValueExA(hKey, "EnableLUA",
        NULL, NULL, (LPBYTE)&val, &sz) == ERROR_SUCCESS)
    {
        internal_printf("  EnableLUA:             %lu %s\n", val,
            val == 0 ? "(UAC DISABLED!)" : "(enabled)");
    }

    val = 0; sz = sizeof(DWORD);
    if (ADVAPI32$RegQueryValueExA(hKey, "ConsentPromptBehaviorAdmin",
        NULL, NULL, (LPBYTE)&val, &sz) == ERROR_SUCCESS)
    {
        const char *desc = "unknown";
        if (val == 0) desc = "Elevate without prompting (!)";
        else if (val == 1) desc = "Prompt for credentials on secure desktop";
        else if (val == 2) desc = "Prompt for consent on secure desktop";
        else if (val == 3) desc = "Prompt for credentials";
        else if (val == 4) desc = "Prompt for consent";
        else if (val == 5) desc = "Prompt for consent for non-Windows binaries";
        internal_printf("  ConsentPromptAdmin:    %lu (%s)\n", val, desc);
    }

    val = 0; sz = sizeof(DWORD);
    if (ADVAPI32$RegQueryValueExA(hKey, "LocalAccountTokenFilterPolicy",
        NULL, NULL, (LPBYTE)&val, &sz) == ERROR_SUCCESS)
    {
        internal_printf("  TokenFilterPolicy:     %lu %s\n", val,
            val == 1 ? "(remote UAC disabled for local admins!)" : "");
    }

    val = 0; sz = sizeof(DWORD);
    if (ADVAPI32$RegQueryValueExA(hKey, "FilterAdministratorToken",
        NULL, NULL, (LPBYTE)&val, &sz) == ERROR_SUCCESS)
    {
        internal_printf("  FilterAdminToken:      %lu\n", val);
    }

    ADVAPI32$RegCloseKey(hKey);
}

/* =========================================================
   8. Token Privileges
   ========================================================= */
void CheckTokenPrivileges(void)
{
    internal_printf("\n=== [8/10] Token Privileges ===\n");
    HANDLE hToken = NULL;
    if (!ADVAPI32$OpenProcessToken(KERNEL32$GetCurrentProcess(),
        TOKEN_QUERY, &hToken))
    {
        internal_printf("  [-] Cannot open process token\n");
        return;
    }

    DWORD needed = 0;
    ADVAPI32$GetTokenInformation(hToken, TokenPrivileges, NULL, 0, &needed);
    PTOKEN_PRIVILEGES tp = (PTOKEN_PRIVILEGES)
        KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), 0, needed);
    if (!tp) { KERNEL32$CloseHandle(hToken); return; }

    if (ADVAPI32$GetTokenInformation(hToken, TokenPrivileges, tp, needed, &needed))
    {
        const char *interesting[] = {
            "SeImpersonatePrivilege",
            "SeAssignPrimaryTokenPrivilege",
            "SeTcbPrivilege",
            "SeBackupPrivilege",
            "SeRestorePrivilege",
            "SeDebugPrivilege",
            "SeTakeOwnershipPrivilege",
            "SeLoadDriverPrivilege",
            "SeCreateTokenPrivilege",
            NULL
        };

        for (DWORD i = 0; i < tp->PrivilegeCount; i++)
        {
            char name[64] = {0};
            DWORD nameSz = sizeof(name);
            if (ADVAPI32$LookupPrivilegeNameA(NULL, &tp->Privileges[i].Luid,
                name, &nameSz))
            {
                const char *state = "Disabled";
                if (tp->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED)
                    state = "Enabled";
                else if (tp->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED_BY_DEFAULT)
                    state = "Default";

                int hot = 0;
                for (int j = 0; interesting[j]; j++)
                    if (MSVCRT$_stricmp(name, interesting[j]) == 0) { hot = 1; break; }

                if (hot)
                    internal_printf("  [!] %s (%s)\n", name, state);
                else
                    internal_printf("      %s (%s)\n", name, state);
            }
        }
    }
    KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, tp);
    KERNEL32$CloseHandle(hToken);
}

/* =========================================================
   9. Cached GPP Passwords (Groups.xml in SYSVOL)
   ========================================================= */
void CheckGPPPasswords(void)
{
    internal_printf("\n=== [9/10] Cached GPP Passwords ===\n");
    char sysvolBase[MAX_PATH] = {0};
    KERNEL32$ExpandEnvironmentStringsA("%SystemRoot%\\SYSVOL", sysvolBase, MAX_PATH);

    DWORD attr = KERNEL32$GetFileAttributesA(sysvolBase);
    if (attr == INVALID_FILE_ATTRIBUTES) {
        /* try LOGONSERVER share */
        char logon[256] = {0};
        KERNEL32$GetEnvironmentVariableA("LOGONSERVER", logon, sizeof(logon));
        if (logon[0]) {
            MSVCRT$sprintf(sysvolBase, "%s\\SYSVOL", logon);
            attr = KERNEL32$GetFileAttributesA(sysvolBase);
        }
    }

    if (attr == INVALID_FILE_ATTRIBUTES) {
        internal_printf("  [-] SYSVOL not accessible (not domain-joined or no access)\n");
        return;
    }

    const char *files[] = {
        "\\Policies\\*\\Machine\\Preferences\\Groups\\Groups.xml",
        "\\Policies\\*\\Machine\\Preferences\\Services\\Services.xml",
        "\\Policies\\*\\Machine\\Preferences\\Scheduledtasks\\Scheduledtasks.xml",
        "\\Policies\\*\\Machine\\Preferences\\DataSources\\DataSources.xml",
        NULL
    };

    int found = 0;
    for (int f = 0; files[f]; f++)
    {
        char pattern[MAX_PATH * 2] = {0};
        MSVCRT$sprintf(pattern, "%s%s", sysvolBase, files[f]);

        WIN32_FIND_DATAA fd;
        HANDLE hFind = KERNEL32$FindFirstFileA(pattern, &fd);
        if (hFind != INVALID_HANDLE_VALUE) {
            internal_printf("  [!] Found GPP file: %s\n", files[f]);
            KERNEL32$FindClose(hFind);
            found++;
        }
    }

    if (!found)
        internal_printf("  [-] No cached GPP password files found\n");
}

/* =========================================================
   10. Unattend / Sysprep Credential Files
   ========================================================= */
void CheckUnattendFiles(void)
{
    internal_printf("\n=== [10/10] Unattend/Sysprep Credential Files ===\n");
    char windir[MAX_PATH] = {0};
    KERNEL32$ExpandEnvironmentStringsA("%SystemRoot%", windir, MAX_PATH);

    const char *candidates[] = {
        "\\Panther\\Unattend.xml",
        "\\Panther\\unattend.xml",
        "\\Panther\\Unattended.xml",
        "\\Panther\\unattend\\Unattend.xml",
        "\\System32\\Sysprep\\unattend.xml",
        "\\System32\\Sysprep\\Unattend.xml",
        "\\System32\\Sysprep\\sysprep.xml",
        "\\sysprep.inf",
        "\\sysprep\\sysprep.xml",
        NULL
    };

    int found = 0;
    for (int i = 0; candidates[i]; i++)
    {
        char full[MAX_PATH * 2] = {0};
        MSVCRT$sprintf(full, "%s%s", windir, candidates[i]);

        DWORD attr = KERNEL32$GetFileAttributesA(full);
        if (attr != INVALID_FILE_ATTRIBUTES && !(attr & FILE_ATTRIBUTE_DIRECTORY))
        {
            internal_printf("  [!] Found: %s\n", full);
            found++;
        }
    }

    if (!found)
        internal_printf("  [-] No Unattend/Sysprep files found\n");
}

/* =========================================================
   BOF Entry Point
   arg: 0=all, 1-10=individual check
   ========================================================= */
#ifdef BOF
void go(char *args, int alen)
{
    datap parser;
    int   check = 0;

    BeaconDataParse(&parser, args, alen);
    check = BeaconDataInt(&parser);

    if (!bofstart())
        return;

    if (check == 0)
        internal_printf("========== PrivKit Privilege Escalation Audit ==========\n");

    if (check == 0 || check == 1)  CheckAlwaysInstallElevated();
    if (check == 0 || check == 2)  CheckUnquotedServicePaths();
    if (check == 0 || check == 3)  CheckModifiableServices();
    if (check == 0 || check == 4)  CheckAutoLogon();
    if (check == 0 || check == 5)  CheckScheduledTasks();
    if (check == 0 || check == 6)  CheckWritablePath();
    if (check == 0 || check == 7)  CheckUACSettings();
    if (check == 0 || check == 8)  CheckTokenPrivileges();
    if (check == 0 || check == 9)  CheckGPPPasswords();
    if (check == 0 || check == 10) CheckUnattendFiles();

    if (check == 0)
        internal_printf("\n========== Audit Complete ==========\n");

    printoutput(1);
}
#endif
