/*
 * UacCheck BOF — recon-only UAC bypass feasibility checker.
 *
 * For each UAC-BOF-Bonanza technique, checks whether the bypass would
 * succeed on the current target without actually firing it.  Checks:
 *   - OS version / build number gates
 *   - UAC registry settings (EnableLUA, ConsentPromptBehaviorAdmin)
 *   - Token integrity level and admin group membership
 *   - Per-technique preconditions (file existence, registry key
 *     writability, COM CLSID presence, scheduled task existence)
 *
 * Modes (packed as a single int by the Python wrapper):
 *   0 = all    — run every check
 *   1 = env    — environment info only (OS, UAC settings, token)
 *   2 = trustedpath
 *   3 = silentcleanup
 *   4 = sspidatagram
 *   5 = registrycommand
 *   6 = elevatedcom
 *   7 = colordataproxy
 *   8 = editionupgrade
 */

#include <windows.h>
#include "../../RemoteOps/CS-Remote-OPs-BOF/src/common/bofdefs.h"
#include "../../RemoteOps/CS-Remote-OPs-BOF/src/common/base.c"

DECLSPEC_IMPORT LONG   WINAPI ADVAPI32$RegOpenKeyExA(HKEY, LPCSTR, DWORD, REGSAM, PHKEY);
DECLSPEC_IMPORT LONG   WINAPI ADVAPI32$RegCloseKey(HKEY);
DECLSPEC_IMPORT LONG   WINAPI ADVAPI32$RegQueryValueExA(HKEY, LPCSTR, LPDWORD, LPDWORD, LPBYTE, LPDWORD);
DECLSPEC_IMPORT BOOL   WINAPI ADVAPI32$OpenProcessToken(HANDLE, DWORD, PHANDLE);
DECLSPEC_IMPORT BOOL   WINAPI ADVAPI32$GetTokenInformation(HANDLE, TOKEN_INFORMATION_CLASS, LPVOID, DWORD, PDWORD);
DECLSPEC_IMPORT PUCHAR WINAPI ADVAPI32$GetSidSubAuthorityCount(PSID);
DECLSPEC_IMPORT PDWORD WINAPI ADVAPI32$GetSidSubAuthority(PSID, DWORD);
DECLSPEC_IMPORT BOOL   WINAPI ADVAPI32$AllocateAndInitializeSid(PSID_IDENTIFIER_AUTHORITY, BYTE, DWORD, DWORD, DWORD, DWORD, DWORD, DWORD, DWORD, DWORD, PSID*);
DECLSPEC_IMPORT PVOID  WINAPI ADVAPI32$FreeSid(PSID);
DECLSPEC_IMPORT BOOL   WINAPI ADVAPI32$EqualSid(PSID, PSID);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$GetCurrentProcess(void);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$CloseHandle(HANDLE);
DECLSPEC_IMPORT DWORD  WINAPI KERNEL32$GetFileAttributesA(LPCSTR);
DECLSPEC_IMPORT DWORD  WINAPI KERNEL32$ExpandEnvironmentStringsA(LPCSTR, LPSTR, DWORD);
DECLSPEC_IMPORT HMODULE WINAPI KERNEL32$LoadLibraryA(LPCSTR);
DECLSPEC_IMPORT FARPROC WINAPI KERNEL32$GetProcAddress(HMODULE, LPCSTR);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$FreeLibrary(HMODULE);

void *memcpy(void *dest, const void *src, size_t n) { return MSVCRT$memcpy(dest, src, n); }
void *memset(void *s, int c, size_t n)              { MSVCRT$memset(s, c, n); return s; }

typedef LONG (NTAPI *pRtlGetVersion)(PRTL_OSVERSIONINFOW);

/* ================================================================
   Environment context — gathered once, shared by all technique checks
   ================================================================ */
typedef struct {
    DWORD dwMajor;
    DWORD dwMinor;
    DWORD dwBuild;
    DWORD dwEnableLUA;
    DWORD dwConsentBehavior;
    DWORD dwIntegrityLevel;
    BOOL  bIsAdmin;
    BOOL  bIsElevated;
    BOOL  bEnvValid;
} UAC_ENV;

static void GatherEnvironment(UAC_ENV *env)
{
    HKEY     hKey      = NULL;
    HANDLE   hToken    = NULL;
    HANDLE   hHeap     = NULL;
    LONG     lResult   = 0;
    DWORD    dwSize    = 0;
    DWORD    dwType    = 0;
    DWORD    dwLenNeeded = 0;
    PSID     pAdminSid = NULL;
    SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;

    memset(env, 0, sizeof(UAC_ENV));

    /* --- OS version via RtlGetVersion --- */
    HMODULE hNtdll = KERNEL32$LoadLibraryA("ntdll.dll");
    if (hNtdll)
    {
        pRtlGetVersion fnVer = (pRtlGetVersion)KERNEL32$GetProcAddress(hNtdll, "RtlGetVersion");
        if (fnVer)
        {
            RTL_OSVERSIONINFOW vi;
            memset(&vi, 0, sizeof(vi));
            vi.dwOSVersionInfoSize = sizeof(vi);
            if (fnVer(&vi) == 0)
            {
                env->dwMajor = vi.dwMajorVersion;
                env->dwMinor = vi.dwMinorVersion;
                env->dwBuild = vi.dwBuildNumber;
            }
        }
        KERNEL32$FreeLibrary(hNtdll);
    }

    /* --- UAC registry settings --- */
    env->dwEnableLUA      = 1;
    env->dwConsentBehavior = 5;

    lResult = ADVAPI32$RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
        0, KEY_QUERY_VALUE, &hKey);
    if (lResult == ERROR_SUCCESS)
    {
        dwSize = sizeof(DWORD);
        if (ADVAPI32$RegQueryValueExA(hKey, "EnableLUA", NULL, &dwType,
                (LPBYTE)&env->dwEnableLUA, &dwSize) != ERROR_SUCCESS)
            env->dwEnableLUA = 1;

        dwSize = sizeof(DWORD);
        if (ADVAPI32$RegQueryValueExA(hKey, "ConsentPromptBehaviorAdmin", NULL, &dwType,
                (LPBYTE)&env->dwConsentBehavior, &dwSize) != ERROR_SUCCESS)
            env->dwConsentBehavior = 5;

        ADVAPI32$RegCloseKey(hKey);
        hKey = NULL;
    }

    /* --- Token: integrity level --- */
    if (!ADVAPI32$OpenProcessToken(KERNEL32$GetCurrentProcess(), TOKEN_QUERY, &hToken))
    {
        env->bEnvValid = TRUE;
        return;
    }

    hHeap = KERNEL32$GetProcessHeap();

    ADVAPI32$GetTokenInformation(hToken, TokenIntegrityLevel, NULL, 0, &dwLenNeeded);
    if (dwLenNeeded > 0)
    {
        PTOKEN_MANDATORY_LABEL pTIL = (PTOKEN_MANDATORY_LABEL)KERNEL32$HeapAlloc(hHeap, HEAP_ZERO_MEMORY, dwLenNeeded);
        if (pTIL)
        {
            if (ADVAPI32$GetTokenInformation(hToken, TokenIntegrityLevel, pTIL, dwLenNeeded, &dwLenNeeded))
            {
                PUCHAR pCount = ADVAPI32$GetSidSubAuthorityCount(pTIL->Label.Sid);
                if (pCount && *pCount > 0)
                {
                    PDWORD pLevel = ADVAPI32$GetSidSubAuthority(pTIL->Label.Sid, (DWORD)(*pCount - 1));
                    if (pLevel)
                        env->dwIntegrityLevel = *pLevel;
                }
            }
            KERNEL32$HeapFree(hHeap, 0, pTIL);
        }
    }

    if (env->dwIntegrityLevel >= SECURITY_MANDATORY_HIGH_RID)
        env->bIsElevated = TRUE;

    /* --- Token: admin group membership ---
       CheckTokenMembership returns FALSE for the admin SID on a UAC
       filtered token because the group is SE_GROUP_USE_FOR_DENY_ONLY
       (disabled).  That's the exact scenario we're checking for — a
       local admin whose token was filtered by UAC.  So we walk
       TokenGroups with EqualSid instead, which finds the SID regardless
       of its attributes.  This matches PrivKit's UACStatusCheck. */
    if (ADVAPI32$AllocateAndInitializeSid(&NtAuthority, 2,
            SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,
            0, 0, 0, 0, 0, 0, &pAdminSid))
    {
        DWORD dwGroupLen = 0;
        ADVAPI32$GetTokenInformation(hToken, TokenGroups, NULL, 0, &dwGroupLen);
        if (dwGroupLen > 0)
        {
            PTOKEN_GROUPS pGroups = (PTOKEN_GROUPS)KERNEL32$HeapAlloc(hHeap, HEAP_ZERO_MEMORY, dwGroupLen);
            if (pGroups)
            {
                if (ADVAPI32$GetTokenInformation(hToken, TokenGroups, pGroups, dwGroupLen, &dwGroupLen))
                {
                    DWORD gi;
                    for (gi = 0; gi < pGroups->GroupCount; gi++)
                    {
                        if (ADVAPI32$EqualSid(pAdminSid, pGroups->Groups[gi].Sid))
                        {
                            env->bIsAdmin = TRUE;
                            break;
                        }
                    }
                }
                KERNEL32$HeapFree(hHeap, 0, pGroups);
            }
        }
        ADVAPI32$FreeSid(pAdminSid);
    }

    KERNEL32$CloseHandle(hToken);
    env->bEnvValid = TRUE;
}

static void PrintEnvironment(UAC_ENV *env)
{
    internal_printf("=== UAC Bypass Feasibility Check ===\n\n");
    internal_printf("[*] OS Version: %lu.%lu (Build %lu)\n", env->dwMajor, env->dwMinor, env->dwBuild);
    internal_printf("[*] EnableLUA: %s\n", env->dwEnableLUA ? "Yes (UAC active)" : "No (UAC disabled)");

    internal_printf("[*] ConsentPromptBehaviorAdmin: %lu", env->dwConsentBehavior);
    switch (env->dwConsentBehavior)
    {
        case 0: internal_printf(" (Elevate without prompting)\n"); break;
        case 1: internal_printf(" (Prompt for credentials on secure desktop)\n"); break;
        case 2: internal_printf(" (Prompt for consent on secure desktop)\n"); break;
        case 3: internal_printf(" (Prompt for credentials)\n"); break;
        case 4: internal_printf(" (Prompt for consent)\n"); break;
        case 5: internal_printf(" (Prompt for consent for non-Windows binaries)\n"); break;
        default: internal_printf(" (Unknown)\n"); break;
    }

    internal_printf("[*] Integrity Level: ");
    if (env->dwIntegrityLevel >= SECURITY_MANDATORY_SYSTEM_RID)
        internal_printf("System\n");
    else if (env->dwIntegrityLevel >= SECURITY_MANDATORY_HIGH_RID)
        internal_printf("High (Elevated)\n");
    else if (env->dwIntegrityLevel >= SECURITY_MANDATORY_MEDIUM_RID)
        internal_printf("Medium\n");
    else if (env->dwIntegrityLevel >= SECURITY_MANDATORY_LOW_RID)
        internal_printf("Low\n");
    else
        internal_printf("Untrusted\n");

    internal_printf("[*] Local Admin Group Member: %s\n", env->bIsAdmin ? "Yes" : "No");

    internal_printf("\n[*] Bypass Eligibility: ");
    if (env->bIsElevated)
    {
        internal_printf("Already elevated — UAC bypass not needed\n");
    }
    else if (!env->dwEnableLUA)
    {
        internal_printf("UAC disabled — all processes run elevated\n");
    }
    else if (env->bIsAdmin)
    {
        internal_printf("Medium-integrity admin with UAC — bypasses applicable\n");
    }
    else
    {
        internal_printf("Not a local admin — UAC bypass will NOT work\n");
    }
}

/* ================================================================
   Helper: can the current user run UAC bypasses at all?
   Must be a local admin with a medium-integrity (filtered) token.
   ================================================================ */
static BOOL CanBypass(UAC_ENV *env)
{
    return env->dwEnableLUA && env->bIsAdmin && !env->bIsElevated;
}

/* ================================================================
   Helper: check if a file exists (expand env vars first)
   ================================================================ */
static BOOL FileExistsExpanded(LPCSTR path)
{
    char expanded[MAX_PATH];
    DWORD len = KERNEL32$ExpandEnvironmentStringsA(path, expanded, MAX_PATH);
    if (len == 0 || len > MAX_PATH)
        return FALSE;
    DWORD attrs = KERNEL32$GetFileAttributesA(expanded);
    return (attrs != INVALID_FILE_ATTRIBUTES && !(attrs & FILE_ATTRIBUTE_DIRECTORY));
}

/* ================================================================
   Helper: can we write to an HKCU registry key?
   ================================================================ */
static BOOL CanWriteHKCUKey(LPCSTR subkey)
{
    HKEY hKey = NULL;
    LONG r = ADVAPI32$RegOpenKeyExA(HKEY_CURRENT_USER, subkey, 0,
                                     KEY_SET_VALUE | KEY_QUERY_VALUE, &hKey);
    if (r == ERROR_SUCCESS)
    {
        ADVAPI32$RegCloseKey(hKey);
        return TRUE;
    }
    /* Key doesn't exist yet — try to create it (then delete) */
    DWORD dwDisp = 0;
    r = ADVAPI32$RegOpenKeyExA(HKEY_CURRENT_USER, subkey, 0, KEY_READ, &hKey);
    if (r == ERROR_FILE_NOT_FOUND)
        return TRUE;  /* HKCU — we can create it */
    if (r == ERROR_SUCCESS)
        ADVAPI32$RegCloseKey(hKey);
    return (r == ERROR_SUCCESS);
}

/* ================================================================
   Helper: check if an HKLM registry key is readable
   ================================================================ */
static BOOL HKLMKeyExists(LPCSTR subkey)
{
    HKEY hKey = NULL;
    LONG r = ADVAPI32$RegOpenKeyExA(HKEY_LOCAL_MACHINE, subkey, 0, KEY_READ, &hKey);
    if (r == ERROR_SUCCESS)
    {
        ADVAPI32$RegCloseKey(hKey);
        return TRUE;
    }
    return FALSE;
}

/* ================================================================
   Per-technique checks
   ================================================================ */

static void CheckTrustedPath(UAC_ENV *env)
{
    internal_printf("\n--- TrustedPathDLLHijack ---\n");
    internal_printf("[*] Technique: Create fake 'C:\\Windows \\System32\\' (trailing space)\n");
    internal_printf("[*]   then drop a malicious Secur32.dll, execute ComputerDefaults.exe\n");

    if (!CanBypass(env))
    {
        internal_printf("[-] NOT VIABLE: requires medium-integrity local admin token\n");
        return;
    }

    BOOL bCompDef = FileExistsExpanded("%SystemRoot%\\System32\\ComputerDefaults.exe");
    internal_printf("[*] ComputerDefaults.exe present: %s\n", bCompDef ? "Yes" : "No");

    if (env->dwBuild >= 22000)
        internal_printf("[!] Warning: Win11 (build %lu) may have patched this vector\n", env->dwBuild);

    if (bCompDef)
        internal_printf("[+] VIABLE -> uac-bypass trustedpath <local_dll>\n");
    else
        internal_printf("[-] NOT VIABLE: ComputerDefaults.exe not found\n");
}

static void CheckSilentCleanup(UAC_ENV *env)
{
    internal_printf("\n--- SilentCleanupWinDir ---\n");
    internal_printf("[*] Technique: Set HKCU\\Environment\\windir to hijack path,\n");
    internal_printf("[*]   SilentCleanup scheduled task runs as elevated\n");

    if (!CanBypass(env))
    {
        internal_printf("[-] NOT VIABLE: requires medium-integrity local admin token\n");
        return;
    }

    BOOL bEnvKey = CanWriteHKCUKey("Environment");
    internal_printf("[*] HKCU\\Environment writable: %s\n", bEnvKey ? "Yes" : "No");

    BOOL bTaskExists = HKLMKeyExists(
        "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tree"
        "\\Microsoft\\Windows\\DiskCleanup\\SilentCleanup");
    internal_printf("[*] SilentCleanup task registered: %s\n", bTaskExists ? "Yes" : "No");

    if (bEnvKey && bTaskExists)
        internal_printf("[+] VIABLE -> uac-bypass silentcleanup <local_exe>\n");
    else
        internal_printf("[-] NOT VIABLE: missing precondition(s)\n");
}

static void CheckSspiDatagram(UAC_ENV *env)
{
    internal_printf("\n--- SSPI Datagram Contexts ---\n");
    internal_printf("[*] Technique: SSPI datagram-style auth context abuse for token theft\n");

    if (!CanBypass(env))
    {
        internal_printf("[-] NOT VIABLE: requires medium-integrity local admin token\n");
        return;
    }

    if (env->dwBuild < 17134)
    {
        internal_printf("[-] NOT VIABLE: requires Windows 10 1803+ (build 17134+), current: %lu\n", env->dwBuild);
        return;
    }

    internal_printf("[*] OS build %lu >= 17134: OK\n", env->dwBuild);
    internal_printf("[+] VIABLE -> uac-bypass sspidatagram <remote_file>\n");
}

static void CheckRegistryCommand(UAC_ENV *env)
{
    internal_printf("\n--- RegistryShellCommand (fodhelper / ms-settings) ---\n");
    internal_printf("[*] Technique: Write to HKCU\\Software\\Classes\\ms-settings\\Shell\\Open\\command,\n");
    internal_printf("[*]   then trigger fodhelper.exe (auto-elevates via ms-settings handler)\n");

    if (!CanBypass(env))
    {
        internal_printf("[-] NOT VIABLE: requires medium-integrity local admin token\n");
        return;
    }

    BOOL bFodhelper = FileExistsExpanded("%SystemRoot%\\System32\\fodhelper.exe");
    internal_printf("[*] fodhelper.exe present: %s\n", bFodhelper ? "Yes" : "No");

    BOOL bCanWrite = CanWriteHKCUKey("Software\\Classes\\ms-settings\\Shell\\Open\\command");
    internal_printf("[*] HKCU\\...\\ms-settings\\Shell\\Open\\command writable: %s\n",
                    bCanWrite ? "Yes" : "No");

    if (env->dwBuild < 15063)
    {
        internal_printf("[-] NOT VIABLE: requires Windows 10 1703+ (build 15063+), current: %lu\n", env->dwBuild);
        return;
    }

    if (bFodhelper && bCanWrite)
        internal_printf("[+] VIABLE -> uac-bypass registrycommand <remote_file>\n");
    else
        internal_printf("[-] NOT VIABLE: missing precondition(s)\n");
}

static void CheckElevatedCOM(UAC_ENV *env)
{
    internal_printf("\n--- CmstpElevatedCOM (ICMLuaUtil) ---\n");
    internal_printf("[*] Technique: CoCreateInstance of CMSTPLUA COM object with elevation moniker\n");
    internal_printf("[*]   ICMLuaUtil::ShellExec to launch payload elevated\n");

    if (!CanBypass(env))
    {
        internal_printf("[-] NOT VIABLE: requires medium-integrity local admin token\n");
        return;
    }

    BOOL bCmstp = FileExistsExpanded("%SystemRoot%\\System32\\cmstp.exe");
    internal_printf("[*] cmstp.exe present: %s\n", bCmstp ? "Yes" : "No");

    BOOL bClsid = HKLMKeyExists("SOFTWARE\\Classes\\CLSID\\{3E5FC7F9-9A51-4367-9063-A120244FBEC7}");
    internal_printf("[*] CMSTPLUA CLSID registered: %s\n", bClsid ? "Yes" : "No");

    if (bCmstp && bClsid)
        internal_printf("[+] VIABLE -> uac-bypass elevatedcom <remote_file>\n");
    else
        internal_printf("[-] NOT VIABLE: missing precondition(s)\n");
}

static void CheckColorDataProxy(UAC_ENV *env)
{
    internal_printf("\n--- ColorDataProxy + ICMLuaUtil ---\n");
    internal_printf("[*] Technique: Abuse ColorDataProxy COM interface to write to a protected\n");
    internal_printf("[*]   location, then ICMLuaUtil::ShellExec from there\n");

    if (!CanBypass(env))
    {
        internal_printf("[-] NOT VIABLE: requires medium-integrity local admin token\n");
        return;
    }

    BOOL bCmstp = FileExistsExpanded("%SystemRoot%\\System32\\cmstp.exe");
    internal_printf("[*] cmstp.exe present: %s\n", bCmstp ? "Yes" : "No");

    BOOL bCmstpClsid = HKLMKeyExists("SOFTWARE\\Classes\\CLSID\\{3E5FC7F9-9A51-4367-9063-A120244FBEC7}");
    internal_printf("[*] CMSTPLUA CLSID registered: %s\n", bCmstpClsid ? "Yes" : "No");

    BOOL bColorClsid = HKLMKeyExists("SOFTWARE\\Classes\\CLSID\\{D2E7025F-2709-432D-B726-2B1B337B9997}");
    internal_printf("[*] ColorDataProxy CLSID registered: %s\n", bColorClsid ? "Yes" : "No");

    if (env->dwBuild < 17134)
    {
        internal_printf("[-] NOT VIABLE: requires Windows 10 1803+ (build 17134+), current: %lu\n", env->dwBuild);
        return;
    }

    if (bCmstp && bCmstpClsid && bColorClsid)
        internal_printf("[+] VIABLE -> uac-bypass colordataproxy <remote_file>\n");
    else
        internal_printf("[-] NOT VIABLE: missing precondition(s)\n");
}

static void CheckEditionUpgrade(UAC_ENV *env)
{
    internal_printf("\n--- EditionUpgradeManager COM ---\n");
    internal_printf("[*] Technique: Abuse IEditionUpgradeManager COM + HKCU\\Environment\\windir\n");
    internal_printf("[*]   hijack to execute payload as elevated\n");

    if (!CanBypass(env))
    {
        internal_printf("[-] NOT VIABLE: requires medium-integrity local admin token\n");
        return;
    }

    BOOL bEnvKey = CanWriteHKCUKey("Environment");
    internal_printf("[*] HKCU\\Environment writable: %s\n", bEnvKey ? "Yes" : "No");

    BOOL bClsid = HKLMKeyExists("SOFTWARE\\Classes\\CLSID\\{17CCA47D-DAE5-4E4A-AC42-CC54E28F334A}");
    internal_printf("[*] EditionUpgradeManager CLSID registered: %s\n", bClsid ? "Yes" : "No");

    if (env->dwBuild < 17134)
    {
        internal_printf("[-] NOT VIABLE: requires Windows 10 1803+ (build 17134+), current: %lu\n", env->dwBuild);
        return;
    }

    if (bEnvKey && bClsid)
        internal_printf("[+] VIABLE -> uac-bypass editionupgrade <local_exe>\n");
    else
        internal_printf("[-] NOT VIABLE: missing precondition(s)\n");
}

/* ================================================================
   Entry point — dispatched by mode integer from Python
   ================================================================ */
#ifdef BOF
void go(char *args, int len)
{
    datap parser;
    int   mode = 0;

    BeaconDataParse(&parser, args, len);
    mode = BeaconDataInt(&parser);

    bofstart();

    UAC_ENV env;
    GatherEnvironment(&env);

    if (!env.bEnvValid)
    {
        internal_printf("[!] Failed to gather environment info\n");
        printoutput(TRUE);
        return;
    }

    if (mode == 0 || mode == 1)
        PrintEnvironment(&env);

    if (mode == 0 || mode == 2) CheckTrustedPath(&env);
    if (mode == 0 || mode == 3) CheckSilentCleanup(&env);
    if (mode == 0 || mode == 4) CheckSspiDatagram(&env);
    if (mode == 0 || mode == 5) CheckRegistryCommand(&env);
    if (mode == 0 || mode == 6) CheckElevatedCOM(&env);
    if (mode == 0 || mode == 7) CheckColorDataProxy(&env);
    if (mode == 0 || mode == 8) CheckEditionUpgrade(&env);

    if (mode == 0)
    {
        internal_printf("\n=== Summary ===\n");
        if (!CanBypass(&env))
        {
            if (env.bIsElevated)
                internal_printf("[*] Already elevated — no bypass needed\n");
            else if (!env.dwEnableLUA)
                internal_printf("[*] UAC is disabled — no bypass needed\n");
            else
                internal_printf("[-] Not a local admin — no bypass will work\n");
        }
        else
        {
            internal_printf("[*] Review [+] entries above for viable techniques\n");
            internal_printf("[*] Use 'uac-bypass <technique> ...' to execute\n");
        }
    }

    printoutput(TRUE);
}
#endif
