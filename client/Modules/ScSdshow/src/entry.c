#include <windows.h>
#include <winsvc.h>
#include <sddl.h>
#include "../../RemoteOps/CS-Remote-OPs-BOF/src/common/bofdefs.h"
#include "../../RemoteOps/CS-Remote-OPs-BOF/src/common/base.c"

#ifndef SDDL_REVISION_1
#define SDDL_REVISION_1 1
#endif

DECLSPEC_IMPORT SC_HANDLE WINAPI ADVAPI32$OpenSCManagerA(LPCSTR, LPCSTR, DWORD);
DECLSPEC_IMPORT SC_HANDLE WINAPI ADVAPI32$OpenServiceA(SC_HANDLE, LPCSTR, DWORD);
DECLSPEC_IMPORT BOOL      WINAPI ADVAPI32$CloseServiceHandle(SC_HANDLE);
DECLSPEC_IMPORT BOOL      WINAPI ADVAPI32$QueryServiceObjectSecurity(SC_HANDLE, SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, DWORD, LPDWORD);
DECLSPEC_IMPORT BOOL      WINAPI ADVAPI32$ConvertSecurityDescriptorToStringSecurityDescriptorA(PSECURITY_DESCRIPTOR, DWORD, SECURITY_INFORMATION, LPSTR*, PULONG);
DECLSPEC_IMPORT BOOL      WINAPI ADVAPI32$GetSecurityDescriptorOwner(PSECURITY_DESCRIPTOR, PSID*, LPBOOL);
DECLSPEC_IMPORT BOOL      WINAPI ADVAPI32$GetSecurityDescriptorGroup(PSECURITY_DESCRIPTOR, PSID*, LPBOOL);
DECLSPEC_IMPORT BOOL      WINAPI ADVAPI32$GetSecurityDescriptorDacl(PSECURITY_DESCRIPTOR, LPBOOL, PACL*, LPBOOL);
DECLSPEC_IMPORT BOOL      WINAPI ADVAPI32$GetAce(PACL, DWORD, LPVOID*);
DECLSPEC_IMPORT BOOL      WINAPI ADVAPI32$LookupAccountSidA(LPCSTR, PSID, LPSTR, LPDWORD, LPSTR, LPDWORD, PSID_NAME_USE);
DECLSPEC_IMPORT BOOL      WINAPI ADVAPI32$ConvertSidToStringSidA(PSID, LPSTR*);

DECLSPEC_IMPORT DWORD  WINAPI KERNEL32$GetLastError(void);
DECLSPEC_IMPORT HLOCAL WINAPI KERNEL32$LocalFree(HLOCAL);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$GetProcessHeap(void);
DECLSPEC_IMPORT LPVOID WINAPI KERNEL32$HeapAlloc(HANDLE, DWORD, SIZE_T);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$HeapFree(HANDLE, DWORD, LPVOID);

void *memcpy(void *dest, const void *src, size_t n) { return MSVCRT$memcpy(dest, src, n); }
void *memset(void *s, int c, size_t n)              { MSVCRT$memset(s, c, n); return s; }

/* Service-specific rights */
#define SVC_QUERY_CONFIG      0x0001
#define SVC_CHANGE_CONFIG     0x0002
#define SVC_QUERY_STATUS      0x0004
#define SVC_ENUMERATE_DEPS    0x0008
#define SVC_START             0x0010
#define SVC_STOP              0x0020
#define SVC_PAUSE_CONTINUE    0x0040
#define SVC_INTERROGATE       0x0080
#define SVC_USER_DEF_CTRL     0x0100

/* Standard rights */
#define ST_DELETE             0x00010000
#define ST_READ_CONTROL       0x00020000
#define ST_WRITE_DAC          0x00040000
#define ST_WRITE_OWNER        0x00080000
#define ST_SYNCHRONIZE        0x00100000

#define SVC_ALL_ACCESS        0x000F01FF

static void PrintSid(PSID pSid)
{
    char name[256]   = {0};
    char domain[256] = {0};
    DWORD nl = 256, dl = 256;
    SID_NAME_USE use;

    if (!pSid) { internal_printf("(null)"); return; }

    if (ADVAPI32$LookupAccountSidA(NULL, pSid, name, &nl, domain, &dl, &use))
    {
        if (domain[0]) internal_printf("%s\\%s", domain, name);
        else           internal_printf("%s", name);
    }
    else
    {
        LPSTR sidStr = NULL;
        if (ADVAPI32$ConvertSidToStringSidA(pSid, &sidStr))
        {
            internal_printf("%s", sidStr);
            KERNEL32$LocalFree(sidStr);
        }
        else
        {
            internal_printf("(unknown SID)");
        }
    }
}

static void PrintServiceRights(DWORD mask)
{
    int first = 1;

    if ((mask & SVC_ALL_ACCESS) == SVC_ALL_ACCESS &&
        (mask & (ST_DELETE|ST_READ_CONTROL|ST_WRITE_DAC|ST_WRITE_OWNER)) ==
        (ST_DELETE|ST_READ_CONTROL|ST_WRITE_DAC|ST_WRITE_OWNER))
    {
        internal_printf("Full Control");
        return;
    }

#define EMIT(bit, sddl, name)                                    \
    do {                                                         \
        if (mask & (bit)) {                                      \
            if (!first) internal_printf(", ");                   \
            internal_printf("%s (%s)", name, sddl); first = 0;   \
        }                                                        \
    } while (0)

    EMIT(SVC_QUERY_CONFIG,   "CC", "QueryConfig");
    EMIT(SVC_CHANGE_CONFIG,  "DC", "ChangeConfig");
    EMIT(SVC_QUERY_STATUS,   "LC", "QueryStatus");
    EMIT(SVC_ENUMERATE_DEPS, "SW", "EnumerateDependents");
    EMIT(SVC_START,          "RP", "Start");
    EMIT(SVC_STOP,           "WP", "Stop");
    EMIT(SVC_PAUSE_CONTINUE, "DT", "PauseContinue");
    EMIT(SVC_INTERROGATE,    "LO", "Interrogate");
    EMIT(SVC_USER_DEF_CTRL,  "CR", "UserDefinedControl");
    EMIT(ST_DELETE,          "SD", "Delete");
    EMIT(ST_READ_CONTROL,    "RC", "ReadControl");
    EMIT(ST_WRITE_DAC,       "WD", "WriteDac");
    EMIT(ST_WRITE_OWNER,     "WO", "WriteOwner");
    EMIT(ST_SYNCHRONIZE,     "SY", "Synchronize");
#undef EMIT

    if (first) internal_printf("Special (0x%08X)", mask);
}

static const char *AceTypeName(BYTE t)
{
    switch (t)
    {
        case ACCESS_ALLOWED_ACE_TYPE: return "Allow";
        case ACCESS_DENIED_ACE_TYPE:  return "Deny";
        case SYSTEM_AUDIT_ACE_TYPE:   return "Audit";
        case SYSTEM_ALARM_ACE_TYPE:   return "Alarm";
        default:                      return "Other";
    }
}

void go(char *args, int len)
{
    datap parser;
    char *svcName = NULL;
    int   svcNameLen = 0;
    SC_HANDLE hSCM = NULL, hSvc = NULL;
    PSECURITY_DESCRIPTOR pSD = NULL;
    DWORD needed = 0;
    SECURITY_INFORMATION sec =
        OWNER_SECURITY_INFORMATION |
        GROUP_SECURITY_INFORMATION |
        DACL_SECURITY_INFORMATION;
    LPSTR sddl = NULL;
    ULONG sddlLen = 0;
    PSID pOwner = NULL, pGroup = NULL;
    PACL pDacl = NULL;
    BOOL bOwnerDefaulted = FALSE, bGroupDefaulted = FALSE;
    BOOL bDaclPresent = FALSE, bDaclDefaulted = FALSE;
    DWORD i;

    bofstart();

    BeaconDataParse(&parser, args, len);
    svcName = BeaconDataExtract(&parser, &svcNameLen);
    if (!svcName || svcNameLen <= 1)
    {
        internal_printf("[-] Missing service name\n");
        printoutput(TRUE);
        return;
    }

    hSCM = ADVAPI32$OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT);
    if (!hSCM)
    {
        internal_printf("[-] OpenSCManager failed (error %lu)\n", KERNEL32$GetLastError());
        printoutput(TRUE);
        return;
    }

    hSvc = ADVAPI32$OpenServiceA(hSCM, svcName, READ_CONTROL);
    if (!hSvc)
    {
        internal_printf("[-] OpenService('%s') failed (error %lu)\n",
                        svcName, KERNEL32$GetLastError());
        ADVAPI32$CloseServiceHandle(hSCM);
        printoutput(TRUE);
        return;
    }

    ADVAPI32$QueryServiceObjectSecurity(hSvc, sec, NULL, 0, &needed);
    if (needed == 0)
    {
        internal_printf("[-] QueryServiceObjectSecurity size probe failed (error %lu)\n",
                        KERNEL32$GetLastError());
        goto cleanup;
    }
    pSD = KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, needed);
    if (!pSD)
    {
        internal_printf("[-] HeapAlloc for SD failed\n");
        goto cleanup;
    }
    if (!ADVAPI32$QueryServiceObjectSecurity(hSvc, sec, pSD, needed, &needed))
    {
        internal_printf("[-] QueryServiceObjectSecurity failed (error %lu)\n",
                        KERNEL32$GetLastError());
        goto cleanup;
    }

    internal_printf("=== Security Descriptor for service: %s ===\n\n", svcName);

    /* Raw SDDL first — matches `sc.exe sdshow` output verbatim */
    if (ADVAPI32$ConvertSecurityDescriptorToStringSecurityDescriptorA(
            pSD, SDDL_REVISION_1, sec, &sddl, &sddlLen))
    {
        internal_printf("[Raw SDDL]\n%s\n\n", sddl);
        KERNEL32$LocalFree(sddl);
        sddl = NULL;
    }
    else
    {
        internal_printf("[!] SDDL conversion failed (error %lu)\n\n",
                        KERNEL32$GetLastError());
    }

    /* Friendly parsed view */
    internal_printf("[Friendly]\n");

    if (ADVAPI32$GetSecurityDescriptorOwner(pSD, &pOwner, &bOwnerDefaulted) && pOwner)
    {
        internal_printf("Owner: ");
        PrintSid(pOwner);
        internal_printf("\n");
    }
    if (ADVAPI32$GetSecurityDescriptorGroup(pSD, &pGroup, &bGroupDefaulted) && pGroup)
    {
        internal_printf("Group: ");
        PrintSid(pGroup);
        internal_printf("\n");
    }

    if (ADVAPI32$GetSecurityDescriptorDacl(pSD, &bDaclPresent, &pDacl, &bDaclDefaulted))
    {
        internal_printf("\nDACL:\n");
        if (bDaclPresent && pDacl == NULL)
        {
            internal_printf("  (NULL DACL — grants everyone all access)\n");
        }
        else if (bDaclPresent && pDacl)
        {
            for (i = 0; i < pDacl->AceCount; i++)
            {
                ACCESS_ALLOWED_ACE *pAce = NULL;
                if (!ADVAPI32$GetAce(pDacl, i, (LPVOID*)&pAce))
                    continue;

                internal_printf("  [%s] ", AceTypeName(pAce->Header.AceType));
                PrintSid((PSID)&pAce->SidStart);
                internal_printf("\n");
                internal_printf("    Rights: ");
                PrintServiceRights(pAce->Mask);
                internal_printf("\n\n");
            }
        }
        else
        {
            internal_printf("  (not present)\n");
        }
    }

cleanup:
    if (pSD)  KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, pSD);
    if (hSvc) ADVAPI32$CloseServiceHandle(hSvc);
    if (hSCM) ADVAPI32$CloseServiceHandle(hSCM);
    printoutput(TRUE);
}
