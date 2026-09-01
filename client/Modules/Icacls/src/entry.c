#include <windows.h>
#include <aclapi.h>
#include <sddl.h>
#include <stdio.h>

#ifdef BOF

#define intAlloc(size) KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, size)
#define intFree(addr) KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, addr)

WINBASEAPI void * WINAPI KERNEL32$HeapAlloc(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes);
WINBASEAPI HANDLE WINAPI KERNEL32$GetProcessHeap(void);
WINBASEAPI BOOL WINAPI KERNEL32$HeapFree(HANDLE, DWORD, PVOID);
WINBASEAPI HLOCAL WINAPI KERNEL32$LocalFree(HLOCAL);
WINBASEAPI DWORD WINAPI KERNEL32$GetFileAttributesA(LPCSTR lpFileName);

DECLSPEC_IMPORT void *  MSVCRT$calloc(size_t, size_t);
DECLSPEC_IMPORT void    MSVCRT$free(void *);
DECLSPEC_IMPORT int     MSVCRT$vsnprintf(char *, size_t, const char *, va_list);
DECLSPEC_IMPORT void *  MSVCRT$memset(void *, int, size_t);
DECLSPEC_IMPORT void *  MSVCRT$memcpy(void *, const void *, size_t);

DECLSPEC_IMPORT DWORD WINAPI ADVAPI32$GetNamedSecurityInfoA(LPCSTR, SE_OBJECT_TYPE, SECURITY_INFORMATION, PSID*, PSID*, PACL*, PACL*, PSECURITY_DESCRIPTOR*);
DECLSPEC_IMPORT BOOL  WINAPI ADVAPI32$LookupAccountSidA(LPCSTR, PSID, LPSTR, LPDWORD, LPSTR, LPDWORD, PSID_NAME_USE);
DECLSPEC_IMPORT BOOL  WINAPI ADVAPI32$ConvertSidToStringSidA(PSID, LPSTR*);
DECLSPEC_IMPORT BOOL  WINAPI ADVAPI32$GetAce(PACL, DWORD, LPVOID*);
DECLSPEC_IMPORT BOOL  WINAPI ADVAPI32$IsValidAcl(PACL);

/* beacon.h inline */
typedef struct { char *original; char *buffer; int length; int size; } datap;
DECLSPEC_IMPORT void   BeaconDataParse(datap *, char *, int);
DECLSPEC_IMPORT char * BeaconDataExtract(datap *, int *);
DECLSPEC_IMPORT void   BeaconOutput(int, char *, int);
DECLSPEC_IMPORT void   BeaconPrintf(int, const char *, ...);
#define CALLBACK_OUTPUT 0x0
#define CALLBACK_ERROR  0x0d

void *__cdecl memcpy(void *dest, const void *src, size_t n) { return MSVCRT$memcpy(dest, src, n); }
void *__cdecl memset(void *dest, int c, size_t n) { MSVCRT$memset(dest, c, n); return dest; }

#ifndef bufsize
#define bufsize 16384
#endif

static char * output = NULL;
static WORD currentoutsize = 0;

int bofstart(void)
{
    output = (char*)MSVCRT$calloc(bufsize, 1);
    currentoutsize = 0;
    return 1;
}

void internal_printf(const char* format, ...)
{
    char * intBuffer = NULL;
    int buffersize = 0;
    va_list args;
    va_start(args, format);
    buffersize = MSVCRT$vsnprintf(NULL, 0, format, args);
    va_end(args);
    if (buffersize <= 0) return;
    intBuffer = (char*)intAlloc(buffersize + 1);
    va_start(args, format);
    MSVCRT$vsnprintf(intBuffer, buffersize + 1, format, args);
    va_end(args);
    if (buffersize + currentoutsize < bufsize)
    {
        memcpy(output + currentoutsize, intBuffer, buffersize);
        currentoutsize += buffersize;
    }
    else
    {
        BeaconOutput(CALLBACK_OUTPUT, output, currentoutsize);
        currentoutsize = 0;
        memset(output, 0, bufsize);
        int remain = buffersize;
        char *src = intBuffer;
        while (remain > 0)
        {
            int chunk = remain < bufsize ? remain : bufsize;
            memcpy(output, src, chunk);
            currentoutsize = chunk;
            if (currentoutsize == bufsize)
            {
                BeaconOutput(CALLBACK_OUTPUT, output, currentoutsize);
                currentoutsize = 0;
                memset(output, 0, bufsize);
            }
            src += chunk;
            remain -= chunk;
        }
    }
    intFree(intBuffer);
}

void printoutput(BOOL done)
{
    if (currentoutsize > 0)
        BeaconOutput(CALLBACK_OUTPUT, output, currentoutsize);
    currentoutsize = 0;
    if (output) memset(output, 0, bufsize);
    if (done && output) { MSVCRT$free(output); output = NULL; }
}

static void PrintSid(PSID pSid)
{
    if (!pSid) { internal_printf("(null)"); return; }
    char name[256] = {0};
    char domain[256] = {0};
    DWORD nameLen = 256, domainLen = 256;
    SID_NAME_USE use;
    if (ADVAPI32$LookupAccountSidA(NULL, pSid, name, &nameLen, domain, &domainLen, &use))
    {
        if (domain[0])
            internal_printf("%s\\%s", domain, name);
        else
            internal_printf("%s", name);
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
            internal_printf("(unknown SID)");
    }
}

static void PrintPermissions(DWORD mask)
{
    if ((mask & 0x1F01FF) == 0x1F01FF)       { internal_printf("F  (Full Control)"); return; }
    if ((mask & 0x1301BF) == 0x1301BF)       { internal_printf("M  (Modify)"); return; }
    if ((mask & 0x1200A9) == 0x1200A9)       { internal_printf("RX (Read & Execute)"); return; }

    int first = 1;
    if (mask & 0x120089) { internal_printf("R (Read)"); first = 0; }
    if (mask & 0x120116) { if (!first) internal_printf(", "); internal_printf("W (Write)"); first = 0; }
    if (mask & 0x10000000) { if (!first) internal_printf(", "); internal_printf("GA (Generic All)"); first = 0; }
    if (mask & 0x20000000) { if (!first) internal_printf(", "); internal_printf("GX (Generic Execute)"); first = 0; }
    if (mask & 0x40000000) { if (!first) internal_printf(", "); internal_printf("GW (Generic Write)"); first = 0; }
    if (mask & 0x80000000) { if (!first) internal_printf(", "); internal_printf("GR (Generic Read)"); first = 0; }
    if (first) internal_printf("Special (0x%08X)", mask);
}

static void PrintInheritance(BYTE flags, BOOL isDirectory)
{
    BOOL ci = flags & CONTAINER_INHERIT_ACE;
    BOOL oi = flags & OBJECT_INHERIT_ACE;
    BOOL io = flags & INHERIT_ONLY_ACE;

    if (!isDirectory)
    {
        /* CI/OI/IO describe propagation to child objects; files have none.
           If any of those flags happen to be set on a file ACE (rare), report
           the raw flags rather than the misleading folder-oriented text. */
        if (!ci && !oi && !io) { internal_printf("This file"); return; }
        internal_printf("This file (unexpected flags=0x%02X)", flags);
        return;
    }

    if (!ci && !oi && !io)      internal_printf("This folder only");
    else if (ci && oi && !io)   internal_printf("This folder, subfolders, and files");
    else if (ci && !oi && !io)  internal_printf("This folder and subfolders");
    else if (!ci && oi && !io)  internal_printf("This folder and files");
    else if (ci && oi && io)    internal_printf("Subfolders and files only");
    else if (ci && !oi && io)   internal_printf("Subfolders only");
    else if (!ci && oi && io)   internal_printf("Files only");
    else                        internal_printf("Special (flags=0x%02X)", flags);
}

VOID go(IN PCHAR Buffer, IN ULONG Length)
{
    datap parser;
    int pathLen = 0;
    char *path = NULL;
    PSID pOwner = NULL;
    PSID pGroup = NULL;
    PACL pDacl = NULL;
    PSECURITY_DESCRIPTOR pSD = NULL;

    BeaconDataParse(&parser, Buffer, Length);
    path = BeaconDataExtract(&parser, &pathLen);
    if (!path || pathLen <= 0)
    {
        BeaconPrintf(CALLBACK_ERROR, "No path argument provided");
        return;
    }

    if (!bofstart()) return;

    DWORD attrs = KERNEL32$GetFileAttributesA(path);
    BOOL isDirectory = (attrs != INVALID_FILE_ATTRIBUTES) &&
                       (attrs & FILE_ATTRIBUTE_DIRECTORY);

    DWORD ret = ADVAPI32$GetNamedSecurityInfoA(
        path, SE_FILE_OBJECT,
        OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
        &pOwner, &pGroup, &pDacl, NULL, &pSD
    );

    if (ret != ERROR_SUCCESS)
    {
        internal_printf("GetNamedSecurityInfo failed for '%s': error %lu\n", path, ret);
        printoutput(TRUE);
        return;
    }

    internal_printf("=== ACL for: %s ===\n\n", path);
    internal_printf("Owner: ");
    PrintSid(pOwner);
    internal_printf("\n\n");

    if (!pDacl || !ADVAPI32$IsValidAcl(pDacl))
    {
        internal_printf("(No DACL or invalid ACL)\n");
        printoutput(TRUE);
        if (pSD) KERNEL32$LocalFree(pSD);
        return;
    }

    ACL_SIZE_INFORMATION aclInfo;
    memset(&aclInfo, 0, sizeof(aclInfo));
    aclInfo.AceCount = pDacl->AceCount;

    for (DWORD i = 0; i < pDacl->AceCount; i++)
    {
        ACCESS_ALLOWED_ACE *pAce = NULL;
        if (!ADVAPI32$GetAce(pDacl, i, (LPVOID*)&pAce))
            continue;

        const char *aceType = "Unknown";
        if (pAce->Header.AceType == ACCESS_ALLOWED_ACE_TYPE)
            aceType = "Allow";
        else if (pAce->Header.AceType == ACCESS_DENIED_ACE_TYPE)
            aceType = "Deny";

        PSID pAceSid = (PSID)&pAce->SidStart;

        internal_printf("  [%s] ", aceType);
        PrintSid(pAceSid);
        internal_printf("\n");
        internal_printf("    Permissions: ");
        PrintPermissions(pAce->Mask);
        internal_printf("\n");
        internal_printf("    Inherited:   %s\n", (pAce->Header.AceFlags & INHERITED_ACE) ? "Yes" : "No");
        internal_printf("    Applies to:  ");
        PrintInheritance(pAce->Header.AceFlags, isDirectory);
        internal_printf("\n\n");
    }

    printoutput(TRUE);
    if (pSD) KERNEL32$LocalFree(pSD);
}

#endif /* BOF */
