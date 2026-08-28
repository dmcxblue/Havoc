#ifndef BOFDEFS_H
#define BOFDEFS_H

#include <windows.h>
#include <winternl.h>

/* ---- DFR (Dynamic Function Resolution) ---- */

/* kernel32 */
DECLSPEC_IMPORT HMODULE  WINAPI KERNEL32$LoadLibraryA(LPCSTR);
DECLSPEC_IMPORT FARPROC  WINAPI KERNEL32$GetProcAddress(HMODULE, LPCSTR);
DECLSPEC_IMPORT BOOL     WINAPI KERNEL32$FreeLibrary(HMODULE);
DECLSPEC_IMPORT HANDLE   WINAPI KERNEL32$GetCurrentProcess(VOID);
DECLSPEC_IMPORT HANDLE   WINAPI KERNEL32$OpenProcess(DWORD, BOOL, DWORD);
DECLSPEC_IMPORT BOOL     WINAPI KERNEL32$CloseHandle(HANDLE);
DECLSPEC_IMPORT DWORD    WINAPI KERNEL32$GetLastError(VOID);
DECLSPEC_IMPORT VOID     WINAPI KERNEL32$SetLastError(DWORD);
DECLSPEC_IMPORT DWORD    WINAPI KERNEL32$GetFileAttributesA(LPCSTR);
DECLSPEC_IMPORT HANDLE   WINAPI KERNEL32$FindFirstFileA(LPCSTR, LPWIN32_FIND_DATAA);
DECLSPEC_IMPORT BOOL     WINAPI KERNEL32$FindNextFileA(HANDLE, LPWIN32_FIND_DATAA);
DECLSPEC_IMPORT BOOL     WINAPI KERNEL32$FindClose(HANDLE);
DECLSPEC_IMPORT DWORD    WINAPI KERNEL32$GetEnvironmentVariableA(LPCSTR, LPSTR, DWORD);
DECLSPEC_IMPORT DWORD    WINAPI KERNEL32$ExpandEnvironmentStringsA(LPCSTR, LPSTR, DWORD);
DECLSPEC_IMPORT BOOL     WINAPI KERNEL32$GetTokenInformation(HANDLE, TOKEN_INFORMATION_CLASS, LPVOID, DWORD, PDWORD);
DECLSPEC_IMPORT BOOL     WINAPI KERNEL32$OpenProcessToken(HANDLE, DWORD, PHANDLE);
DECLSPEC_IMPORT HANDLE   WINAPI KERNEL32$CreateFileA(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
DECLSPEC_IMPORT DWORD    WINAPI KERNEL32$GetFileSize(HANDLE, LPDWORD);
DECLSPEC_IMPORT BOOL     WINAPI KERNEL32$ReadFile(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
DECLSPEC_IMPORT LPVOID   WINAPI KERNEL32$HeapAlloc(HANDLE, DWORD, SIZE_T);
DECLSPEC_IMPORT BOOL     WINAPI KERNEL32$HeapFree(HANDLE, DWORD, LPVOID);
DECLSPEC_IMPORT HANDLE   WINAPI KERNEL32$GetProcessHeap(VOID);

/* advapi32 */
DECLSPEC_IMPORT LONG     WINAPI ADVAPI32$RegOpenKeyExA(HKEY, LPCSTR, DWORD, REGSAM, PHKEY);
DECLSPEC_IMPORT LONG     WINAPI ADVAPI32$RegQueryValueExA(HKEY, LPCSTR, LPDWORD, LPDWORD, LPBYTE, LPDWORD);
DECLSPEC_IMPORT LONG     WINAPI ADVAPI32$RegCloseKey(HKEY);
DECLSPEC_IMPORT LONG     WINAPI ADVAPI32$RegEnumKeyExA(HKEY, DWORD, LPSTR, LPDWORD, LPDWORD, LPSTR, LPDWORD, PFILETIME);
DECLSPEC_IMPORT LONG     WINAPI ADVAPI32$RegEnumValueA(HKEY, DWORD, LPSTR, LPDWORD, LPDWORD, LPDWORD, LPBYTE, LPDWORD);
DECLSPEC_IMPORT SC_HANDLE WINAPI ADVAPI32$OpenSCManagerA(LPCSTR, LPCSTR, DWORD);
DECLSPEC_IMPORT SC_HANDLE WINAPI ADVAPI32$OpenServiceA(SC_HANDLE, LPCSTR, DWORD);
DECLSPEC_IMPORT BOOL     WINAPI ADVAPI32$QueryServiceConfigA(SC_HANDLE, LPQUERY_SERVICE_CONFIGA, DWORD, LPDWORD);
DECLSPEC_IMPORT BOOL     WINAPI ADVAPI32$EnumServicesStatusA(SC_HANDLE, DWORD, DWORD, LPENUM_SERVICE_STATUSA, DWORD, LPDWORD, LPDWORD, LPDWORD);
DECLSPEC_IMPORT BOOL     WINAPI ADVAPI32$CloseServiceHandle(SC_HANDLE);
DECLSPEC_IMPORT BOOL     WINAPI ADVAPI32$QueryServiceObjectSecurity(SC_HANDLE, SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, DWORD, LPDWORD);
DECLSPEC_IMPORT BOOL     WINAPI ADVAPI32$OpenProcessToken(HANDLE, DWORD, PHANDLE);
DECLSPEC_IMPORT BOOL     WINAPI ADVAPI32$GetTokenInformation(HANDLE, TOKEN_INFORMATION_CLASS, LPVOID, DWORD, PDWORD);
DECLSPEC_IMPORT BOOL     WINAPI ADVAPI32$LookupPrivilegeNameA(LPCSTR, PLUID, LPSTR, LPDWORD);
DECLSPEC_IMPORT BOOL     WINAPI ADVAPI32$GetSecurityDescriptorDacl(PSECURITY_DESCRIPTOR, LPBOOL, PACL, LPBOOL);
DECLSPEC_IMPORT BOOL     WINAPI ADVAPI32$GetAce(PACL, DWORD, LPVOID*);
DECLSPEC_IMPORT BOOL     WINAPI ADVAPI32$LookupAccountSidA(LPCSTR, PSID, LPSTR, LPDWORD, LPSTR, LPDWORD, PSID_NAME_USE);
DECLSPEC_IMPORT BOOL     WINAPI ADVAPI32$ConvertSidToStringSidA(PSID, LPSTR*);

/* shell32 */
DECLSPEC_IMPORT HRESULT  WINAPI SHELL32$SHGetFolderPathA(HWND, int, HANDLE, DWORD, LPSTR);

/* shlwapi */
DECLSPEC_IMPORT BOOL     WINAPI SHLWAPI$PathFileExistsA(LPCSTR);

/* msvcrt */
DECLSPEC_IMPORT void*    __cdecl MSVCRT$memcpy(void*, const void*, size_t);
DECLSPEC_IMPORT void*    __cdecl MSVCRT$memset(void*, int, size_t);
DECLSPEC_IMPORT int      __cdecl MSVCRT$strcmp(const char*, const char*);
DECLSPEC_IMPORT int      __cdecl MSVCRT$_stricmp(const char*, const char*);
DECLSPEC_IMPORT size_t   __cdecl MSVCRT$strlen(const char*);
DECLSPEC_IMPORT char*    __cdecl MSVCRT$strcpy(char*, const char*);
DECLSPEC_IMPORT char*    __cdecl MSVCRT$strcat(char*, const char*);
DECLSPEC_IMPORT char*    __cdecl MSVCRT$strstr(const char*, const char*);
DECLSPEC_IMPORT char*    __cdecl MSVCRT$strchr(const char*, int);
DECLSPEC_IMPORT int      __cdecl MSVCRT$sprintf(char*, const char*, ...);
DECLSPEC_IMPORT int      __cdecl MSVCRT$_snprintf(char*, size_t, const char*, ...);
DECLSPEC_IMPORT int      __cdecl MSVCRT$toupper(int);
DECLSPEC_IMPORT int      __cdecl MSVCRT$tolower(int);
DECLSPEC_IMPORT char*    __cdecl MSVCRT$strtok(char*, const char*);
DECLSPEC_IMPORT void*    __cdecl MSVCRT$calloc(size_t, size_t);
DECLSPEC_IMPORT void     __cdecl MSVCRT$free(void*);
DECLSPEC_IMPORT int      __cdecl MSVCRT$_vsnprintf(char*, size_t, const char*, va_list);

/* ---- Beacon Output API ---- */

#ifdef BOF

#define CALLBACK_OUTPUT      0x0
#define CALLBACK_OUTPUT_OEM  0x1e
#define CALLBACK_ERROR       0x0d
#define CALLBACK_OUTPUT_UTF8 0x20

typedef struct {
    char*  original;
    char*  buffer;
    int    length;
    int    size;
} formatp;

typedef struct {
    char* original;
    char* buffer;
    int   length;
    int   size;
} datap;

DECLSPEC_IMPORT void    BeaconDataParse(datap*, char*, int);
DECLSPEC_IMPORT char*   BeaconDataExtract(datap*, int*);
DECLSPEC_IMPORT int     BeaconDataInt(datap*);
DECLSPEC_IMPORT short   BeaconDataShort(datap*);
DECLSPEC_IMPORT int     BeaconDataLength(datap*);

DECLSPEC_IMPORT void    BeaconFormatAlloc(formatp*, int);
DECLSPEC_IMPORT void    BeaconFormatReset(formatp*);
DECLSPEC_IMPORT void    BeaconFormatFree(formatp*);
DECLSPEC_IMPORT void    BeaconFormatAppend(formatp*, char*, int);
DECLSPEC_IMPORT void    BeaconFormatPrintf(formatp*, char*, ...);
DECLSPEC_IMPORT char*   BeaconFormatToString(formatp*, int*);
DECLSPEC_IMPORT void    BeaconFormatInt(formatp*, int);

DECLSPEC_IMPORT void    BeaconPrintf(int, char*, ...);
DECLSPEC_IMPORT void    BeaconOutput(int, char*, int);

/* ---- bofstart / internal_printf / printoutput ---- */
/* Heap-allocated buffer with auto-flush when full */

#define intAlloc(sz)  KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, (sz))
#define intFree(p)    KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, (p))

#ifndef BUFFER_SIZE
#define BUFFER_SIZE 8192
#endif

static char  *_bof_output  = NULL;
static int    _bof_offset  = 0;

static int bofstart(void)
{
    _bof_output = (char *)MSVCRT$calloc(BUFFER_SIZE, 1);
    _bof_offset = 0;
    return (_bof_output != NULL);
}

static void internal_printf(const char *fmt, ...)
{
    if (!_bof_output) return;
    va_list args;
    va_start(args, fmt);
    int need = MSVCRT$_vsnprintf(NULL, 0, fmt, args);
    va_end(args);
    if (need <= 0) return;

    char *tmp = (char *)intAlloc(need + 1);
    if (!tmp) return;
    va_start(args, fmt);
    MSVCRT$_vsnprintf(tmp, need + 1, fmt, args);
    va_end(args);

    if (need + _bof_offset < BUFFER_SIZE) {
        MSVCRT$memcpy(_bof_output + _bof_offset, tmp, need);
        _bof_offset += need;
    } else {
        if (_bof_offset > 0) {
            BeaconOutput(CALLBACK_OUTPUT, _bof_output, _bof_offset);
            _bof_offset = 0;
            MSVCRT$memset(_bof_output, 0, BUFFER_SIZE);
        }
        if (need < BUFFER_SIZE) {
            MSVCRT$memcpy(_bof_output, tmp, need);
            _bof_offset = need;
        } else {
            BeaconOutput(CALLBACK_OUTPUT, tmp, need);
        }
    }
    intFree(tmp);
}

static void printoutput(int done)
{
    if (_bof_output && _bof_offset > 0)
        BeaconOutput(CALLBACK_OUTPUT, _bof_output, _bof_offset);
    _bof_offset = 0;
    if (done && _bof_output) {
        MSVCRT$free(_bof_output);
        _bof_output = NULL;
    }
}

#define bofstop() printoutput(1)

#endif /* BOF */

#endif /* BOFDEFS_H */
