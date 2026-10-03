/* k32_shim.c - define bare-named wrappers for the kernel32 functions that
 * sqlite3's os_win.c references BY ADDRESS (its aSyscall[] fault-injection
 * table) plus a few it calls directly without dllimport.
 *
 * Havoc's CoffeeLdr only resolves imports of the form __imp_LIB$FUNC (or a
 * tiny built-in table); bare extern function symbols fail to load.  Taking the
 * address of a dllimport'd function in mingw yields a bare `Func` reference
 * (not __imp_Func), which is exactly what sqlite3 does.  This file turns those
 * bare references into *internal* symbols by defining a `Func` wrapper for each
 * one; each wrapper resolves the real kernel32 export at runtime via
 * GetProcAddress (see k32_resolve in crt_shim.c).
 *
 * Compiled WITHOUT the DFR header (bare names stay bare, matching sqlite3.o),
 * and with DECLSPEC_IMPORT emptied so windows.h declares the Win32 prototypes
 * as plain functions we are allowed to define.
 */
#define DECLSPEC_IMPORT              /* disable dllimport on windows.h decls */
#include <windows.h>

extern void *k32_resolve(const char *name);

#define DEF(ret, name, sig, args)                                       \
    ret WINAPI name sig {                                               \
        typedef ret (WINAPI *fn_t) sig;                                 \
        static fn_t fn_;                                                \
        if (!fn_) fn_ = (fn_t)k32_resolve(#name);                       \
        return fn_ args;                                                \
    }

DEF(BOOL,   AreFileApisANSI, (VOID), ())
DEF(BOOL,   CloseHandle, (HANDLE hObject), (hObject))
DEF(HANDLE, CreateFileA, (LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile),
    (lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile))
DEF(HANDLE, CreateFileMappingW, (HANDLE hFile, LPSECURITY_ATTRIBUTES lpAttributes, DWORD flProtect, DWORD dwMaximumSizeHigh, DWORD dwMaximumSizeLow, LPCWSTR lpName),
    (hFile, lpAttributes, flProtect, dwMaximumSizeHigh, dwMaximumSizeLow, lpName))
DEF(HANDLE, CreateFileW, (LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile),
    (lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile))
DEF(HANDLE, CreateMutexW, (LPSECURITY_ATTRIBUTES lpMutexAttributes, BOOL bInitialOwner, LPCWSTR lpName),
    (lpMutexAttributes, bInitialOwner, lpName))
DEF(BOOL,   DeleteFileA, (LPCSTR lpFileName), (lpFileName))
DEF(BOOL,   DeleteFileW, (LPCWSTR lpFileName), (lpFileName))
DEF(BOOL,   FlushFileBuffers, (HANDLE hFile), (hFile))
DEF(BOOL,   FlushViewOfFile, (LPCVOID lpBaseAddress, SIZE_T dwNumberOfBytesToFlush), (lpBaseAddress, dwNumberOfBytesToFlush))
DEF(DWORD,  FormatMessageA, (DWORD dwFlags, LPCVOID lpSource, DWORD dwMessageId, DWORD dwLanguageId, LPSTR lpBuffer, DWORD nSize, va_list *Arguments),
    (dwFlags, lpSource, dwMessageId, dwLanguageId, lpBuffer, nSize, Arguments))
DEF(DWORD,  FormatMessageW, (DWORD dwFlags, LPCVOID lpSource, DWORD dwMessageId, DWORD dwLanguageId, LPWSTR lpBuffer, DWORD nSize, va_list *Arguments),
    (dwFlags, lpSource, dwMessageId, dwLanguageId, lpBuffer, nSize, Arguments))
DEF(DWORD,  GetCurrentProcessId, (VOID), ())
DEF(BOOL,   GetDiskFreeSpaceA, (LPCSTR lpRootPathName, LPDWORD lpSectorsPerCluster, LPDWORD lpBytesPerSector, LPDWORD lpNumberOfFreeClusters, LPDWORD lpTotalNumberOfClusters),
    (lpRootPathName, lpSectorsPerCluster, lpBytesPerSector, lpNumberOfFreeClusters, lpTotalNumberOfClusters))
DEF(BOOL,   GetDiskFreeSpaceW, (LPCWSTR lpRootPathName, LPDWORD lpSectorsPerCluster, LPDWORD lpBytesPerSector, LPDWORD lpNumberOfFreeClusters, LPDWORD lpTotalNumberOfClusters),
    (lpRootPathName, lpSectorsPerCluster, lpBytesPerSector, lpNumberOfFreeClusters, lpTotalNumberOfClusters))
DEF(DWORD,  GetFileAttributesA, (LPCSTR lpFileName), (lpFileName))
DEF(DWORD,  GetFileAttributesW, (LPCWSTR lpFileName), (lpFileName))
DEF(BOOL,   GetFileAttributesExW, (LPCWSTR lpFileName, GET_FILEEX_INFO_LEVELS fInfoLevelId, LPVOID lpFileInformation),
    (lpFileName, fInfoLevelId, lpFileInformation))
DEF(DWORD,  GetFileSize, (HANDLE hFile, LPDWORD lpFileSizeHigh), (hFile, lpFileSizeHigh))
DEF(DWORD,  GetFullPathNameA, (LPCSTR lpFileName, DWORD nBufferLength, LPSTR lpBuffer, LPSTR *lpFilePart),
    (lpFileName, nBufferLength, lpBuffer, lpFilePart))
DEF(DWORD,  GetFullPathNameW, (LPCWSTR lpFileName, DWORD nBufferLength, LPWSTR lpBuffer, LPWSTR *lpFilePart),
    (lpFileName, nBufferLength, lpBuffer, lpFilePart))
DEF(DWORD,  GetLastError, (VOID), ())
DEF(HMODULE, GetModuleHandleW, (LPCWSTR lpModuleName), (lpModuleName))
DEF(HANDLE, GetProcessHeap, (VOID), ())
DEF(VOID,   GetSystemInfo, (LPSYSTEM_INFO lpSystemInfo), (lpSystemInfo))
DEF(VOID,   GetSystemTime, (LPSYSTEMTIME lpSystemTime), (lpSystemTime))
DEF(VOID,   GetSystemTimeAsFileTime, (LPFILETIME lpSystemTimeAsFileTime), (lpSystemTimeAsFileTime))
DEF(DWORD,  GetTempPathA, (DWORD nBufferLength, LPSTR lpBuffer), (nBufferLength, lpBuffer))
DEF(DWORD,  GetTempPathW, (DWORD nBufferLength, LPWSTR lpBuffer), (nBufferLength, lpBuffer))
DEF(DWORD,  GetTickCount, (VOID), ())
DEF(LPVOID, HeapAlloc, (HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes), (hHeap, dwFlags, dwBytes))
DEF(SIZE_T, HeapCompact, (HANDLE hHeap, DWORD dwFlags), (hHeap, dwFlags))
DEF(HANDLE, HeapCreate, (DWORD flOptions, SIZE_T dwInitialSize, SIZE_T dwMaximumSize), (flOptions, dwInitialSize, dwMaximumSize))
DEF(BOOL,   HeapDestroy, (HANDLE hHeap), (hHeap))
DEF(BOOL,   HeapFree, (HANDLE hHeap, DWORD dwFlags, LPVOID lpMem), (hHeap, dwFlags, lpMem))
DEF(LPVOID, HeapReAlloc, (HANDLE hHeap, DWORD dwFlags, LPVOID lpMem, SIZE_T dwBytes), (hHeap, dwFlags, lpMem, dwBytes))
DEF(SIZE_T, HeapSize, (HANDLE hHeap, DWORD dwFlags, LPCVOID lpMem), (hHeap, dwFlags, lpMem))
DEF(BOOL,   HeapValidate, (HANDLE hHeap, DWORD dwFlags, LPCVOID lpMem), (hHeap, dwFlags, lpMem))
DEF(HLOCAL, LocalFree, (HLOCAL hMem), (hMem))
DEF(BOOL,   LockFile, (HANDLE hFile, DWORD dwFileOffsetLow, DWORD dwFileOffsetHigh, DWORD nNumberOfBytesToLockLow, DWORD nNumberOfBytesToLockHigh),
    (hFile, dwFileOffsetLow, dwFileOffsetHigh, nNumberOfBytesToLockLow, nNumberOfBytesToLockHigh))
DEF(BOOL,   LockFileEx, (HANDLE hFile, DWORD dwFlags, DWORD dwReserved, DWORD nNumberOfBytesToLockLow, DWORD nNumberOfBytesToLockHigh, LPOVERLAPPED lpOverlapped),
    (hFile, dwFlags, dwReserved, nNumberOfBytesToLockLow, nNumberOfBytesToLockHigh, lpOverlapped))
DEF(LPVOID, MapViewOfFile, (HANDLE hFileMappingObject, DWORD dwDesiredAccess, DWORD dwFileOffsetHigh, DWORD dwFileOffsetLow, SIZE_T dwNumberOfBytesToMap),
    (hFileMappingObject, dwDesiredAccess, dwFileOffsetHigh, dwFileOffsetLow, dwNumberOfBytesToMap))
DEF(int,    MultiByteToWideChar, (UINT CodePage, DWORD dwFlags, LPCSTR lpMultiByteStr, int cbMultiByte, LPWSTR lpWideCharStr, int cchWideChar),
    (CodePage, dwFlags, lpMultiByteStr, cbMultiByte, lpWideCharStr, cchWideChar))
DEF(VOID,   OutputDebugStringA, (LPCSTR lpOutputString), (lpOutputString))
DEF(VOID,   OutputDebugStringW, (LPCWSTR lpOutputString), (lpOutputString))
DEF(BOOL,   QueryPerformanceCounter, (LARGE_INTEGER *lpPerformanceCount), (lpPerformanceCount))
DEF(BOOL,   ReadFile, (HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped),
    (hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, lpOverlapped))
DEF(BOOL,   SetEndOfFile, (HANDLE hFile), (hFile))
DEF(DWORD,  SetFilePointer, (HANDLE hFile, LONG lDistanceToMove, PLONG lpDistanceToMoveHigh, DWORD dwMoveMethod),
    (hFile, lDistanceToMove, lpDistanceToMoveHigh, dwMoveMethod))
DEF(VOID,   Sleep, (DWORD dwMilliseconds), (dwMilliseconds))
DEF(BOOL,   SystemTimeToFileTime, (const SYSTEMTIME *lpSystemTime, LPFILETIME lpFileTime), (lpSystemTime, lpFileTime))
DEF(BOOL,   UnlockFile, (HANDLE hFile, DWORD dwFileOffsetLow, DWORD dwFileOffsetHigh, DWORD nNumberOfBytesToUnlockLow, DWORD nNumberOfBytesToUnlockHigh),
    (hFile, dwFileOffsetLow, dwFileOffsetHigh, nNumberOfBytesToUnlockLow, nNumberOfBytesToUnlockHigh))
DEF(BOOL,   UnlockFileEx, (HANDLE hFile, DWORD dwReserved, DWORD nNumberOfBytesToUnlockLow, DWORD nNumberOfBytesToUnlockHigh, LPOVERLAPPED lpOverlapped),
    (hFile, dwReserved, nNumberOfBytesToUnlockLow, nNumberOfBytesToUnlockHigh, lpOverlapped))
DEF(BOOL,   UnmapViewOfFile, (LPCVOID lpBaseAddress), (lpBaseAddress))
DEF(DWORD,  WaitForSingleObject, (HANDLE hHandle, DWORD dwMilliseconds), (hHandle, dwMilliseconds))
DEF(DWORD,  WaitForSingleObjectEx, (HANDLE hHandle, DWORD dwMilliseconds, BOOL bAlertable), (hHandle, dwMilliseconds, bAlertable))
DEF(int,    WideCharToMultiByte, (UINT CodePage, DWORD dwFlags, LPCWSTR lpWideCharStr, int cchWideChar, LPSTR lpMultiByteStr, int cbMultiByte, LPCSTR lpDefaultChar, LPBOOL lpUsedDefaultChar),
    (CodePage, dwFlags, lpWideCharStr, cchWideChar, lpMultiByteStr, cbMultiByte, lpDefaultChar, lpUsedDefaultChar))
DEF(BOOL,   WriteFile, (HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped),
    (hFile, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped))
