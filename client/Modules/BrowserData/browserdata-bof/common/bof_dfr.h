/* bof_dfr.h - Dynamic Function Resolution shim for the browserdata BOF.
 *
 * Havoc's CoffeeLdr resolves imports of the form __imp_LIB$FUNC via
 * LoadLibrary(LIB)+GetProcAddress(FUNC); unqualified __imp_FUNC only resolves
 * against a tiny built-in table, and bare externs do NOT resolve at all. So
 * every kernel32 import must end up as __imp_KERNEL32$FUNC. We pre-alias each
 * symbol to KERNEL32$FUNC before any SDK header runs, so mingw's `windows.h`
 * (and sqlite3's own windows.h include) emit __imp_KERNEL32$FUNC.
 *
 * Functions that mingw's SDK declares WITHOUT dllimport (tlhelp32.h) need an
 * explicit __declspec(dllimport) prototype after their header is included;
 * those live in the .c files that use them (bd_locked.c), not here.
 *
 * Force-included via -include for every TU including vendor/sqlite3.c.
 */
#ifndef BOF_DFR_H
#define BOF_DFR_H

#define AreFileApisANSI           KERNEL32$AreFileApisANSI
#define CloseHandle               KERNEL32$CloseHandle
#define CopyFileA                 KERNEL32$CopyFileA
#define CreateDirectoryA          KERNEL32$CreateDirectoryA
#define CreateFileA               KERNEL32$CreateFileA
#define CreateFileMappingW        KERNEL32$CreateFileMappingW
#define CreateFileW               KERNEL32$CreateFileW
#define CreateMutexW              KERNEL32$CreateMutexW
#define CreateProcessA            KERNEL32$CreateProcessA
#define CreateRemoteThread        KERNEL32$CreateRemoteThread
#define CreateToolhelp32Snapshot  KERNEL32$CreateToolhelp32Snapshot
#define DeleteFileA               KERNEL32$DeleteFileA
#define DeleteFileW               KERNEL32$DeleteFileW
#define DuplicateHandle           KERNEL32$DuplicateHandle
#define FindClose                 KERNEL32$FindClose
#define FindFirstFileA            KERNEL32$FindFirstFileA
#define FindNextFileA             KERNEL32$FindNextFileA
#define FlushFileBuffers          KERNEL32$FlushFileBuffers
#define FlushInstructionCache     KERNEL32$FlushInstructionCache
#define FlushViewOfFile           KERNEL32$FlushViewOfFile
#define FormatMessageA            KERNEL32$FormatMessageA
#define FormatMessageW            KERNEL32$FormatMessageW
#define FreeLibrary               KERNEL32$FreeLibrary
#define GetCurrentProcess         KERNEL32$GetCurrentProcess
#define GetCurrentProcessId       KERNEL32$GetCurrentProcessId
#define GetDiskFreeSpaceA         KERNEL32$GetDiskFreeSpaceA
#define GetDiskFreeSpaceW         KERNEL32$GetDiskFreeSpaceW
#define GetFileAttributesA        KERNEL32$GetFileAttributesA
#define GetFileAttributesExW      KERNEL32$GetFileAttributesExW
#define GetFileAttributesW        KERNEL32$GetFileAttributesW
#define GetFileSize               KERNEL32$GetFileSize
#define GetFileSizeEx             KERNEL32$GetFileSizeEx
#define GetFileType               KERNEL32$GetFileType
#define GetFinalPathNameByHandleA KERNEL32$GetFinalPathNameByHandleA
#define GetFullPathNameA          KERNEL32$GetFullPathNameA
#define GetFullPathNameW          KERNEL32$GetFullPathNameW
#define GetLastError              KERNEL32$GetLastError
#define GetModuleHandleA          KERNEL32$GetModuleHandleA
#define GetModuleHandleW          KERNEL32$GetModuleHandleW
#define GetProcessHeap            KERNEL32$GetProcessHeap
#define GetProcAddress            KERNEL32$GetProcAddress
#define GetSystemInfo             KERNEL32$GetSystemInfo
#define GetSystemTime             KERNEL32$GetSystemTime
#define GetSystemTimeAsFileTime   KERNEL32$GetSystemTimeAsFileTime
#define GetTempPathA              KERNEL32$GetTempPathA
#define GetTempPathW              KERNEL32$GetTempPathW
#define GetTickCount              KERNEL32$GetTickCount
#define HeapAlloc                 KERNEL32$HeapAlloc
#define HeapCompact               KERNEL32$HeapCompact
#define HeapCreate                KERNEL32$HeapCreate
#define HeapDestroy               KERNEL32$HeapDestroy
#define HeapFree                  KERNEL32$HeapFree
#define HeapReAlloc               KERNEL32$HeapReAlloc
#define HeapSize                  KERNEL32$HeapSize
#define HeapValidate              KERNEL32$HeapValidate
#define LocalFree                 KERNEL32$LocalFree
#define LockFile                  KERNEL32$LockFile
#define LockFileEx                KERNEL32$LockFileEx
#define LoadLibraryA              KERNEL32$LoadLibraryA
#define MapViewOfFile             KERNEL32$MapViewOfFile
#define MultiByteToWideChar       KERNEL32$MultiByteToWideChar
#define OpenProcess               KERNEL32$OpenProcess
#define OutputDebugStringA        KERNEL32$OutputDebugStringA
#define OutputDebugStringW        KERNEL32$OutputDebugStringW
#define Process32First            KERNEL32$Process32First
#define Process32Next             KERNEL32$Process32Next
#define QueryPerformanceCounter   KERNEL32$QueryPerformanceCounter
#define ReadFile                  KERNEL32$ReadFile
#define ReadProcessMemory         KERNEL32$ReadProcessMemory
#define RemoveDirectoryA          KERNEL32$RemoveDirectoryA
#define SetEndOfFile              KERNEL32$SetEndOfFile
#define SetEnvironmentVariableA   KERNEL32$SetEnvironmentVariableA
#define SetFilePointer            KERNEL32$SetFilePointer
#define Sleep                     KERNEL32$Sleep
#define SystemTimeToFileTime      KERNEL32$SystemTimeToFileTime
#define TerminateProcess          KERNEL32$TerminateProcess
#define UnlockFile                KERNEL32$UnlockFile
#define UnlockFileEx              KERNEL32$UnlockFileEx
#define UnmapViewOfFile           KERNEL32$UnmapViewOfFile
#define VirtualAllocEx            KERNEL32$VirtualAllocEx
#define VirtualProtectEx          KERNEL32$VirtualProtectEx
#define WaitForSingleObject       KERNEL32$WaitForSingleObject
#define WaitForSingleObjectEx     KERNEL32$WaitForSingleObjectEx
#define WideCharToMultiByte       KERNEL32$WideCharToMultiByte
#define WriteFile                 KERNEL32$WriteFile
#define WriteProcessMemory        KERNEL32$WriteProcessMemory

#endif /* BOF_DFR_H */
