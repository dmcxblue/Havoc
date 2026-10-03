#pragma once

//
// Common Header Includes
//
#include <ntstatus.h>
#include <windows.h>

//
// Internal "Beacon" API header
//
#include "beacon.h"

WINADVAPI LONG WINAPI ADVAPI32$RegOpenKeyExA (HKEY, LPCSTR, DWORD, REGSAM, PHKEY);
WINADVAPI LONG WINAPI ADVAPI32$RegCloseKey(HKEY);
WINADVAPI LONG WINAPI ADVAPI32$RegSaveKeyA (HKEY, LPCSTR, LPSECURITY_ATTRIBUTES);
WINBASEAPI BOOL WINAPI ADVAPI32$OpenProcessToken (HANDLE, DWORD, PHANDLE);
WINBASEAPI DWORD WINAPI KERNEL32$GetLastError (void);
WINBASEAPI BOOL WINAPI ADVAPI32$LookupPrivilegeValueA (LPCSTR, LPCSTR, PLUID);
WINBASEAPI BOOL WINAPI ADVAPI32$AdjustTokenPrivileges(HANDLE, BOOL, PTOKEN_PRIVILEGES, DWORD, PTOKEN_PRIVILEGES, PDWORD);
WINBASEAPI HANDLE WINAPI KERNEL32$GetCurrentProcess (void);
WINBASEAPI BOOL WINAPI KERNEL32$CloseHandle (HANDLE);
WINBASEAPI LPSTR WINAPI SHLWAPI$PathCombineA(LPSTR,LPCSTR,LPCSTR);

// Extras used by the SeBackupPrivilege probe.
WINBASEAPI BOOL   WINAPI ADVAPI32$GetTokenInformation(HANDLE, TOKEN_INFORMATION_CLASS, LPVOID, DWORD, PDWORD);
WINBASEAPI HLOCAL WINAPI KERNEL32$LocalAlloc(UINT, SIZE_T);
WINBASEAPI HLOCAL WINAPI KERNEL32$LocalFree(HLOCAL);

// Buffered-output helpers. Same pattern as Gpresult/src/bofout.cpp — one
// heap buffer, vsnprintf into a stack scratch, single BeaconOutput flush.
// Avoids BeaconFormat*, which returned a stale pointer through
// BeaconPrintf("%.*s", ...) and crashed the Demon in the previous build.
#include <stdarg.h>
DECLSPEC_IMPORT void * __cdecl MSVCRT$calloc(size_t n, size_t s);
DECLSPEC_IMPORT void   __cdecl MSVCRT$free(void* p);
DECLSPEC_IMPORT void * __cdecl MSVCRT$memcpy(void* d, const void* s, size_t n);
DECLSPEC_IMPORT int    __cdecl MSVCRT$vsnprintf(char* d, size_t n, const char* fmt, va_list arg);
