#pragma once

#include <windows.h>
#include <ntsecapi.h>
#include <dsgetdc.h>
#include <tlhelp32.h>

// Macros
#define STATUS_SUCCESS              ((NTSTATUS)0x00000000L)
#define STATUS_MEMORY_NOT_ALLOCATED ((NTSTATUS)0xC00000A0L)
#define NT_SUCCESS(status)          ((NTSTATUS)(status) >= 0)
#define MemAlloc(size) KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, (size))
#define MemFree(ptr)   KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, (ptr))

#include "structs.h"

// Project structs
typedef struct _TIME_FIELDS {
    SHORT Year;
    SHORT Month;
    SHORT Day;
    SHORT Hour;
    SHORT Minute;
    SHORT Second;
    SHORT Milliseconds;
    SHORT Weekday;
} TIME_FIELDS, *PTIME_FIELDS;

typedef struct {
    LUID          luid;
    char          spn[256];
    char          clientName[256];
    char          clientRealm[256];
    char          serverRealm[256];
    LARGE_INTEGER startTime;
    LARGE_INTEGER endTime;
    LARGE_INTEGER renewUntil;
    ULONG         ticketFlags;
    LONG          encryptionType;
} TICKET_ENTRY, *PTICKET_ENTRY;

typedef struct {
    PTICKET_ENTRY tickets;
    int           count;
} TICKET_CACHE, *PTICKET_CACHE;

typedef struct {
    ULONG       mask;
    const char* name;
} FLAG_ENTRY, *PFLAG_ENTRY;

// KERNEL32
DECLSPEC_IMPORT HANDLE   WINAPI KERNEL32$GetProcessHeap(VOID);
DECLSPEC_IMPORT LPVOID   WINAPI KERNEL32$HeapAlloc(HANDLE, DWORD, SIZE_T);
DECLSPEC_IMPORT BOOL     WINAPI KERNEL32$HeapFree(HANDLE, DWORD, LPVOID);
DECLSPEC_IMPORT DWORD    WINAPI KERNEL32$WaitForSingleObjectEx(HANDLE, DWORD, BOOLEAN);
DECLSPEC_IMPORT VOID     WINAPI KERNEL32$GetLocalTime(LPSYSTEMTIME);
DECLSPEC_IMPORT int      WINAPI KERNEL32$WideCharToMultiByte(UINT, DWORD, LPCWCH, int, LPSTR, int, LPCCH, LPBOOL);
DECLSPEC_IMPORT HANDLE   WINAPI KERNEL32$CreateToolhelp32Snapshot(DWORD, DWORD);
DECLSPEC_IMPORT BOOL     WINAPI KERNEL32$Thread32First(HANDLE, LPTHREADENTRY32);
DECLSPEC_IMPORT BOOL     WINAPI KERNEL32$Thread32Next(HANDLE, LPTHREADENTRY32);
DECLSPEC_IMPORT HANDLE   WINAPI KERNEL32$OpenThread(DWORD, BOOL, DWORD);
DECLSPEC_IMPORT DWORD    WINAPI KERNEL32$GetCurrentProcessId(VOID);
DECLSPEC_IMPORT BOOL     WINAPI KERNEL32$CloseHandle(HANDLE);
DECLSPEC_IMPORT HMODULE  WINAPI KERNEL32$LoadLibraryA(LPCSTR);
DECLSPEC_IMPORT HMODULE  WINAPI KERNEL32$GetModuleHandleA(LPCSTR);
DECLSPEC_IMPORT FARPROC  WINAPI KERNEL32$GetProcAddress(HMODULE, LPCSTR);
DECLSPEC_IMPORT VOID     WINAPI KERNEL32$GetSystemTime(LPSYSTEMTIME);
DECLSPEC_IMPORT BOOL     WINAPI KERNEL32$SystemTimeToFileTime(CONST SYSTEMTIME*, LPFILETIME);
DECLSPEC_IMPORT BOOL     WINAPI KERNEL32$FileTimeToSystemTime(CONST FILETIME*, LPSYSTEMTIME);
DECLSPEC_IMPORT int      WINAPI KERNEL32$MultiByteToWideChar(UINT, DWORD, LPCCH, int, LPWSTR, int);
DECLSPEC_IMPORT DWORD    WINAPI KERNEL32$GetLastError();

// ADVAPI32
DECLSPEC_IMPORT BOOL     WINAPI ADVAPI32$OpenProcessToken(HANDLE, DWORD, PHANDLE);
DECLSPEC_IMPORT BOOL     WINAPI ADVAPI32$OpenThreadToken(HANDLE, DWORD, BOOL, PHANDLE);
DECLSPEC_IMPORT BOOL     WINAPI ADVAPI32$GetTokenInformation(HANDLE, TOKEN_INFORMATION_CLASS, LPVOID, DWORD, PDWORD);
DECLSPEC_IMPORT BOOL     WINAPI ADVAPI32$DuplicateTokenEx(HANDLE, DWORD, LPSECURITY_ATTRIBUTES, SECURITY_IMPERSONATION_LEVEL, TOKEN_TYPE, PHANDLE);
DECLSPEC_IMPORT BOOL     WINAPI ADVAPI32$SetThreadToken(PHANDLE, HANDLE);
DECLSPEC_IMPORT BOOL     WINAPI ADVAPI32$RevertToSelf(VOID);
DECLSPEC_IMPORT BOOL     WINAPI ADVAPI32$EqualSid(PSID, PSID);
DECLSPEC_IMPORT BOOL     WINAPI ADVAPI32$AllocateAndInitializeSid(PSID_IDENTIFIER_AUTHORITY, BYTE, DWORD, DWORD, DWORD, DWORD, DWORD, DWORD, DWORD, DWORD, PSID*);
DECLSPEC_IMPORT PVOID    WINAPI ADVAPI32$FreeSid(PSID);
DECLSPEC_IMPORT BOOL     WINAPI ADVAPI32$SystemFunction036(PVOID, ULONG);

// NTDLL
DECLSPEC_IMPORT VOID     NTAPI  NTDLL$RtlTimeToTimeFields(PLARGE_INTEGER, PTIME_FIELDS);
DECLSPEC_IMPORT VOID     NTAPI  NTDLL$RtlSystemTimeToLocalTime(PLARGE_INTEGER, PLARGE_INTEGER);
DECLSPEC_IMPORT NTSTATUS NTAPI  NTDLL$NtQuerySystemTime(PLARGE_INTEGER);

// SECUR32
DECLSPEC_IMPORT NTSTATUS WINAPI SECUR32$LsaRegisterLogonProcess(PLSA_STRING, PHANDLE, PLSA_OPERATIONAL_MODE);
DECLSPEC_IMPORT NTSTATUS WINAPI SECUR32$LsaLookupAuthenticationPackage(HANDLE, PLSA_STRING, PULONG);
DECLSPEC_IMPORT NTSTATUS WINAPI SECUR32$LsaCallAuthenticationPackage(HANDLE, ULONG, PVOID, ULONG, PVOID*, PULONG, PNTSTATUS);
DECLSPEC_IMPORT NTSTATUS WINAPI SECUR32$LsaFreeReturnBuffer(PVOID);
DECLSPEC_IMPORT NTSTATUS WINAPI SECUR32$LsaEnumerateLogonSessions(PULONG, PLUID*);
DECLSPEC_IMPORT NTSTATUS WINAPI SECUR32$LsaGetLogonSessionData(PLUID, PSECURITY_LOGON_SESSION_DATA*);
DECLSPEC_IMPORT NTSTATUS WINAPI SECUR32$LsaDeregisterLogonProcess(HANDLE);

// NETAPI32
DECLSPEC_IMPORT DWORD    WINAPI NETAPI32$DsGetDcNameA(LPCSTR, LPCSTR, GUID*, LPCSTR, ULONG, PDOMAIN_CONTROLLER_INFOA*);
DECLSPEC_IMPORT DWORD    WINAPI NETAPI32$NetApiBufferFree(LPVOID);

// WS2_32 (only when winsock headers included)
#ifdef _WINSOCK2API_
DECLSPEC_IMPORT int    __stdcall WS2_32$WSAGetLastError(void);
DECLSPEC_IMPORT int    WSAAPI    WS2_32$WSAStartup(WORD, LPWSADATA);
DECLSPEC_IMPORT int    WSAAPI    WS2_32$WSACleanup(void);
DECLSPEC_IMPORT int    __stdcall WS2_32$getaddrinfo(const char*, const char*, const struct addrinfo*, struct addrinfo**);
DECLSPEC_IMPORT void   __stdcall WS2_32$freeaddrinfo(struct addrinfo*);
DECLSPEC_IMPORT SOCKET __stdcall WS2_32$socket(int, int, int);
DECLSPEC_IMPORT int    WSAAPI    WS2_32$connect(SOCKET, const struct sockaddr*, int);
DECLSPEC_IMPORT int    WSAAPI    WS2_32$send(SOCKET, const char*, int, int);
DECLSPEC_IMPORT int    WSAAPI    WS2_32$recv(SOCKET, char*, int, int);
DECLSPEC_IMPORT int    __stdcall WS2_32$closesocket(SOCKET);
#endif

// MSVCRT
DECLSPEC_IMPORT int           WINAPI MSVCRT$strcmp(const char*, const char*);
DECLSPEC_IMPORT int           WINAPI MSVCRT$wcsncmp(const WCHAR*, const WCHAR*, size_t);
DECLSPEC_IMPORT size_t        WINAPI MSVCRT$wcslen(const WCHAR*);
DECLSPEC_IMPORT void*         WINAPI MSVCRT$memcpy(void*, const void*, size_t);
DECLSPEC_IMPORT int           WINAPI MSVCRT$_stricmp(const char*, const char*);
DECLSPEC_IMPORT int           WINAPI MSVCRT$_snprintf(char*, size_t, const char*, ...);
DECLSPEC_IMPORT int           __cdecl MSVCRT$sprintf(char*, const char*, ...);
DECLSPEC_IMPORT size_t        WINAPI MSVCRT$strlen(const char*);
DECLSPEC_IMPORT unsigned long WINAPI MSVCRT$strtoul(const char*, char**, int);

// common.c
BOOL     IsSystem(VOID);
HANDLE   StealSystemToken(VOID);
NTSTATUS GetLsaHandle(HANDLE* hLsa);
BOOL     IsTargetUser(const char* targetUsers, const char* username);
NTSTATUS ExtractTicket(HANDLE hLsa, ULONG authPackage, LUID luid, UNICODE_STRING target, PUCHAR* ticket, PULONG ticketSize);
NTSTATUS EnumerateTGTs(HANDLE hLsa, ULONG authPackage, char* targetUsers, PTICKET_CACHE cache);
VOID     PrintTime(LARGE_INTEGER* li);
VOID     PrintTicketInformation(PTICKET_ENTRY entry, const char* label);
VOID     PrintTicket(PBYTE ticket, ULONG ticketSize);
