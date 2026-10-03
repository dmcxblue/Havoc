#pragma once

#include <winsock2.h>
#include <windows.h>
#include <winldap.h>

/* DsGetDcNameA is declared in the SDK's dsgetdc.h, not in winnt.h/winbase.h.
   Include it so both the -DBOF prototype below and the off-implant harness bind
   against the SDK's real signature instead of an implicit declaration. */
#include <dsgetdc.h>
/* <lmapibuf.h> is not standalone - it needs NET_API_STATUS from lmcons.h, which
   only lm.h pulls in first (and in the right order). */
#include <lm.h>

/* Aliased rather than hand-declared: the SDK (and wine's) DSGETDCNAMEA layout
   MUST match byte-for-byte, because DsGetDcNameA writes that struct straight
   into our allocation. A hand-rolled copy silently misparses it. */
#define ASREP_DC_INFOA DOMAIN_CONTROLLER_INFOA

#if defined(BOF)

/* msvcrt */
WINBASEAPI size_t __cdecl MSVCRT$strlen(const char*);
WINBASEAPI void*  __cdecl MSVCRT$calloc(size_t, size_t);
WINBASEAPI void   __cdecl MSVCRT$free(void*);
WINBASEAPI void*  __cdecl MSVCRT$memcpy(void*, const void*, size_t);
WINBASEAPI void*  __cdecl MSVCRT$memset(void*, int, size_t);
WINBASEAPI int    __cdecl MSVCRT$sprintf(char*, const char*, ...);
WINBASEAPI int    __cdecl MSVCRT$vsnprintf(char*, size_t, const char*, va_list);

/* kernel32 */
WINBASEAPI DWORD WINAPI KERNEL32$GetTickCount(VOID);
WINBASEAPI DWORD WINAPI KERNEL32$GetLastError(VOID);

/* wldap32 */
WINBASEAPI LDAP*        LDAPAPI WLDAP32$ldap_init(PSTR, ULONG);
WINBASEAPI ULONG        LDAPAPI WLDAP32$ldap_set_option(LDAP*, int, const void*);
WINBASEAPI ULONG        LDAPAPI WLDAP32$ldap_bind_s(LDAP*, const PSTR, const PCHAR, ULONG);
WINBASEAPI ULONG        LDAPAPI WLDAP32$ldap_search_s(LDAP*, const PSTR, ULONG, const PSTR, PSTR[], ULONG, LDAPMessage**);
WINBASEAPI LDAPMessage* LDAPAPI WLDAP32$ldap_first_entry(LDAP*, LDAPMessage*);
WINBASEAPI LDAPMessage* LDAPAPI WLDAP32$ldap_next_entry(LDAP*, LDAPMessage*);
WINBASEAPI PCHAR*       LDAPAPI WLDAP32$ldap_get_values(LDAP*, LDAPMessage*, const PSTR);
WINBASEAPI ULONG        LDAPAPI WLDAP32$ldap_value_free(PCHAR*);
WINBASEAPI ULONG        LDAPAPI WLDAP32$ldap_msgfree(LDAPMessage*);
WINBASEAPI ULONG        LDAPAPI WLDAP32$ldap_unbind(LDAP*);

/* ws2_32 */
WINBASEAPI int    WINAPI WS2_32$WSAStartup(WORD, LPWSADATA);
WINBASEAPI int    WINAPI WS2_32$WSACleanup(void);
WINBASEAPI SOCKET WINAPI WS2_32$socket(int, int, int);
WINBASEAPI int    WINAPI WS2_32$connect(SOCKET, const struct sockaddr*, int);
WINBASEAPI int    WINAPI WS2_32$send(SOCKET, const char*, int, int);
WINBASEAPI int    WINAPI WS2_32$recv(SOCKET, char*, int, int);
WINBASEAPI int    WINAPI WS2_32$closesocket(SOCKET);

/* netapi32 */
WINBASEAPI DWORD WINAPI NETAPI32$DsGetDcNameA(LPCSTR, LPCSTR, GUID*, LPCSTR, ULONG, PDOMAIN_CONTROLLER_INFOA*);
WINBASEAPI DWORD WINAPI NETAPI32$NetApiBufferFree(LPVOID);

#else

#define MSVCRT$strlen    strlen
#define MSVCRT$calloc    calloc
#define MSVCRT$free      free
#define MSVCRT$memcpy    memcpy
#define MSVCRT$memset    memset
#define MSVCRT$sprintf   sprintf
#define MSVCRT$vsnprintf vsnprintf

#define KERNEL32$GetTickCount  GetTickCount
#define KERNEL32$GetLastError  GetLastError

#define WLDAP32$ldap_init         ldap_init
#define WLDAP32$ldap_set_option   ldap_set_option
#define WLDAP32$ldap_bind_s       ldap_bind_s
#define WLDAP32$ldap_search_s     ldap_search_s
#define WLDAP32$ldap_first_entry  ldap_first_entry
#define WLDAP32$ldap_next_entry   ldap_next_entry
#define WLDAP32$ldap_get_values   ldap_get_values
#define WLDAP32$ldap_value_free   ldap_value_free
#define WLDAP32$ldap_msgfree      ldap_msgfree
#define WLDAP32$ldap_unbind       ldap_unbind

#define WS2_32$WSAStartup   WSAStartup
#define WS2_32$WSACleanup   WSACleanup
#define WS2_32$socket        socket
#define WS2_32$connect       connect
#define WS2_32$send          send
#define WS2_32$recv          recv
#define WS2_32$closesocket   closesocket

#define NETAPI32$DsGetDcNameA      DsGetDcNameA
#define NETAPI32$NetApiBufferFree  NetApiBufferFree

#endif
