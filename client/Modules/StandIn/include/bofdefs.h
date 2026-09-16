#pragma once

#include <windows.h>
#include <winldap.h>
#include <winber.h>
#include <sddl.h>
#include <dsgetdc.h>

/*
 * StandIn BOF — $ split imports. The demon's COFF loader splits "LIB$FUNC"
 * and resolves via GetProcAddress(LIB, "FUNC"), so every import below is
 * declared with the LIB$ prefix and the un-suffixed export name (wldap32
 * exports both ldap_get_dn and ldap_get_dnA/W; "ldap_get_dn" == ANSI).
 */

/* msvcrt */
WINBASEAPI size_t __cdecl MSVCRT$strlen(const char*);
WINBASEAPI int    __cdecl MSVCRT$strcmp(const char*, const char*);
WINBASEAPI int    __cdecl MSVCRT$sprintf(char*, const char*, ...);
WINBASEAPI int    __cdecl MSVCRT$vsnprintf(char*, size_t, const char*, va_list);
WINBASEAPI void*  __cdecl MSVCRT$memcpy(void*, const void*, size_t);
WINBASEAPI void*  __cdecl MSVCRT$memset(void*, int, size_t);
WINBASEAPI void*  __cdecl MSVCRT$calloc(size_t, size_t);
WINBASEAPI void   __cdecl MSVCRT$free(void*);

/* kernel32 */
WINBASEAPI HLOCAL WINAPI KERNEL32$LocalAlloc(UINT, SIZE_T);
WINBASEAPI HLOCAL WINAPI KERNEL32$LocalFree(HLOCAL);
WINBASEAPI HANDLE WINAPI KERNEL32$GetProcessHeap(VOID);
WINBASEAPI LPVOID WINAPI KERNEL32$HeapAlloc(HANDLE, DWORD, SIZE_T);
WINBASEAPI BOOL   WINAPI KERNEL32$HeapFree(HANDLE, DWORD, LPVOID);
WINBASEAPI DWORD  WINAPI KERNEL32$GetLastError(VOID);
WINBASEAPI int    WINAPI KERNEL32$lstrlenA(LPCSTR);
WINBASEAPI LPSTR  WINAPI KERNEL32$lstrcpyA(LPSTR, LPCSTR);

/* advapi32 */
WINBASEAPI BOOL WINAPI ADVAPI32$ConvertStringSecurityDescriptorToSecurityDescriptorW(LPCWSTR, DWORD, PSECURITY_DESCRIPTOR*, PULONG);
WINBASEAPI BOOL WINAPI ADVAPI32$SystemFunction036(PVOID, ULONG);

/* netapi32 */
WINBASEAPI DWORD WINAPI NETAPI32$DsGetDcNameA(LPCSTR, LPCSTR, GUID*, LPCSTR, ULONG, PDOMAIN_CONTROLLER_INFOA*);
WINBASEAPI DWORD WINAPI NETAPI32$NetApiBufferFree(LPVOID);

/* wldap32 */
WINBASEAPI LDAP*        LDAPAPI WLDAP32$ldap_init(char*, ULONG);
WINBASEAPI LDAP*        LDAPAPI WLDAP32$ldap_sslinit(char*, ULONG, int);
WINBASEAPI ULONG        LDAPAPI WLDAP32$ldap_set_option(LDAP*, int, const void*);
WINBASEAPI ULONG        LDAPAPI WLDAP32$ldap_bind_s(LDAP*, const char*, const char*, ULONG);
WINBASEAPI ULONG        LDAPAPI WLDAP32$ldap_search_s(LDAP*, const char*, ULONG, const char*, char* [], ULONG, LDAPMessage**);
WINBASEAPI LDAPMessage* LDAPAPI WLDAP32$ldap_first_entry(LDAP*, LDAPMessage*);
WINBASEAPI LDAPMessage* LDAPAPI WLDAP32$ldap_next_entry(LDAP*, LDAPMessage*);
WINBASEAPI char*        LDAPAPI WLDAP32$ldap_get_dn(LDAP*, LDAPMessage*);
WINBASEAPI char**       LDAPAPI WLDAP32$ldap_get_values(LDAP*, LDAPMessage*, const char*);
WINBASEAPI struct berval** LDAPAPI WLDAP32$ldap_get_values_len(LDAP*, LDAPMessage*, const char*);
WINBASEAPI ULONG        LDAPAPI WLDAP32$ldap_value_free(char**);
WINBASEAPI ULONG        LDAPAPI WLDAP32$ldap_value_free_len(struct berval**);
WINBASEAPI void         LDAPAPI WLDAP32$ldap_memfree(char*);
WINBASEAPI ULONG        LDAPAPI WLDAP32$ldap_msgfree(LDAPMessage*);
WINBASEAPI ULONG        LDAPAPI WLDAP32$ldap_add_s(LDAP*, const char*, LDAPMod* []);
WINBASEAPI ULONG        LDAPAPI WLDAP32$ldap_modify_s(LDAP*, const char*, LDAPMod* []);
WINBASEAPI ULONG        LDAPAPI WLDAP32$ldap_delete_ext_s(LDAP*, const char*, PLDAPControl*, PLDAPControl*);
WINBASEAPI ULONG        LDAPAPI WLDAP32$ldap_unbind_s(LDAP*);
WINBASEAPI char*        LDAPAPI WLDAP32$ldap_err2string(ULONG);

/* memcpy/memset under -fno-builtin resolve via MSVCRT$ */
void* memcpy(void* d, const void* s, size_t n) { return MSVCRT$memcpy(d, s, n); }
void* memset(void* s, int c, size_t n)          { MSVCRT$memset(s, c, n); return s; }
