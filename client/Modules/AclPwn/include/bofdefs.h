#pragma once

#include <windows.h>
#include <winldap.h>
#include <winber.h>
#include <sddl.h>
#include <dsgetdc.h>

/*
 * AclPwn BOF - $ split imports (COFF loader resolves LIB$FUNC -> GetProcAddress).
 * All ANSI where possible; matches the wldap32/advapi32 API surface used by StandIn
 * plus token-membership helpers for identity-aware DACL walks.
 */

/* msvcrt */
WINBASEAPI size_t __cdecl MSVCRT$strlen(const char*);
WINBASEAPI int    __cdecl MSVCRT$strcmp(const char*, const char*);
WINBASEAPI int    __cdecl MSVCRT$strncmp(const char*, const char*, size_t);
WINBASEAPI char*  __cdecl MSVCRT$strchr(const char*, int);
WINBASEAPI int    __cdecl MSVCRT$sprintf(char*, const char*, ...);
WINBASEAPI int    __cdecl MSVCRT$vsnprintf(char*, size_t, const char*, va_list);
WINBASEAPI void*  __cdecl MSVCRT$memcpy(void*, const void*, size_t);
WINBASEAPI void*  __cdecl MSVCRT$memset(void*, int, size_t);
WINBASEAPI void*  __cdecl MSVCRT$calloc(size_t, size_t);
WINBASEAPI void   __cdecl MSVCRT$free(void*);

/* advapi32 */
WINBASEAPI BOOL WINAPI ADVAPI32$LookupAccountSidA(LPCSTR, PSID, LPSTR, LPDWORD, LPSTR, LPDWORD, PSID_NAME_USE);
WINBASEAPI BOOL WINAPI ADVAPI32$LookupAccountNameA(LPCSTR, LPCSTR, PSID, LPDWORD, LPSTR, LPDWORD, PSID_NAME_USE);
WINBASEAPI BOOL WINAPI ADVAPI32$GetUserNameA(LPSTR, LPDWORD);
WINBASEAPI BOOLEAN WINAPI ADVAPI32$SystemFunction036(PVOID RandomBuffer, ULONG RandomBufferLength);

/* netapi32 */
WINBASEAPI DWORD WINAPI NETAPI32$DsGetDcNameA(LPCSTR, LPCSTR, GUID*, LPCSTR, ULONG, PDOMAIN_CONTROLLER_INFOA*);
WINBASEAPI DWORD WINAPI NETAPI32$NetApiBufferFree(LPVOID);

/* wldap32 */
WINBASEAPI LDAP*        LDAPAPI WLDAP32$ldap_init(char*, ULONG);
WINBASEAPI ULONG        LDAPAPI WLDAP32$ldap_set_option(LDAP*, int, const void*);
WINBASEAPI ULONG        LDAPAPI WLDAP32$ldap_bind_s(LDAP*, const char*, const char*, ULONG);
WINBASEAPI ULONG        LDAPAPI WLDAP32$ldap_search_s(LDAP*, const char*, ULONG, const char*, char* [], ULONG, LDAPMessage**);
WINBASEAPI ULONG        LDAPAPI WLDAP32$ldap_search_ext_s(LDAP*, const char*, ULONG, const char*, char* [], ULONG, PLDAPControl*, PLDAPControl*, struct l_timeval*, ULONG, LDAPMessage**);
WINBASEAPI LDAPMessage* LDAPAPI WLDAP32$ldap_first_entry(LDAP*, LDAPMessage*);
WINBASEAPI LDAPMessage* LDAPAPI WLDAP32$ldap_next_entry(LDAP*, LDAPMessage*);
WINBASEAPI char*        LDAPAPI WLDAP32$ldap_get_dn(LDAP*, LDAPMessage*);
WINBASEAPI char**       LDAPAPI WLDAP32$ldap_get_values(LDAP*, LDAPMessage*, const char*);
WINBASEAPI struct berval** LDAPAPI WLDAP32$ldap_get_values_len(LDAP*, LDAPMessage*, const char*);
WINBASEAPI ULONG        LDAPAPI WLDAP32$ldap_value_free(char**);
WINBASEAPI ULONG        LDAPAPI WLDAP32$ldap_value_free_len(struct berval**);
WINBASEAPI ULONG        LDAPAPI WLDAP32$ldap_count_entries(LDAP*, LDAPMessage*);
WINBASEAPI void         LDAPAPI WLDAP32$ldap_memfree(char*);
WINBASEAPI ULONG        LDAPAPI WLDAP32$ldap_msgfree(LDAPMessage*);
WINBASEAPI ULONG        LDAPAPI WLDAP32$ldap_modify_s(LDAP*, const char*, LDAPMod* []);
WINBASEAPI ULONG        LDAPAPI WLDAP32$ldap_modify_ext_s(LDAP*, const char*, LDAPMod* [], PLDAPControl*, PLDAPControl*);
WINBASEAPI ULONG        LDAPAPI WLDAP32$ldap_unbind_s(LDAP*);
WINBASEAPI char*        LDAPAPI WLDAP32$ldap_err2string(ULONG);

/* memcpy/memset under -fno-builtin resolve via MSVCRT$ */
void* memcpy(void* d, const void* s, size_t n) { return MSVCRT$memcpy(d, s, n); }
void* memset(void* s, int c, size_t n)          { MSVCRT$memset(s, c, n); return s; }
