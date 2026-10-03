#ifndef LDAP_HELPER_H
#define LDAP_HELPER_H

/*
 * LDAP plumbing for the `gpresult domain` sweep.
 *
 * winldap.h is deliberately NOT included: its plain DECLSPEC_IMPORT
 * declarations would emit unresolvable __imp_ldap_* symbols and break the
 * module's DFR (__imp_MODULE$Function) contract. The types below mirror
 * winldap.h exactly for x64 — verified against the mingw-w64 headers and
 * the libwldap32.a export list.
 */

typedef struct berval_t {
    unsigned long bv_len;   /* ULONG — 32-bit on Windows (LLP64) */
    char*         bv_val;   /* aligned to 8 → same layout as lber.h berval */
} berval_t;

typedef struct ldap_control_a {
    char*         ldctl_oid;
    berval_t      ldctl_value;
    unsigned char ldctl_iscritical;   /* BOOLEAN — same offsets as LDAPControlA */
} LDAP_CONTROL_A;

/* protocol constants (values match winldap.h) */
#define LDAP_PORT            389
#define LDAP_SCOPE_BASE      0x00
#define LDAP_SCOPE_ONELEVEL  0x01
#define LDAP_SCOPE_SUBTREE   0x02
#define LDAP_SUCCESS         0x00
#define LDAP_NO_SUCH_OBJECT  0x20
#define LDAP_AUTH_NEGOTIATE  0x486   /* LDAP_AUTH_OTHERKIND | 0x0400 */
#define LDAP_OPT_VERSION     0x11

/* LDAP_SERVER_SD_FLAGS_OID — asks the server to return nTSecurityDescriptor
 * to non-admin binds. Value is a BER SEQUENCE { INTEGER flags }; 0x7 =
 * OWNER | GROUP | DACL security information. */
#define LDAP_SERVER_SD_FLAGS_OID "1.2.840.113556.1.4.801"
static const unsigned char LDAP_BER_SD_FLAGS[5] = { 0x30, 0x03, 0x02, 0x01, 0x07 };

/* LDAP_PAGED_RESULT_OID_STRING */
#define LDAP_PAGED_RESULT_OID "1.2.840.113556.1.4.319"

typedef struct LdapSession {
    void*         ld;
    char          dc[256];         /* DomainControllerName, "dc01.dom.local" */
    char          dnsDomain[256];  /* DNS domain name */
    char          domainDN[512];   /* defaultNamingContext (or DNS-derived) */
    char          configDN[512];   /* configurationNamingContext */
    char          err[256];        /* last error text */
    unsigned long lastRc;          /* last LDAP result code */
} LdapSession;

/* DsGetDcNameA + ldap_initA + negotiate bind + rootDSE read. 0 on success. */
int  LdapConnect(LdapSession* s);
void LdapClose(LdapSession* s);

typedef void (*LdapEntryFn)(void* ld, void* entry, void* ctx);

/*
 * Runs `filter` under `base` and invokes cb() per entry.
 *  - sdFlags != 0  → attach the SD-flags control (value 0x7) so the DACL is
 *                    returned to non-admin binds.
 *  - paged         → follow the paged-results control until the cookie
 *                    drains (LDAP MaxPageSize proof).
 *  - maxEntries    → per-surface soft cap; *truncated set when it cut the walk.
 * Returns the number of entries visited, or -1 on error (s->err / s->lastRc).
 */
int  LdapSearch(LdapSession* s, const char* base, int scope, const char* filter,
                char** attrs, unsigned long sdFlags, int paged, int maxEntries,
                LdapEntryFn cb, void* ctx, int* truncated);

/* attribute helpers */
int  LdapGetStrValue(void* ld, void* entry, const char* attr, char* out, int cap);
berval_t** LdapGetBervals(void* ld, void* entry, const char* attr);
void LdapFreeBervals(berval_t** vals);
char* LdapEntryDn(void* ld, void* entry);
void  LdapFreeDn(char* dn);

#endif /* LDAP_HELPER_H */
