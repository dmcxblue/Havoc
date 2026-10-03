/*
 * ldap_helper — bind, rootDSE, SD-flags control, paged search.
 * All WinLDAP imports are DFR (__imp_WLDAP32$*) per the module contract;
 * export names verified against mingw-w64's libwldap32.a.
 */

#include <windows.h>
#include <dsgetdc.h>
#include <stdarg.h>
#include <stddef.h>

#include "bofout.h"
#include "ldap_helper.h"

extern "C" {
    /* WLDAP32 */
    DECLSPEC_IMPORT void*         WINAPI WLDAP32$ldap_initA(PSTR HostName, unsigned long PortNumber);
    DECLSPEC_IMPORT unsigned long WINAPI WLDAP32$ldap_set_optionA(void* ld, int option, const void* invalue);
    DECLSPEC_IMPORT unsigned long WINAPI WLDAP32$ldap_bind_sA(void* ld, const char* dn, const char* cred, unsigned long method);
    DECLSPEC_IMPORT unsigned long WINAPI WLDAP32$ldap_search_ext_sA(void* ld, const char* base, unsigned long scope, char* filter, char** attrs, unsigned long attrsonly, LDAP_CONTROL_A** ServerControls, LDAP_CONTROL_A** ClientControls, void* timeout, unsigned long SizeLimit, void** res);
    DECLSPEC_IMPORT void*         WINAPI WLDAP32$ldap_first_entry(void* ld, void* res);
    DECLSPEC_IMPORT void*         WINAPI WLDAP32$ldap_next_entry(void* ld, void* entry);
    DECLSPEC_IMPORT unsigned long WINAPI WLDAP32$ldap_count_entries(void* ld, void* res);
    DECLSPEC_IMPORT char**        WINAPI WLDAP32$ldap_get_valuesA(void* ld, void* entry, const char* attr);
    DECLSPEC_IMPORT unsigned long WINAPI WLDAP32$ldap_value_freeA(char** vals);
    DECLSPEC_IMPORT berval_t**    WINAPI WLDAP32$ldap_get_values_lenA(void* ld, void* entry, const char* attr);
    DECLSPEC_IMPORT unsigned long WINAPI WLDAP32$ldap_value_free_len(berval_t** vals);
    DECLSPEC_IMPORT unsigned long WINAPI WLDAP32$ldap_msgfree(void* res);
    DECLSPEC_IMPORT unsigned long WINAPI WLDAP32$ldap_unbind(void* ld);
    DECLSPEC_IMPORT char*         WINAPI WLDAP32$ldap_get_dnA(void* ld, void* entry);
    DECLSPEC_IMPORT unsigned long WINAPI WLDAP32$ldap_memfreeA(void* p);
    DECLSPEC_IMPORT char*         WINAPI WLDAP32$ldap_err2stringA(unsigned long err);
    DECLSPEC_IMPORT unsigned long WINAPI WLDAP32$ldap_create_page_controlA(void* ld, unsigned long PageSize, berval_t* Cookie, unsigned char IsCritical, LDAP_CONTROL_A** Control);
    DECLSPEC_IMPORT unsigned long WINAPI WLDAP32$ldap_parse_page_controlA(void* ld, LDAP_CONTROL_A** ServerControls, unsigned long* TotalCount, berval_t** Cookie);
    DECLSPEC_IMPORT unsigned long WINAPI WLDAP32$ldap_parse_resultA(void* ld, void* res, unsigned long* ReturnCode, char** MatchedDNs, char** ErrorMessage, char*** Referrals, LDAP_CONTROL_A*** ServerControls, unsigned char FreeIt);
    DECLSPEC_IMPORT unsigned long WINAPI WLDAP32$ldap_control_freeA(LDAP_CONTROL_A* Control);
    DECLSPEC_IMPORT unsigned long WINAPI WLDAP32$ldap_controls_freeA(LDAP_CONTROL_A** Controls);
    DECLSPEC_IMPORT void          WINAPI WLDAP32$ber_bvfree(berval_t* bv);

    /* NETAPI32 */
    DECLSPEC_IMPORT unsigned long WINAPI NETAPI32$DsGetDcNameA(const char* ComputerName, const char* DomainName, GUID* DomainGuid, const char* SiteName, unsigned long Flags, DOMAIN_CONTROLLER_INFOA** DomainControllerInfo);
    DECLSPEC_IMPORT unsigned long WINAPI NETAPI32$NetApiBufferFree(void* Buffer);

    /* MSVCRT */
    DECLSPEC_IMPORT int    __cdecl MSVCRT$sprintf(char* d, const char* fmt, ...);
    DECLSPEC_IMPORT int    __cdecl MSVCRT$vsnprintf(char* d, size_t n, const char* fmt, va_list arg);
    DECLSPEC_IMPORT void*  __cdecl MSVCRT$memcpy(void* d, const void* s, size_t n);
    DECLSPEC_IMPORT size_t __cdecl MSVCRT$strlen(const char* s);
}

/* ---- tiny string helpers (no extra CRT) ---- */

static void StrCopy(char* d, int cap, const char* s)
{
    int i = 0;
    if (!s) { d[0] = '\0'; return; }
    while (s[i] && i < cap - 1) { d[i] = s[i]; i++; }
    d[i] = '\0';
}

static void SetErr(LdapSession* s, const char* fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    MSVCRT$vsnprintf(s->err, sizeof(s->err), fmt, ap);
    va_end(ap);
}

/* foo.bar.local → DC=foo,DC=bar,DC=local */
static void DnsToDn(const char* dns, char* out, int cap)
{
    int pos = 0;
    const char* p = dns;
    out[0] = '\0';
    while (p && *p && pos < cap - 12) {
        const char* q = p;
        while (*q && *q != '.') q++;
        if (q == p) break;
        pos += MSVCRT$sprintf(out + pos, "DC=%.*s%s", (int)(q - p), p, *q ? "," : "");
        p = (*q) ? q + 1 : q;
    }
}

/* ---- connect / close ---- */

int LdapConnect(LdapSession* s)
{
    DOMAIN_CONTROLLER_INFOA* pdc = NULL;
    unsigned long rc;
    unsigned long ver = 3;

    s->ld = NULL; s->err[0] = '\0'; s->lastRc = LDAP_SUCCESS;
    s->dc[0] = s->dnsDomain[0] = s->domainDN[0] = s->configDN[0] = '\0';

    rc = NETAPI32$DsGetDcNameA(NULL, NULL, NULL, NULL, DS_RETURN_DNS_NAME, &pdc);
    if (rc != 0 || !pdc) {
        SetErr(s, "DsGetDcNameA failed: 0x%08lx", rc);
        return -1;
    }
    {
        const char* host = pdc->DomainControllerName;
        if (host && host[0] == '\\' && host[1] == '\\') host += 2;
        StrCopy(s->dc,        (int)sizeof(s->dc),        host);
        StrCopy(s->dnsDomain, (int)sizeof(s->dnsDomain), pdc->DomainName ? pdc->DomainName : "");
    }
    NETAPI32$NetApiBufferFree(pdc);

    s->ld = WLDAP32$ldap_initA(s->dc, LDAP_PORT);
    if (!s->ld) {
        SetErr(s, "ldap_initA(%s) failed", s->dc);
        return -1;
    }
    WLDAP32$ldap_set_optionA(s->ld, LDAP_OPT_VERSION, &ver);

    /* NULL dn/cred → Negotiate with the process token; no creds handled */
    rc = WLDAP32$ldap_bind_sA(s->ld, NULL, NULL, LDAP_AUTH_NEGOTIATE);
    if (rc != LDAP_SUCCESS) {
        SetErr(s, "ldap_bind_sA failed: %lu (%s) — beacon token likely not a domain principal", rc, WLDAP32$ldap_err2stringA(rc));
        s->lastRc = rc;
        WLDAP32$ldap_unbind(s->ld);
        s->ld = NULL;
        return -1;
    }

    /* rootDSE → configuration NC + default NC */
    {
        static char* kRootAttrs[] = { (char*)"configurationNamingContext", (char*)"defaultNamingContext", NULL };
        void* res = NULL;
        rc = WLDAP32$ldap_search_ext_sA(s->ld, (char*)"", LDAP_SCOPE_BASE, (char*)"(objectClass=*)", kRootAttrs, 0, NULL, NULL, NULL, 0, &res);
        if (rc == LDAP_SUCCESS && res) {
            void* e = WLDAP32$ldap_first_entry(s->ld, res);
            char tmp[512];
            if (e) {
                if (LdapGetStrValue(s->ld, e, "configurationNamingContext", tmp, (int)sizeof(tmp)))
                    StrCopy(s->configDN, (int)sizeof(s->configDN), tmp);
                if (LdapGetStrValue(s->ld, e, "defaultNamingContext", tmp, (int)sizeof(tmp)))
                    StrCopy(s->domainDN, (int)sizeof(s->domainDN), tmp);
            }
            WLDAP32$ldap_msgfree(res);
        }
    }
    if (!s->domainDN[0])
        DnsToDn(s->dnsDomain, s->domainDN, (int)sizeof(s->domainDN));
    if (!s->domainDN[0]) {
        SetErr(s, "could not determine the domain DN");
        return -1;
    }
    return 0;
}

void LdapClose(LdapSession* s)
{
    if (s->ld) { WLDAP32$ldap_unbind(s->ld); s->ld = NULL; }
}

/* ---- search ---- */

int LdapSearch(LdapSession* s, const char* base, int scope, const char* filter,
               char** attrs, unsigned long sdFlags, int paged, int maxEntries,
               LdapEntryFn cb, void* ctx, int* truncated)
{
    int visited = 0;
    berval_t* cookie = NULL;

    if (truncated) *truncated = 0;

    for (;;) {
        LDAP_CONTROL_A  sdCtrl;
        LDAP_CONTROL_A* pageCtrl = NULL;
        LDAP_CONTROL_A* ctrls[3];
        int             nctrl = 0;
        void*           res = NULL;
        unsigned long   rc;

        if (sdFlags) {
            sdCtrl.ldctl_oid         = (char*)LDAP_SERVER_SD_FLAGS_OID;
            sdCtrl.ldctl_value.bv_len = sizeof(LDAP_BER_SD_FLAGS);
            sdCtrl.ldctl_value.bv_val = (char*)LDAP_BER_SD_FLAGS;
            sdCtrl.ldctl_iscritical  = 1;
            ctrls[nctrl++] = &sdCtrl;
        }
        if (paged &&
            WLDAP32$ldap_create_page_controlA(s->ld, 1000, cookie, 1, &pageCtrl) == LDAP_SUCCESS &&
            pageCtrl) {
            ctrls[nctrl++] = pageCtrl;
        }
        ctrls[nctrl] = NULL;

        rc = WLDAP32$ldap_search_ext_sA(s->ld, (char*)base, (unsigned long)scope,
                                        (char*)filter, attrs, 0, ctrls, NULL, NULL, 0, &res);
        if (pageCtrl) { WLDAP32$ldap_control_freeA(pageCtrl); pageCtrl = NULL; }

        if (rc != LDAP_SUCCESS) {
            SetErr(s, "ldap_search_ext_sA(base=%.120s) failed: %lu (%s)", base, rc, WLDAP32$ldap_err2stringA(rc));
            s->lastRc = rc;
            if (cookie) { WLDAP32$ber_bvfree(cookie); cookie = NULL; }
            return -1;
        }

        {
            void* e = WLDAP32$ldap_first_entry(s->ld, res);
            while (e) {
                if (maxEntries > 0 && visited >= maxEntries) {
                    if (truncated) *truncated = 1;
                    break;
                }
                cb(s->ld, e, ctx);
                visited++;
                e = WLDAP32$ldap_next_entry(s->ld, e);
            }
        }

        if (paged) {
            unsigned long   serr = LDAP_SUCCESS, total = 0;
            LDAP_CONTROL_A** sctrls = NULL;
            berval_t*        next = NULL;
            if (WLDAP32$ldap_parse_resultA(s->ld, res, &serr, NULL, NULL, NULL, &sctrls, 0) == LDAP_SUCCESS) {
                if (WLDAP32$ldap_parse_page_controlA(s->ld, sctrls, &total, &next) == LDAP_SUCCESS) {
                    /* next is the fresh cookie (allocated by the API) */
                }
                if (sctrls) WLDAP32$ldap_controls_freeA(sctrls);
            }
            if (cookie) { WLDAP32$ber_bvfree(cookie); cookie = NULL; }
            cookie = next;
        }
        WLDAP32$ldap_msgfree(res);
        res = NULL;

        if (truncated && *truncated) break;
        if (!paged || !cookie || cookie->bv_len == 0) break;
    }

    if (cookie) { WLDAP32$ber_bvfree(cookie); cookie = NULL; }
    s->lastRc = LDAP_SUCCESS;
    return visited;
}

/* ---- attribute helpers ---- */

int LdapGetStrValue(void* ld, void* entry, const char* attr, char* out, int cap)
{
    char** vals;
    int    ok = 0;
    out[0] = '\0';
    vals = WLDAP32$ldap_get_valuesA(ld, entry, attr);
    if (!vals) return 0;
    if (vals[0]) {
        int i = 0;
        while (vals[0][i] && i < cap - 1) { out[i] = vals[0][i]; i++; }
        out[i] = '\0';
        ok = 1;
    }
    WLDAP32$ldap_value_freeA(vals);
    return ok;
}

berval_t** LdapGetBervals(void* ld, void* entry, const char* attr)
{
    return WLDAP32$ldap_get_values_lenA(ld, entry, attr);
}

void LdapFreeBervals(berval_t** vals)
{
    if (vals) WLDAP32$ldap_value_free_len(vals);
}

char* LdapEntryDn(void* ld, void* entry)
{
    return WLDAP32$ldap_get_dnA(ld, entry);
}

void LdapFreeDn(char* dn)
{
    if (dn) WLDAP32$ldap_memfreeA(dn);
}
