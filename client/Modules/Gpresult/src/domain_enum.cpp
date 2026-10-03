/*
 * domain_enum — `gpresult domain` main sweep (PLAN-DOMAIN.md).
 *
 * Six ACL surfaces, all ACE-walked against the caller's token SIDs:
 *   1. GPO objects      CN=Policies,CN=System,<domainDN>
 *   2. SYSVOL GPT       \\<dom>\SYSVOL\<dom>\Policies\{guid}\ file DACLs
 *   3. Domain root      WriteProperty on gPLink
 *   4. OUs              WriteProperty on gPLink (subtree, paged)
 *   5. Sites            CN=Sites,CN=Configuration (gPLink)
 *   6. WMI filters      CN=SOM,CN=WMIPolicy,CN=System (msWMI-Som)
 *
 * Output is buffered (bof_printf) and severity-tagged:
 *   [!] actionable, [+] write-limited, [ ] read-only (-v only).
 */

#define SECURITY_WIN32
#include <windows.h>
#include <secext.h>

extern "C" {
    /* ADVAPI32 */
    DECLSPEC_IMPORT BOOL  WINAPI ADVAPI32$LookupAccountSidA(LPCSTR lpSystemName, PSID Sid, LPSTR Name, LPDWORD cchName, LPSTR ReferencedDomainName, LPDWORD cchReferencedDomainName, PSID_NAME_USE peUse);
    DECLSPEC_IMPORT BOOL  WINAPI ADVAPI32$ConvertSidToStringSidA(PSID Sid, LPSTR* StringSid);
    DECLSPEC_IMPORT BOOL  WINAPI ADVAPI32$GetFileSecurityA(LPCSTR lpFileName, SECURITY_INFORMATION RequestedInformation, PSECURITY_DESCRIPTOR pSecurityDescriptor, DWORD nLength, LPDWORD lpnLengthNeeded);
    DECLSPEC_IMPORT DWORD WINAPI ADVAPI32$GetSidLengthRequired(UCHAR nSubAuthorityCount);

    /* SECUR32 */
    DECLSPEC_IMPORT BOOLEAN WINAPI SECUR32$GetUserNameExA(EXTENDED_NAME_FORMAT NameFormat, LPSTR lpNameBuffer, PULONG nSize);

    /* KERNEL32 */
    DECLSPEC_IMPORT DWORD   WINAPI KERNEL32$GetLastError(VOID);
    DECLSPEC_IMPORT HLOCAL  WINAPI KERNEL32$LocalAlloc(UINT uFlags, SIZE_T dwBytes);
    DECLSPEC_IMPORT HLOCAL  WINAPI KERNEL32$LocalFree(HLOCAL hMem);

    /* MSVCRT */
    DECLSPEC_IMPORT int    __cdecl MSVCRT$sprintf(char* d, const char* fmt, ...);
    DECLSPEC_IMPORT void*  __cdecl MSVCRT$memcpy(void* d, const void* s, size_t n);
}

#include "bofout.h"
#include "ldap_helper.h"
#include "sd_walker.h"
#include "gpo_rights_table.h"
#include "domain_enum.h"

/* shared buffered-output engine (src/bofout.cpp) */
#define bprintf bof_printf

#define SOFT_CAP 500
#define MAXGPT   96
#define LMEM_ZEROINIT_ 0x0040

/* ---- tiny string helpers (no extra CRT) ---- */

static void StrCopy(char* d, int cap, const char* s)
{
    int i = 0;
    if (!s) { d[0] = '\0'; return; }
    while (s[i] && i < cap - 1) { d[i] = s[i]; i++; }
    d[i] = '\0';
}

static int BytesEq(const void* a, const void* b, unsigned long n)
{
    const unsigned char* x = (const unsigned char*)a;
    const unsigned char* y = (const unsigned char*)b;
    for (unsigned long i = 0; i < n; i++)
        if (x[i] != y[i]) return 0;
    return 1;
}

/* ---- SID → "DOMAIN\name" resolution (cached) ---- */

struct SidNameEnt {
    unsigned char sid[SD_SID_MAX_BYTES];
    int           sidLen;
    char          name[256];
};

static SidNameEnt g_sidCache[64];
static int        g_sidCacheN  = 0;
static char       g_sidScratch[280];

static const char* ResolveSidName(void* sid)
{
    unsigned long  len;
    SidNameEnt*    e = NULL;
    char*          out;
    char           name[128], dom[128];
    DWORD          n = (DWORD)sizeof(name), d = (DWORD)sizeof(dom);
    SID_NAME_USE   use;

    if (!sid) return "?";
    len = ADVAPI32$GetSidLengthRequired(((unsigned char*)sid)[1]);
    if (len == 0 || len > SD_SID_MAX_BYTES) return "?";

    for (int i = 0; i < g_sidCacheN; i++)
        if (g_sidCache[i].sidLen == (int)len && BytesEq(g_sidCache[i].sid, sid, len))
            return g_sidCache[i].name;

    if (g_sidCacheN < (int)(sizeof(g_sidCache) / sizeof(g_sidCache[0])))
        e = &g_sidCache[g_sidCacheN++];
    if (e) {
        MSVCRT$memcpy(e->sid, sid, len);
        e->sidLen = (int)len;
        out = e->name;
    } else {
        out = g_sidScratch;
    }

    if (ADVAPI32$LookupAccountSidA(NULL, (PSID)sid, name, &n, dom, &d, &use))
        MSVCRT$sprintf(out, "%s%s%s", dom, dom[0] ? "\\" : "", name);
    else {
        LPSTR ss = NULL;
        if (ADVAPI32$ConvertSidToStringSidA((PSID)sid, &ss)) {
            StrCopy(out, 260, ss);
            KERNEL32$LocalFree((HLOCAL)ss);
        } else {
            StrCopy(out, 260, "<unresolved SID>");
        }
    }
    return out;
}

/* ---- sweep state ---- */

struct GptItem {
    char guid[80];
    char fsPath[768];
};

struct SweepState {
    int          verbose;
    TokenSidSet* toks;
    int          surface;        /* surface currently being processed */
    int          firstForObject; /* object header not yet printed     */
    char         objTitle[1200];
    char         sectTitle[SURF_COUNT][700];
    int          sectPrinted[SURF_COUNT];
    int          cnt[3];         /* actionable / limited / read */
    int          objs[SURF_COUNT];
    int          anyTrunc;
    int          gptOverflow;
    GptItem*     gpt;
    int          gptN;
};

static char SevChar(int sev)
{
    return (sev == SEV_ACTIONABLE) ? '!' : (sev == SEV_LIMITED) ? '+' : ' ';
}

static void SurfaceHeader(SweepState* st, int surface)
{
    if (st->sectPrinted[surface]) return;
    st->sectPrinted[surface] = 1;
    bprintf("\n%s\n", st->sectTitle[surface]);
}

/* ---- emission ---- */

static const char* kSurfaceTag(int surface);

static void Emit(SweepState* st, const ClassCtx* c, const char* who, int inherited)
{
    ClassOut cl;
    ClassifyAce(c, &cl);
    st->cnt[cl.sev]++;

    if (cl.sev == SEV_READ && !st->verbose) return;   /* suppressed */

    SurfaceHeader(st, st->surface);
    if (st->firstForObject) {
        bprintf("%-9s %s\n", kSurfaceTag(st->surface), st->objTitle);
        st->firstForObject = 0;
    }
    if (inherited && st->verbose)
        bprintf("         via %-32s %s (mask=0x%08lX) [inherited]\n", who, cl.label, c->mask);
    else
        bprintf("         via %-32s %s (mask=0x%08lX)\n", who, cl.label, c->mask);
    bprintf("         [%c] %s: %s\n", SevChar(cl.sev), cl.verb, cl.hint);
}

struct ObjCtx {
    SweepState* st;
    ClassCtx    cc;
    char        guidBuf[40];
};

static void AceCb(void* ctx, unsigned long mask, int aceType, const char* objGuid,
                  void* aceSid, int inherited)
{
    ObjCtx* o = (ObjCtx*)ctx;
    o->cc.mask    = mask;
    o->cc.aceType = aceType;
    StrCopy(o->guidBuf, (int)sizeof(o->guidBuf), objGuid);
    Emit(o->st, &o->cc, ResolveSidName(aceSid), inherited);
}

/* surface tag ([GPO] / [SYSVOL] / [LINK] / [WMI]) — gpo_rights_table has the
 * surface enum, the tag belongs to presentation, so it lives here. */
static const char* kSurfaceTag(int surface)
{
    switch (surface) {
    case SURF_GPO:  return "[GPO]";
    case SURF_SYSVOL: return "[SYSVOL]";
    case SURF_WMI:  return "[WMI]";
    default:        return "[LINK]";
    }
}

static void ProcessSd(SweepState* st, int surface, const char* title,
                      const void* sd, const char* filePath)
{
    ObjCtx o;
    o.st          = st;
    o.cc.surface  = surface;
    o.cc.mask     = 0;
    o.cc.aceType  = SD_ACE_ALLOWED;
    o.cc.objGuid  = o.guidBuf;
    o.cc.filePath = filePath ? filePath : "";
    o.guidBuf[0]  = '\0';
    st->surface       = surface;
    st->firstForObject = 1;
    StrCopy(st->objTitle, (int)sizeof(st->objTitle), title);
    SdWalkDacl(sd, st->toks, AceCb, &o);
}

/* ---- per-surface LDAP entry callbacks ---- */

static void GetEntrySd(SweepState* st, void* ld, void* entry, int surface, const char* title)
{
    berval_t** sdv = LdapGetBervals(ld, entry, "nTSecurityDescriptor");
    st->objs[surface]++;
    if (!sdv || !sdv[0]) {
        if (st->verbose)
            bprintf("[ ] no nTSecurityDescriptor returned for %s\n", title);
        if (sdv) LdapFreeBervals(sdv);
        return;
    }
    ProcessSd(st, surface, title, sdv[0]->bv_val, NULL);
    LdapFreeBervals(sdv);
}

static void GpoEntryCb(void* ld, void* entry, void* ctx)
{
    SweepState* st = (SweepState*)ctx;
    char name[256], cn[128], fs[768], title[1300];

    LdapGetStrValue(ld, entry, "displayName",    name, (int)sizeof(name));
    LdapGetStrValue(ld, entry, "cn",             cn,   (int)sizeof(cn));
    LdapGetStrValue(ld, entry, "gPCFileSysPath", fs,   (int)sizeof(fs));
    if (!name[0])
        LdapGetStrValue(ld, entry, "distinguishedName", name, (int)sizeof(name));

    if (cn[0] && name[0])
        MSVCRT$sprintf(title, "%s   {%s}", name, cn);
    else if (cn[0])
        MSVCRT$sprintf(title, "{%s}", cn);
    else
        StrCopy(title, (int)sizeof(title), name[0] ? name : "(unnamed GPO)");

    if (fs[0]) {
        if (st->gptN < MAXGPT) {
            StrCopy(st->gpt[st->gptN].guid,   (int)sizeof(st->gpt[0].guid),   cn);
            StrCopy(st->gpt[st->gptN].fsPath, (int)sizeof(st->gpt[0].fsPath), fs);
            st->gptN++;
        } else {
            st->gptOverflow = 1;
        }
    }

    GetEntrySd(st, ld, entry, SURF_GPO, title);
}

static void LinkEntryCb(void* ld, void* entry, void* ctx)
{
    SweepState* st = (SweepState*)ctx;
    char dn[1024];

    LdapGetStrValue(ld, entry, "distinguishedName", dn, (int)sizeof(dn));
    if (!dn[0]) {
        char* d = LdapEntryDn(ld, entry);
        if (d) { StrCopy(dn, (int)sizeof(dn), d); LdapFreeDn(d); }
    }
    GetEntrySd(st, ld, entry, st->surface, dn[0] ? dn : "(no DN)");
}

static void WmiEntryCb(void* ld, void* entry, void* ctx)
{
    SweepState* st = (SweepState*)ctx;
    char name[256], dn[1024], title[1300];

    LdapGetStrValue(ld, entry, "msWMI-Name", name, (int)sizeof(name));
    LdapGetStrValue(ld, entry, "distinguishedName", dn, (int)sizeof(dn));

    if (name[0] && dn[0])
        MSVCRT$sprintf(title, "%s  %s", name, dn);
    else
        StrCopy(title, (int)sizeof(title), dn[0] ? dn : (name[0] ? name : "(unnamed WMI filter)"));

    GetEntrySd(st, ld, entry, SURF_WMI, title);
}

/* ---- common surface runner ---- */

static int RunSurface(SweepState* st, LdapSession* s, int surface, const char* base,
                      int scope, const char* filter, char** attrs, LdapEntryFn cb,
                      const char* name)
{
    int tr = 0;
    int rc = LdapSearch(s, base, scope, filter, attrs, 7 /* SD flags: OWNER|GROUP|DACL */,
                        1 /* paged */, SOFT_CAP, cb, st, &tr);
    if (rc < 0) {
        if (s->lastRc == LDAP_NO_SUCH_OBJECT) {
            if (st->verbose)
                bprintf("[*] %s: container not present in this domain\n", name);
        } else {
            SurfaceHeader(st, surface);
            bprintf("[!!] %s: %s\n", name, s->err[0] ? s->err : "search failed");
        }
        return rc;
    }
    if (tr) {
        st->anyTrunc = 1;
        SurfaceHeader(st, surface);
        bprintf("[!] %s surface truncated at %d objects\n", name, SOFT_CAP);
    }
    return rc;
}

/* ---- SYSVOL GPT file DACLs ---- */

static void SysvolSweep(SweepState* st)
{
    st->surface = SURF_SYSVOL;
    for (int i = 0; i < st->gptN; i++) {
        GptItem* it = &st->gpt[i];
        DWORD  need = 0;
        char*  buf;
        char   title[900];

        ADVAPI32$GetFileSecurityA(it->fsPath, DACL_SECURITY_INFORMATION, NULL, 0, &need);
        if (need == 0) {
            SurfaceHeader(st, SURF_SYSVOL);
            bprintf("[SKIP] SYSVOL DACL not read for {%s}: win32 %lu\n",
                    it->guid[0] ? it->guid : "?", KERNEL32$GetLastError());
            continue;
        }
        buf = (char*)KERNEL32$LocalAlloc(LMEM_FIXED | LMEM_ZEROINIT_, need);
        if (!buf) continue;
        if (!ADVAPI32$GetFileSecurityA(it->fsPath, DACL_SECURITY_INFORMATION, buf, need, &need)) {
            SurfaceHeader(st, SURF_SYSVOL);
            bprintf("[SKIP] SYSVOL DACL not read for {%s}: win32 %lu\n",
                    it->guid[0] ? it->guid : "?", KERNEL32$GetLastError());
            KERNEL32$LocalFree(buf);
            continue;
        }
        st->objs[SURF_SYSVOL]++;
        StrCopy(title, (int)sizeof(title), it->fsPath);
        ProcessSd(st, SURF_SYSVOL, title, buf, it->fsPath);
        KERNEL32$LocalFree(buf);
    }
}

/* ---- main sweep ---- */

void GpresultDomainSweep(int verbose)
{
    LdapSession sess;
    SweepState  st;
    TokenSidSet toks;
    char        sam[256];
    ULONG       samN = (ULONG)sizeof(sam);

    /* zero state (no memset declared — field assigns) */
    sess.ld = NULL;
    st.verbose = verbose;
    st.toks = &toks;
    st.surface = SURF_GPO;
    st.firstForObject = 1;
    st.objTitle[0] = '\0';
    st.anyTrunc = 0;
    st.gptOverflow = 0;
    st.gpt = NULL;
    st.gptN = 0;
    for (int i = 0; i < SURF_COUNT; i++) {
        st.sectPrinted[i] = 0;
        st.objs[i] = 0;
        for (int j = 0; j < 3; j++) st.cnt[j] = 0;
    }
    for (int i = 0; i < 3; i++) st.cnt[i] = 0;

    bprintf("=== gpresult domain — GPO ACE sweep (caller token) ===\n");

    if (LdapConnect(&sess) != 0) {
        bprintf("[!!] %s\n", sess.err[0] ? sess.err : "could not reach a domain controller");
        return;
    }

    sam[0] = '\0';
    SECUR32$GetUserNameExA(NameSamCompatible, sam, &samN);

    bprintf("DC:      %s\n", sess.dc);
    bprintf("Domain:  %s  (%s)\n", sess.dnsDomain, sess.domainDN);
    if (verbose) bprintf("Config:  %s\n", sess.configDN);

    if (TokenSidsBuild(&toks) != 0) {
        bprintf("[!!] OpenProcessToken/GetTokenInformation failed — no token SIDs\n");
        LdapClose(&sess);
        return;
    }
    bprintf("Token:   %s  (%d matching SIDs)\n", sam[0] ? sam : "(unknown)", toks.count);
    if (verbose) {
        bprintf("\nToken SIDs considered:\n");
        for (int i = 0; i < toks.count; i++)
            bprintf("    - %s\n", ResolveSidName(toks.sids[i]));
    }

    /* GPT collection + section titles (need domainDN) */
    st.gpt = (GptItem*)KERNEL32$LocalAlloc(LMEM_FIXED | LMEM_ZEROINIT_, sizeof(GptItem) * MAXGPT);
    MSVCRT$sprintf(st.sectTitle[SURF_GPO], "--- GPO objects (CN=Policies,CN=System,%s) ---", sess.domainDN);
    StrCopy(st.sectTitle[SURF_SYSVOL],     (int)sizeof(st.sectTitle[0]), "--- SYSVOL DACLs (GPT) ---");
    StrCopy(st.sectTitle[SURF_DOMAINROOT], (int)sizeof(st.sectTitle[0]), "--- Domain root (gPLink) ---");
    StrCopy(st.sectTitle[SURF_OU],         (int)sizeof(st.sectTitle[0]), "--- OUs (gPLink) ---");
    StrCopy(st.sectTitle[SURF_SITE],       (int)sizeof(st.sectTitle[0]), "--- Sites (gPLink) ---");
    MSVCRT$sprintf(st.sectTitle[SURF_WMI], "--- WMI filters (CN=SOM,CN=WMIPolicy,CN=System,%s) ---", sess.domainDN);

    /* surface 1 — GPO objects */
    {
        char base[1200];
        char* attrs[] = { (char*)"cn", (char*)"displayName", (char*)"gPCFileSysPath",
                          (char*)"distinguishedName", (char*)"nTSecurityDescriptor", NULL };
        st.surface = SURF_GPO;
        MSVCRT$sprintf(base, "CN=Policies,CN=System,%s", sess.domainDN);
        RunSurface(&st, &sess, SURF_GPO, base, LDAP_SCOPE_ONELEVEL,
                   "(objectClass=groupPolicyContainer)", attrs, GpoEntryCb, "GPO objects");
    }

    /* surface 3 — domain root (gPLink) */
    {
        char* attrs[] = { (char*)"distinguishedName", (char*)"nTSecurityDescriptor", NULL };
        st.surface = SURF_DOMAINROOT;
        RunSurface(&st, &sess, SURF_DOMAINROOT, sess.domainDN, LDAP_SCOPE_BASE,
                   "(objectClass=*)", attrs, LinkEntryCb, "domain root");
    }

    /* surface 4 — OUs (subtree, paged) */
    {
        char* attrs[] = { (char*)"distinguishedName", (char*)"nTSecurityDescriptor", NULL };
        st.surface = SURF_OU;
        RunSurface(&st, &sess, SURF_OU, sess.domainDN, LDAP_SCOPE_SUBTREE,
                   "(objectClass=organizationalUnit)", attrs, LinkEntryCb, "OUs");
    }

    /* surface 5 — sites (config NC) */
    if (sess.configDN[0]) {
        char base[1200];
        char* attrs[] = { (char*)"distinguishedName", (char*)"nTSecurityDescriptor", NULL };
        st.surface = SURF_SITE;
        MSVCRT$sprintf(base, "CN=Sites,%s", sess.configDN);
        RunSurface(&st, &sess, SURF_SITE, base, LDAP_SCOPE_ONELEVEL,
                   "(objectClass=site)", attrs, LinkEntryCb, "sites");
    } else if (verbose) {
        bprintf("[*] sites: configurationNamingContext unavailable\n");
    }

    /* surface 6 — WMI filters */
    {
        char base[1200];
        char* attrs[] = { (char*)"cn", (char*)"msWMI-Name", (char*)"distinguishedName",
                          (char*)"nTSecurityDescriptor", NULL };
        st.surface = SURF_WMI;
        MSVCRT$sprintf(base, "CN=SOM,CN=WMIPolicy,CN=System,%s", sess.domainDN);
        RunSurface(&st, &sess, SURF_WMI, base, LDAP_SCOPE_ONELEVEL,
                   "(objectClass=msWMI-Som)", attrs, WmiEntryCb, "WMI filters");
    }

    /* surface 2 — SYSVOL GPT file DACLs */
    SysvolSweep(&st);

    /* summary */
    bprintf("\n");
    if (st.cnt[0] + st.cnt[1] + st.cnt[2] == 0) {
        bprintf("[=] No GPO-touching ACEs matched the caller's token\n");
    } else {
        bprintf("[=] Summary: [!] %d actionable, [+] %d write-limited, [ ] %d read-only%s\n",
                st.cnt[0], st.cnt[1], st.cnt[2],
                (st.cnt[2] && !st.verbose) ? " (hidden — rerun with -v)" : "");
    }
    if (verbose)
        bprintf("[*] objects walked: GPO %d, SYSVOL %d, domain %d, OU %d, sites %d, WMI %d\n",
                st.objs[SURF_GPO], st.objs[SURF_SYSVOL], st.objs[SURF_DOMAINROOT],
                st.objs[SURF_OU], st.objs[SURF_SITE], st.objs[SURF_WMI]);
    if (st.anyTrunc)
        bprintf("[*] one or more surfaces hit the %d-object soft cap\n", SOFT_CAP);
    if (st.gptOverflow)
        bprintf("[*] SYSVOL check capped at %d GPT paths\n", MAXGPT);

    if (st.gpt) KERNEL32$LocalFree(st.gpt);
    TokenSidsFree(&toks);
    LdapClose(&sess);
}
