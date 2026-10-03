/* crt_shim.c - BOF CRT shim.
 *
 * The Havoc/CS COFF loader resolves undefined symbols against the demon's own
 * exports (kernel32 etc.), NOT arbitrary msvcrt symbols. The engine + sqlite3
 * reference msvcrt string/memory/printf functions, so we define them here:
 *   - string/memory  -> pure C (no deps)
 *   - malloc/calloc/realloc/free, printf family, strtod, getenv, _write,
 *     _gmtime64, strftime -> resolved from msvcrt.dll at runtime
 *
 * Deliberately does NOT include <windows.h> — that transitively pulls
 * <stdlib.h>/<string.h>, whose attributed declarations (nothrow/restrict)
 * conflict with our own definitions. We declare the two Win32 entry points we
 * need by hand instead.
 *
 * Compiled into the BOF only, never the standalone exe (which links msvcrt).
 */
#include <stdarg.h>
#include <stddef.h>

typedef void *HMODULE;
__declspec(dllimport) HMODULE __stdcall LoadLibraryA(const char *);
__declspec(dllimport) void * __stdcall GetProcAddress(HMODULE, const char *);

/* ================================================================== */
/* runtime-resolved msvcrt                                              */
/* ================================================================== */
static HMODULE g_msvcrt;
static void crt_init(void) {
    if (!g_msvcrt) g_msvcrt = LoadLibraryA("msvcrt.dll");
}
static void *crt_fn(const char *name) {
    crt_init();
    return g_msvcrt ? GetProcAddress(g_msvcrt, name) : NULL;
}

/* kernel32 resolver used by k32_shim.c (sqlite3 references kernel32 functions
 * by ADDRESS, producing bare externs the COFF loader can't resolve; the shim
 * turns them into internal wrappers that forward here). */
static HMODULE g_kernel32;
void *k32_resolve(const char *name) {
    if (!g_kernel32) g_kernel32 = LoadLibraryA("kernel32.dll");
    return g_kernel32 ? GetProcAddress(g_kernel32, name) : NULL;
}

void *malloc(size_t n) {
    typedef void *(*F)(size_t); F f = (F)crt_fn("malloc"); return f ? f(n) : NULL;
}
void *calloc(size_t a, size_t b) {
    typedef void *(*F)(size_t, size_t); F f = (F)crt_fn("calloc"); return f ? f(a, b) : NULL;
}
void *realloc(void *p, size_t n) {
    typedef void *(*F)(void *, size_t); F f = (F)crt_fn("realloc"); return f ? f(p, n) : NULL;
}
void free(void *p) {
    typedef void (*F)(void *); F f = (F)crt_fn("free"); if (f) f(p);
}

int _vsnprintf(char *b, size_t n, const char *fmt, va_list ap) {
    typedef int (*F)(char *, size_t, const char *, va_list);
    F f = (F)crt_fn("_vsnprintf"); return f ? f(b, n, fmt, ap) : -1;
}
int _snprintf(char *b, size_t n, const char *fmt, ...) {
    va_list ap; int r; va_start(ap, fmt); r = _vsnprintf(b, n, fmt, ap); va_end(ap); return r;
}

double strtod(const char *s, char **end) {
    typedef double (*F)(const char *, char **);
    F f = (F)crt_fn("strtod"); return f ? f(s, end) : 0.0;
}
char *getenv(const char *n) {
    typedef char *(*F)(const char *);
    F f = (F)crt_fn("getenv"); return f ? f(n) : NULL;
}
int _write(int fd, const void *b, unsigned n) {
    typedef int (*F)(int, const void *, unsigned);
    F f = (F)crt_fn("_write"); return f ? f(fd, b, n) : -1;
}

/* ================================================================== */
/* pure C string/memory                                                 */
/* ================================================================== */
size_t strlen(const char *s) { const char *p = s; while (*p) p++; return (size_t)(p - s); }
size_t wcslen(const wchar_t *s) { const wchar_t *p = s; while (*p) p++; return (size_t)(p - s); }

int strcmp(const char *a, const char *b) {
    while (*a && *a == *b) { a++; b++; }
    return (unsigned char)*a - (unsigned char)*b;
}
int strncmp(const char *a, const char *b, size_t n) {
    while (n && *a && *a == *b) { a++; b++; n--; }
    return n ? ((unsigned char)*a - (unsigned char)*b) : 0;
}
static int ascii_tolower(int c) { return (c >= 'A' && c <= 'Z') ? c + 32 : c; }
int _stricmp(const char *a, const char *b) {
    while (*a && *b) {
        int ca = ascii_tolower((unsigned char)*a), cb = ascii_tolower((unsigned char)*b);
        if (ca != cb) return ca - cb;
        a++; b++;
    }
    return ascii_tolower((unsigned char)*a) - ascii_tolower((unsigned char)*b);
}
int _strnicmp(const char *a, const char *b, size_t n) {
    while (n && *a && *b) {
        int ca = ascii_tolower((unsigned char)*a), cb = ascii_tolower((unsigned char)*b);
        if (ca != cb) return ca - cb;
        a++; b++; n--;
    }
    return n ? (ascii_tolower((unsigned char)*a) - ascii_tolower((unsigned char)*b)) : 0;
}

char *strchr(const char *s, int c) {
    while (*s) { if (*s == (char)c) return (char *)s; s++; }
    return c == 0 ? (char *)s : NULL;
}
char *strrchr(const char *s, int c) {
    const char *r = NULL;
    while (*s) { if (*s == (char)c) r = s; s++; }
    return (char *)r;
}
size_t strspn(const char *s, const char *set) {
    const char *p = s; while (*p && strchr(set, *p)) p++; return (size_t)(p - s);
}
size_t strcspn(const char *s, const char *set) {
    const char *p = s; while (*p && !strchr(set, *p)) p++; return (size_t)(p - s);
}

void *memchr(const void *s, int c, size_t n) {
    const unsigned char *p = (const unsigned char *)s;
    while (n--) { if (*p == (unsigned char)c) return (void *)p; p++; }
    return NULL;
}
int memcmp(const void *a, const void *b, size_t n) {
    const unsigned char *x = (const unsigned char *)a, *y = (const unsigned char *)b;
    while (n--) { if (*x != *y) return *x - *y; x++; y++; }
    return 0;
}
void *memcpy(void *d, const void *s, size_t n) {
    unsigned char *dd = (unsigned char *)d; const unsigned char *ss = (const unsigned char *)s;
    while (n--) *dd++ = *ss++;
    return d;
}
void *memmove(void *d, const void *s, size_t n) {
    unsigned char *dd = (unsigned char *)d; const unsigned char *ss = (const unsigned char *)s;
    if (dd < ss) { while (n--) *dd++ = *ss++; }
    else { dd += n; ss += n; while (n--) *--dd = *--ss; }
    return d;
}
void *memset(void *d, int c, size_t n) {
    unsigned char *dd = (unsigned char *)d;
    while (n--) *dd++ = (unsigned char)c;
    return d;
}

/* ================================================================== */
/* time stubs (sqlite datetime is compiled out via SQLITE_OMIT_*)       */
/* ================================================================== */
struct tm { int tm_sec, tm_min, tm_hour, tm_mday, tm_mon, tm_year, tm_wday, tm_yday, tm_isdst; };
struct tm *_gmtime64(const long long *timer) { (void)timer; return (struct tm *)0; }
struct tm *_gmtime32(const long *timer) { (void)timer; return (struct tm *)0; }
size_t strftime(char *s, size_t max, const char *fmt, const struct tm *t) {
    (void)fmt; (void)t;
    if (s && max) s[0] = 0;
    return 0;
}

/* ================================================================== */
/* libgcc 64-bit division helpers (x86 only; x64 uses native insns)     */
/* sqlite3 + the engine do 64-bit arithmetic, which on i686 emits calls  */
/* to __divdi3/__moddi3/__udivdi3/... that the COFF loader can't resolve.*/
/* Implement them without any 64-bit / or % so we don't recurse.         */
/* ================================================================== */
typedef unsigned long long u64;
typedef long long s64;

static u64 sh_udivmod(u64 n, u64 d, u64 *r) {
    u64 q = 0, rem = 0;
    int i;
    if (d == 0) { if (r) *r = n; return 0; }
    for (i = 63; i >= 0; i--) {
        rem = (rem << 1) | ((n >> i) & 1u);
        if (rem >= d) { rem -= d; q |= ((u64)1) << i; }
    }
    if (r) *r = rem;
    return q;
}
static u64 sh_abs(s64 x) {
    u64 u = (u64)x;
    return (x < 0) ? ((u64)0 - u) : u;
}
u64 __udivmoddi4(u64 n, u64 d, u64 *r) { return sh_udivmod(n, d, r); }
u64 __udivdi3(u64 n, u64 d) { return sh_udivmod(n, d, NULL); }
u64 __umoddi3(u64 n, u64 d) { u64 r; (void)sh_udivmod(n, d, &r); return r; }
s64 __divdi3(s64 n, s64 d) {
    int neg = (n < 0) ^ (d < 0);
    u64 q = sh_udivmod(sh_abs(n), sh_abs(d), NULL);
    return neg ? (s64)((u64)0 - q) : (s64)q;
}
s64 __moddi3(s64 n, s64 d) {
    u64 r;
    (void)sh_udivmod(sh_abs(n), sh_abs(d), &r);
    return (n < 0) ? (s64)((u64)0 - r) : (s64)r;
}
s64 __divmoddi4(s64 n, s64 d, s64 *r) {
    int negn = (n < 0), negd = (d < 0);
    u64 rem;
    u64 q = sh_udivmod(sh_abs(n), sh_abs(d), &rem);
    if (r) *r = negn ? (s64)((u64)0 - rem) : (s64)rem;
    return (negn ^ negd) ? (s64)((u64)0 - q) : (s64)q;
}
