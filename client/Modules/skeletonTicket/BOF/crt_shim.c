/*
 * crt_shim.c — self-contained CRT for the BOF port.
 *
 * mimikatz is written for MSVC and assumes the MSVCRT secure/wchar CRT. A BOF
 * must not depend on the loader resolving arbitrary msvcrt symbols, so we:
 *   1. implement string/memory/ctype functions in pure C, and
 *   2. resolve the printf family (and malloc/free) from msvcrt.dll at runtime
 *      via GetModuleHandle/GetProcAddress (kernel32, always resolvable), and
 *   3. implement a minimal secure scanf() covering the formats mimikatz uses
 *      (%d %i %u %x %o %hu %02x %s %[...] %c + literal separators).
 *
 * bof_compat.h defines _CRTIMP/_SECIMP empty so all of these are plain
 * references that link against this file.
 */
#include <windows.h>
#include <stdarg.h>
#include <stddef.h>

/* ================================================================== */
/* runtime-resolved MSVCRT                                              */
/* ================================================================== */
typedef int  (__cdecl *pfn_vscwprintf)(const wchar_t*, va_list);
typedef int  (__cdecl *pfn_vscprintf)(const char*, va_list);
typedef int  (__cdecl *pfn_vsnwprintf)(wchar_t*, size_t, const wchar_t*, va_list);
typedef int  (__cdecl *pfn_vsnprintf)(char*, size_t, const char*, va_list);
typedef int  (__cdecl *pfn_vsprintf)(char*, const char*, va_list);
typedef int  (__cdecl *pfn_vswprintf)(wchar_t*, const wchar_t*, va_list);
typedef int  (__cdecl *pfn_vswprintf_s)(wchar_t*, size_t, const wchar_t*, va_list);
typedef int  (__cdecl *pfn_vsprintf_s)(char*, size_t, const char*, va_list);
typedef void*(__cdecl *pfn_malloc)(size_t);
typedef void*(__cdecl *pfn_calloc)(size_t, size_t);
typedef void*(__cdecl *pfn_realloc)(void*, size_t);
typedef void (__cdecl *pfn_free)(void*);
typedef double (__cdecl *pfn_log)(double);

static HMODULE g_msvcrt;
static int     g_msvcrt_init;
static pfn_vscwprintf  p_vscwprintf;
static pfn_vscprintf   p_vscprintf;
static pfn_vsnwprintf  p_vsnwprintf;
static pfn_vsnprintf   p_vsnprintf;
static pfn_vsprintf    p_vsprintf;
static pfn_vswprintf   p_vswprintf;
static pfn_vswprintf_s p_vswprintf_s;
static pfn_vsprintf_s  p_vsprintf_s;
static pfn_malloc      p_malloc;
static pfn_calloc      p_calloc;
static pfn_realloc     p_realloc;
static pfn_free        p_free;
static pfn_log         p_log;

static void crt_resolve(void) {
    if (g_msvcrt_init) return;
    g_msvcrt = GetModuleHandleA("msvcrt.dll");
    if (!g_msvcrt) g_msvcrt = LoadLibraryA("msvcrt.dll");
    p_vscwprintf  = (pfn_vscwprintf) GetProcAddress(g_msvcrt, "_vscwprintf");
    p_vscprintf   = (pfn_vscprintf)  GetProcAddress(g_msvcrt, "_vscprintf");
    p_vsnwprintf  = (pfn_vsnwprintf) GetProcAddress(g_msvcrt, "_vsnwprintf");
    p_vsnprintf   = (pfn_vsnprintf)  GetProcAddress(g_msvcrt, "_vsnprintf");
    p_vsprintf    = (pfn_vsprintf)   GetProcAddress(g_msvcrt, "vsprintf");
    p_vswprintf   = (pfn_vswprintf)  GetProcAddress(g_msvcrt, "vswprintf");
    p_vswprintf_s = (pfn_vswprintf_s)GetProcAddress(g_msvcrt, "vswprintf_s");
    p_vsprintf_s  = (pfn_vsprintf_s) GetProcAddress(g_msvcrt, "vsprintf_s");
    p_malloc      = (pfn_malloc)     GetProcAddress(g_msvcrt, "malloc");
    p_calloc      = (pfn_calloc)     GetProcAddress(g_msvcrt, "calloc");
    p_realloc     = (pfn_realloc)    GetProcAddress(g_msvcrt, "realloc");
    p_free        = (pfn_free)       GetProcAddress(g_msvcrt, "free");
    p_log         = (pfn_log)        GetProcAddress(g_msvcrt, "log");
    g_msvcrt_init = 1;
}

/* ---- va_list printf wrappers --------------------------------------- */
int __cdecl _vscwprintf(const wchar_t* fmt, va_list ap) { crt_resolve(); return p_vscwprintf(fmt, ap); }
int __cdecl _vscprintf(const char* fmt, va_list ap)    { crt_resolve(); return p_vscprintf(fmt, ap); }
int __cdecl _vsnwprintf(wchar_t* b, size_t n, const wchar_t* fmt, va_list ap) { crt_resolve(); return p_vsnwprintf(b, n, fmt, ap); }
int __cdecl _vsnprintf(char* b, size_t n, const char* fmt, va_list ap)        { crt_resolve(); return p_vsnprintf(b, n, fmt, ap); }
int __cdecl vsprintf(char* b, const char* fmt, va_list ap)                    { crt_resolve(); return p_vsprintf(b, fmt, ap); }
int __cdecl vswprintf(wchar_t* b, const wchar_t* fmt, va_list ap)             { crt_resolve(); return p_vswprintf(b, fmt, ap); }
int __cdecl vswprintf_s(wchar_t* b, size_t n, const wchar_t* fmt, va_list ap) { crt_resolve(); return p_vswprintf_s(b, n, fmt, ap); }
int __cdecl vsprintf_s(char* b, size_t n, const char* fmt, va_list ap)        { crt_resolve(); return p_vsprintf_s(b, n, fmt, ap); }

/* ---- variadic printf wrappers --------------------------------------- */
int __cdecl sprintf(char* b, const char* fmt, ...) {
    va_list ap; int r; crt_resolve();
    va_start(ap, fmt); r = p_vsprintf(b, fmt, ap); va_end(ap); return r;
}
int __cdecl _snprintf(char* b, size_t n, const char* fmt, ...) {
    va_list ap; int r; crt_resolve();
    va_start(ap, fmt); r = p_vsnprintf(b, n, fmt, ap); va_end(ap); return r;
}
int __cdecl snprintf(char* b, size_t n, const char* fmt, ...) {
    va_list ap; int r; crt_resolve();
    va_start(ap, fmt); r = p_vsnprintf(b, n, fmt, ap); va_end(ap); return r;
}
int __cdecl _snwprintf(wchar_t* b, size_t n, const wchar_t* fmt, ...) {
    va_list ap; int r; crt_resolve();
    va_start(ap, fmt); r = p_vsnwprintf(b, n, fmt, ap); va_end(ap); return r;
}
int __cdecl swprintf(wchar_t* b, const wchar_t* fmt, ...) {
    va_list ap; int r; crt_resolve();
    va_start(ap, fmt); r = p_vswprintf(b, fmt, ap); va_end(ap); return r;
}
int __cdecl swprintf_s(wchar_t* b, size_t n, const wchar_t* fmt, ...) {
    va_list ap; int r; crt_resolve();
    va_start(ap, fmt); r = p_vswprintf_s(b, n, fmt, ap); va_end(ap); return r;
}
int __cdecl sprintf_s(char* b, size_t n, const char* fmt, ...) {
    va_list ap; int r; crt_resolve();
    va_start(ap, fmt); r = p_vsprintf_s(b, n, fmt, ap); va_end(ap); return r;
}

/* ---- heap ----------------------------------------------------------- */
void* __cdecl malloc(size_t n)          { crt_resolve(); return p_malloc(n); }
void* __cdecl calloc(size_t c, size_t n){ crt_resolve(); return p_calloc(c, n); }
void* __cdecl realloc(void* p, size_t n){ crt_resolve(); return p_realloc(p, n); }
void  __cdecl free(void* p)             { crt_resolve(); p_free(p); }
double __cdecl log(double x)             { crt_resolve(); return p_log(x); }

/* ================================================================== */
/* minimal scanf (wide + narrow)                                       */
/* ================================================================== */
static int ctype_iswspace(int c) { return c == L' ' || c == L'\t' || c == L'\n' || c == L'\r' || c == L'\v' || c == L'\f'; }
static int ctype_isspace(char c) { return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\v' || c == '\f'; }
static int ctype_wdigitval(wchar_t c) {
    if (c >= L'0' && c <= L'9') return c - L'0';
    if (c >= L'a' && c <= L'f') return c - L'a' + 10;
    if (c >= L'A' && c <= L'F') return c - L'A' + 10;
    return -1;
}
static int ctype_digitval(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* wide scan core; `secure` consumes a rsize_t after each %s/%[/%c pointer */
static int vswscanf_core(const wchar_t* str, const wchar_t* fmt, va_list ap, int secure) {
    const wchar_t* s = str;
    int count = 0;
    while (*fmt) {
        if (ctype_iswspace(*fmt)) {
            while (ctype_iswspace(*fmt)) fmt++;
            while (*s && ctype_iswspace(*s)) s++;
            continue;
        }
        if (*fmt != L'%') {
            if (*s != *fmt) return count;
            s++; fmt++; continue;
        }
        fmt++;
        if (*fmt == L'%') { if (*s == L'%') s++; else return count; fmt++; continue; }
        {
            int suppress = 0, width = 0, len = 0, base = 0, sign = 1, any = 0;
            if (*fmt == L'*') { suppress = 1; fmt++; }
            while (*fmt >= L'0' && *fmt <= L'9') { width = width * 10 + (*fmt - L'0'); fmt++; }
            if (*fmt == L'h') { len = (fmt[1] == L'h') ? 1 : 2; fmt += (fmt[1] == L'h') ? 2 : 1; }
            else if (*fmt == L'l') { len = (fmt[1] == L'l') ? 4 : 3; fmt += (fmt[1] == L'l') ? 2 : 1; }

            if (*fmt == L'c') {
                wchar_t* dst = suppress ? NULL : (wchar_t*)va_arg(ap, wchar_t*);
                if (secure) va_arg(ap, size_t);
                if (width == 0) width = 1;
                while (width-- && *s) { if (dst) *dst++ = *s; s++; }
                if (!suppress) count++;
                fmt++;
            }
            else if (*fmt == L's' || *fmt == L'[') {
                wchar_t* dst = suppress ? NULL : (wchar_t*)va_arg(ap, wchar_t*);
                if (secure) va_arg(ap, size_t);
                if (*fmt == L's') { while (*s && ctype_iswspace(*s)) s++; }
                else {
                    int negate = 0; wchar_t set[128]; int ns = 0, k, in;
                    if (fmt[1] == L'^') { negate = 1; fmt++; }
                    fmt++;
                    while (*fmt && *fmt != L']' && ns < 127) set[ns++] = *fmt++;
                    if (*fmt == L']') fmt++;
                    while (*s && (!width || width-- > 0)) {
                        in = 0;
                        for (k = 0; k < ns; k++) if (set[k] == *s) { in = 1; break; }
                        if (negate ? in : !in) break;
                        if (dst) *dst++ = *s;
                        s++;
                    }
                    if (dst) *dst = 0;
                    if (!suppress) count++;
                    fmt++;
                    continue;
                }
                {
                    int limit = width ? width : 1000000;
                    while (*s && !ctype_iswspace(*s) && limit-- > 0) { if (dst) *dst++ = *s; s++; }
                    if (dst) *dst = 0;
                    if (!suppress) count++;
                }
                fmt++;
            }
            else if (*fmt == L'd' || *fmt == L'i' || *fmt == L'u' || *fmt == L'o' || *fmt == L'x' || *fmt == L'X') {
                while (*s && ctype_iswspace(*s)) s++;
                if (*s == L'+' || *s == L'-') { if (*s == L'-') sign = -1; s++; }
                base = (*fmt == L'o') ? 8 : (*fmt == L'x' || *fmt == L'X') ? 16 : 10;
                if (*fmt == L'i') {
                    if (*s == L'0' && (s[1] == L'x' || s[1] == L'X')) base = 16;
                    else if (*s == L'0') base = 8;
                    else base = 10;
                }
                if (base == 16 && *s == L'0' && (s[1] == L'x' || s[1] == L'X')) s += 2;
                {
                    unsigned long long val = 0; int cnt = width ? width : 64, d;
                    while (cnt-- > 0 && *s) {
                        d = ctype_wdigitval(*s);
                        if (d < 0 || d >= base) break;
                        val = val * base + (unsigned)d; any = 1; s++;
                    }
                    if (!any) return count;
                    if (!suppress) {
                        unsigned long long sv = sign < 0 ? (0ULL - val) : val;
                        if (len == 1) *va_arg(ap, signed char*) = (signed char)sv;
                        else if (len == 2) *va_arg(ap, short*) = (short)sv;
                        else if (len == 3) *va_arg(ap, long*) = (long)sv;
                        else if (len == 4) *va_arg(ap, long long*) = (long long)sv;
                        else if (*fmt == L'u' || *fmt == L'o' || *fmt == L'x' || *fmt == L'X')
                            *va_arg(ap, unsigned int*) = (unsigned int)val;
                        else *va_arg(ap, int*) = (int)sv;
                    }
                    count++;
                }
                fmt++;
            }
            else {
                /* unknown specifier — bail */
                return count;
            }
        }
    }
    return count;
}

static int vsscanf_core(const char* str, const char* fmt, va_list ap, int secure) {
    const char* s = str;
    int count = 0;
    while (*fmt) {
        if (ctype_isspace(*fmt)) { while (ctype_isspace(*fmt)) fmt++; while (*s && ctype_isspace(*s)) s++; continue; }
        if (*fmt != '%') { if (*s != *fmt) return count; s++; fmt++; continue; }
        fmt++;
        if (*fmt == '%') { if (*s == '%') s++; else return count; fmt++; continue; }
        {
            int suppress = 0, width = 0, len = 0, base = 0, sign = 1, any = 0;
            if (*fmt == '*') { suppress = 1; fmt++; }
            while (*fmt >= '0' && *fmt <= '9') { width = width * 10 + (*fmt - '0'); fmt++; }
            if (*fmt == 'h') { len = (fmt[1] == 'h') ? 1 : 2; fmt += (fmt[1] == 'h') ? 2 : 1; }
            else if (*fmt == 'l') { len = (fmt[1] == 'l') ? 4 : 3; fmt += (fmt[1] == 'l') ? 2 : 1; }

            if (*fmt == 'c') {
                char* dst = suppress ? NULL : (char*)va_arg(ap, char*);
                if (secure) va_arg(ap, size_t);
                if (width == 0) width = 1;
                while (width-- && *s) { if (dst) *dst++ = *s; s++; }
                if (!suppress) count++;
                fmt++;
            }
            else if (*fmt == 's' || *fmt == '[') {
                char* dst = suppress ? NULL : (char*)va_arg(ap, char*);
                if (secure) va_arg(ap, size_t);
                if (*fmt == 's') { while (*s && ctype_isspace(*s)) s++; }
                else {
                    int negate = 0; char set[128]; int ns = 0, k, in;
                    if (fmt[1] == '^') { negate = 1; fmt++; }
                    fmt++;
                    while (*fmt && *fmt != ']' && ns < 127) set[ns++] = *fmt++;
                    if (*fmt == ']') fmt++;
                    while (*s && (!width || width-- > 0)) {
                        in = 0;
                        for (k = 0; k < ns; k++) if (set[k] == *s) { in = 1; break; }
                        if (negate ? in : !in) break;
                        if (dst) *dst++ = *s;
                        s++;
                    }
                    if (dst) *dst = 0;
                    if (!suppress) count++;
                    fmt++;
                    continue;
                }
                {
                    int limit = width ? width : 1000000;
                    while (*s && !ctype_isspace(*s) && limit-- > 0) { if (dst) *dst++ = *s; s++; }
                    if (dst) *dst = 0;
                    if (!suppress) count++;
                }
                fmt++;
            }
            else if (*fmt == 'd' || *fmt == 'i' || *fmt == 'u' || *fmt == 'o' || *fmt == 'x' || *fmt == 'X') {
                while (*s && ctype_isspace(*s)) s++;
                if (*s == '+' || *s == '-') { if (*s == '-') sign = -1; s++; }
                base = (*fmt == 'o') ? 8 : (*fmt == 'x' || *fmt == 'X') ? 16 : 10;
                if (*fmt == 'i') {
                    if (*s == '0' && (s[1] == 'x' || s[1] == 'X')) base = 16;
                    else if (*s == '0') base = 8;
                    else base = 10;
                }
                if (base == 16 && *s == '0' && (s[1] == 'x' || s[1] == 'X')) s += 2;
                {
                    unsigned long long val = 0; int cnt = width ? width : 64, d;
                    while (cnt-- > 0 && *s) {
                        d = ctype_digitval(*s);
                        if (d < 0 || d >= base) break;
                        val = val * base + (unsigned)d; any = 1; s++;
                    }
                    if (!any) return count;
                    if (!suppress) {
                        unsigned long long sv = sign < 0 ? (0ULL - val) : val;
                        if (len == 1) *va_arg(ap, signed char*) = (signed char)sv;
                        else if (len == 2) *va_arg(ap, short*) = (short)sv;
                        else if (len == 3) *va_arg(ap, long*) = (long)sv;
                        else if (len == 4) *va_arg(ap, long long*) = (long long)sv;
                        else if (*fmt == 'u' || *fmt == 'o' || *fmt == 'x' || *fmt == 'X')
                            *va_arg(ap, unsigned int*) = (unsigned int)val;
                        else *va_arg(ap, int*) = (int)sv;
                    }
                    count++;
                }
                fmt++;
            }
            else return count;
        }
    }
    return count;
}

int __cdecl swscanf(const wchar_t* str, const wchar_t* fmt, ...) {
    va_list ap; int r; va_start(ap, fmt); r = vswscanf_core(str, fmt, ap, 0); va_end(ap); return r;
}
int __cdecl swscanf_s(const wchar_t* str, const wchar_t* fmt, ...) {
    va_list ap; int r; va_start(ap, fmt); r = vswscanf_core(str, fmt, ap, 1); va_end(ap); return r;
}
int __cdecl sscanf(const char* str, const char* fmt, ...) {
    va_list ap; int r; va_start(ap, fmt); r = vsscanf_core(str, fmt, ap, 0); va_end(ap); return r;
}
int __cdecl sscanf_s(const char* str, const char* fmt, ...) {
    va_list ap; int r; va_start(ap, fmt); r = vsscanf_core(str, fmt, ap, 1); va_end(ap); return r;
}

/* ================================================================== */
/* memory                                                             */
/* ================================================================== */
void* __cdecl memcpy(void* d, const void* s, size_t n) { unsigned char* p = d; const unsigned char* q = s; while (n--) *p++ = *q++; return d; }
void* __cdecl memmove(void* d, const void* s, size_t n) {
    unsigned char* p = d; const unsigned char* q = s;
    if (p < q) { while (n--) *p++ = *q++; } else { p += n; q += n; while (n--) *--p = *--q; }
    return d;
}
void* __cdecl memset(void* d, int c, size_t n) { unsigned char* p = d; while (n--) *p++ = (unsigned char)c; return d; }
int   __cdecl memcmp(const void* a, const void* b, size_t n) {
    const unsigned char* x = a; const unsigned char* y = b; while (n--) { if (*x != *y) return *x - *y; x++; y++; } return 0;
}
void* __cdecl memchr(const void* s, int c, size_t n) { const unsigned char* p = s; while (n--) { if (*p == (unsigned char)c) return (void*)p; p++; } return NULL; }

/* ================================================================== */
/* narrow strings                                                     */
/* ================================================================== */
size_t __cdecl strlen(const char* s) { const char* p = s; while (*p) p++; return (size_t)(p - s); }
char*  __cdecl strcpy(char* d, const char* s) { char* r = d; while ((*d++ = *s++)); return r; }
char*  __cdecl strncpy(char* d, const char* s, size_t n) { size_t i = 0; while (i < n && s[i]) { d[i] = s[i]; i++; } while (i < n) d[i++] = 0; return d; }
char*  __cdecl strcat(char* d, const char* s) { char* r = d; while (*d) d++; while ((*d++ = *s++)); return r; }
char*  __cdecl strncat(char* d, const char* s, size_t n) { char* r = d; while (*d) d++; while (n-- && *s) *d++ = *s++; *d = 0; return r; }
int    __cdecl strcmp(const char* a, const char* b) { while (*a && *a == *b) { a++; b++; } return (unsigned char)*a - (unsigned char)*b; }
int    __cdecl strncmp(const char* a, const char* b, size_t n) { while (n && *a && *a == *b) { a++; b++; n--; } return n ? (unsigned char)*a - (unsigned char)*b : 0; }
int    __cdecl _stricmp(const char* a, const char* b) {
    unsigned char ca, cb;
    while (*a && *b) { ca = (unsigned char)*a; cb = (unsigned char)*b; if (ca >= 'A' && ca <= 'Z') ca += 32; if (cb >= 'A' && cb <= 'Z') cb += 32; if (ca != cb) return ca - cb; a++; b++; }
    return (unsigned char)*a - (unsigned char)*b;
}
int    __cdecl _strnicmp(const char* a, const char* b, size_t n) {
    unsigned char ca, cb;
    while (n--) {
        ca = (unsigned char)*a; cb = (unsigned char)*b;
        if (ca >= 'A' && ca <= 'Z') ca += 32;
        if (cb >= 'A' && cb <= 'Z') cb += 32;
        if (ca != cb || !ca) return ca - cb;
        a++; b++;
    }
    return 0;
}
char*  __cdecl strchr(const char* s, int c) { while (*s) { if (*s == (char)c) return (char*)s; s++; } return c == 0 ? (char*)s : NULL; }
char*  __cdecl strrchr(const char* s, int c) { const char* last = NULL; while (*s) { if (*s == (char)c) last = s; s++; } return c == 0 ? (char*)s : (char*)last; }
char*  __cdecl strstr(const char* h, const char* n) { size_t nl = strlen(n); if (!nl) return (char*)h; for (; *h; h++) if (*h == *n && !strncmp(h, n, nl)) return (char*)h; return NULL; }
char*  __cdecl strdup(const char* s) { size_t n = strlen(s) + 1; char* p = (char*)malloc(n); if (p) memcpy(p, s, n); return p; }
char*  __cdecl _strdup(const char* s) { return strdup(s); }
char*  __cdecl strtok(char* s, const char* delim) {
    static char* saved;
    char* tok;
    if (s) saved = s;
    if (!saved) return NULL;
    while (*saved && strchr(delim, *saved)) saved++;
    if (!*saved) { saved = NULL; return NULL; }
    tok = saved;
    while (*saved && !strchr(delim, *saved)) saved++;
    if (*saved) *saved++ = 0;
    return tok;
}
long  __cdecl strtol(const char* s, char** end, int base) {
    unsigned long v = strtoul(s, end, base);
    return (long)v;
}
unsigned long __cdecl strtoul(const char* s, char** end, int base) {
    unsigned long v = 0; int sign = 1, any = 0, d;
    while (*s == ' ' || *s == '\t' || *s == '\n') s++;
    if (*s == '+' || *s == '-') { if (*s == '-') sign = -1; s++; }
    if (base == 0) base = (*s == '0') ? ((s[1] == 'x' || s[1] == 'X') ? 16 : 8) : 10;
    if (base == 16 && *s == '0' && (s[1] == 'x' || s[1] == 'X')) s += 2;
    while (*s) { d = ctype_digitval(*s); if (d < 0 || d >= base) break; v = v * base + (unsigned)d; any = 1; s++; }
    if (end) *end = (char*)s;
    (void)any;
    return sign < 0 ? (0UL - v) : v;
}
long long __cdecl strtoll(const char* s, char** end, int base) {
    unsigned long long v = strtoull(s, end, base);
    return (long long)v;
}
unsigned long long __cdecl strtoull(const char* s, char** end, int base) {
    unsigned long long v = 0; int sign = 1, d;
    while (*s == ' ' || *s == '\t' || *s == '\n') s++;
    if (*s == '+' || *s == '-') { if (*s == '-') sign = -1; s++; }
    if (base == 0) base = (*s == '0') ? ((s[1] == 'x' || s[1] == 'X') ? 16 : 8) : 10;
    if (base == 16 && *s == '0' && (s[1] == 'x' || s[1] == 'X')) s += 2;
    while (*s) { d = ctype_digitval(*s); if (d < 0 || d >= base) break; v = v * base + (unsigned)d; s++; }
    if (end) *end = (char*)s;
    return sign < 0 ? (0ULL - v) : v;
}
int __cdecl atoi(const char* s) { return (int)strtol(s, NULL, 10); }
long __cdecl atol(const char* s) { return strtol(s, NULL, 10); }

/* ================================================================== */
/* wide strings                                                       */
/* ================================================================== */
size_t __cdecl wcslen(const wchar_t* s) { const wchar_t* p = s; while (*p) p++; return (size_t)(p - s); }
wchar_t* __cdecl wcscpy(wchar_t* d, const wchar_t* s) { wchar_t* r = d; while ((*d++ = *s++)); return r; }
wchar_t* __cdecl wcsncpy(wchar_t* d, const wchar_t* s, size_t n) { size_t i = 0; while (i < n && s[i]) { d[i] = s[i]; i++; } while (i < n) d[i++] = 0; return d; }
wchar_t* __cdecl wcscat(wchar_t* d, const wchar_t* s) { wchar_t* r = d; while (*d) d++; while ((*d++ = *s++)); return r; }
wchar_t* __cdecl wcsncat(wchar_t* d, const wchar_t* s, size_t n) { wchar_t* r = d; while (*d) d++; while (n-- && *s) *d++ = *s++; *d = 0; return r; }
int __cdecl wcscmp(const wchar_t* a, const wchar_t* b) { while (*a && *a == *b) { a++; b++; } return (int)(*a - *b); }
int __cdecl wcsncmp(const wchar_t* a, const wchar_t* b, size_t n) { while (n && *a && *a == *b) { a++; b++; n--; } return n ? (int)(*a - *b) : 0; }
int __cdecl _wcsicmp(const wchar_t* a, const wchar_t* b) {
    wchar_t ca, cb;
    while (*a && *b) {
        ca = *a; cb = *b;
        if (ca >= L'A' && ca <= L'Z') ca += 32; if (cb >= L'A' && cb <= L'Z') cb += 32;
        if (ca >= 0xC0 && ca <= 0xDE && ca != 0xD7) ca += 32;
        if (cb >= 0xC0 && cb <= 0xDE && cb != 0xD7) cb += 32;
        if (ca != cb) return (int)(ca - cb); a++; b++;
    }
    return (int)(*a - *b);
}
int __cdecl _wcsnicmp(const wchar_t* a, const wchar_t* b, size_t n) {
    wchar_t ca, cb;
    while (n--) {
        ca = *a; cb = *b;
        if (ca >= L'A' && ca <= L'Z') ca += 32;
        if (cb >= L'A' && cb <= L'Z') cb += 32;
        if (ca >= 0xC0 && ca <= 0xDE && ca != 0xD7) ca += 32;
        if (cb >= 0xC0 && cb <= 0xDE && cb != 0xD7) cb += 32;
        if (ca != cb || !ca) return (int)(ca - cb);
        a++; b++;
    }
    return 0;
}
wchar_t* __cdecl wcschr(const wchar_t* s, wchar_t c) { while (*s) { if (*s == c) return (wchar_t*)s; s++; } return c == 0 ? (wchar_t*)s : NULL; }
wchar_t* __cdecl wcsrchr(const wchar_t* s, wchar_t c) { const wchar_t* last = NULL; while (*s) { if (*s == c) last = s; s++; } return c == 0 ? (wchar_t*)s : (wchar_t*)last; }
wchar_t* __cdecl wcsstr(const wchar_t* h, const wchar_t* n) { size_t nl = wcslen(n); if (!nl) return (wchar_t*)h; for (; *h; h++) if (*h == *n && !wcsncmp(h, n, nl)) return (wchar_t*)h; return NULL; }
wchar_t* __cdecl wcsdup(const wchar_t* s) { size_t n = (wcslen(s) + 1) * sizeof(wchar_t); wchar_t* p = (wchar_t*)malloc(n); if (p) memcpy(p, s, n); return p; }
wchar_t* __cdecl _wcsdup(const wchar_t* s) { return wcsdup(s); }
size_t __cdecl wcscspn(const wchar_t* s, const wchar_t* reject) {
    const wchar_t* p = s; while (*p) { if (wcschr(reject, *p)) break; p++; } return (size_t)(p - s);
}
size_t __cdecl wcsspn(const wchar_t* s, const wchar_t* accept) {
    const wchar_t* p = s; while (*p) { if (!wcschr(accept, *p)) break; p++; } return (size_t)(p - s);
}
wchar_t* __cdecl wcspbrk(const wchar_t* s, const wchar_t* accept) { while (*s) { if (wcschr(accept, *s)) return (wchar_t*)s; s++; } return NULL; }
/* wcstok omitted: mingw declares the C99 3-arg form, mimikatz does not use it */
unsigned long __cdecl wcstoul(const wchar_t* s, wchar_t** end, int base) {
    unsigned long v = 0; int sign = 1, d;
    while (*s == L' ' || *s == L'\t' || *s == L'\n') s++;
    if (*s == L'+' || *s == L'-') { if (*s == L'-') sign = -1; s++; }
    if (base == 0) base = (*s == L'0') ? ((s[1] == L'x' || s[1] == L'X') ? 16 : 8) : 10;
    if (base == 16 && *s == L'0' && (s[1] == L'x' || s[1] == L'X')) s += 2;
    while (*s) { d = ctype_wdigitval(*s); if (d < 0 || d >= base) break; v = v * base + (unsigned)d; s++; }
    if (end) *end = (wchar_t*)s;
    return sign < 0 ? (0UL - v) : v;
}
long __cdecl wcstol(const wchar_t* s, wchar_t** end, int base) { return (long)wcstoul(s, end, base); }
unsigned long long __cdecl wcstoull(const wchar_t* s, wchar_t** end, int base) {
    unsigned long long v = 0; int sign = 1, d;
    while (*s == L' ' || *s == L'\t' || *s == L'\n') s++;
    if (*s == L'+' || *s == L'-') { if (*s == L'-') sign = -1; s++; }
    if (base == 0) base = (*s == L'0') ? ((s[1] == L'x' || s[1] == L'X') ? 16 : 8) : 10;
    if (base == 16 && *s == L'0' && (s[1] == L'x' || s[1] == L'X')) s += 2;
    while (*s) { d = ctype_wdigitval(*s); if (d < 0 || d >= base) break; v = v * base + (unsigned)d; s++; }
    if (end) *end = (wchar_t*)s;
    return sign < 0 ? (0ULL - v) : v;
}
long long __cdecl wcstoll(const wchar_t* s, wchar_t** end, int base) { return (long long)wcstoull(s, end, base); }
int __cdecl _wtoi(const wchar_t* s) { return (int)wcstol(s, NULL, 10); }
long __cdecl _wtol(const wchar_t* s) { return wcstol(s, NULL, 10); }

/* ================================================================== */
/* ctype                                                              */
/* ================================================================== */
int __cdecl tolower(int c) { return (c >= 'A' && c <= 'Z') ? c + 32 : c; }
int __cdecl toupper(int c) { return (c >= 'a' && c <= 'z') ? c - 32 : c; }
int __cdecl isdigit(int c) { return (c >= '0' && c <= '9'); }
int __cdecl isspace(int c) { return (c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\v' || c == '\f'); }
int __cdecl isalpha(int c) { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'); }
int __cdecl isalnum(int c) { return isalpha(c) || isdigit(c); }
int __cdecl isxdigit(int c) { return isdigit(c) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'); }
int __cdecl isprint(int c) { return (c >= 0x20 && c <= 0x7e); }

wint_t __cdecl towupper(wint_t c) { return (c >= L'a' && c <= L'z') ? c - 32 : c; }
wint_t __cdecl towlower(wint_t c) { return (c >= L'A' && c <= L'Z') ? c + 32 : c; }

/* isw* are macros expanding to iswctype(); provide the real workhorse. */
int __cdecl iswctype(wint_t c, wctype_t type) {
    int props = 0;
    if (c >= L'A' && c <= L'Z') { props |= _UPPER | 0x0100; if (c <= L'F') props |= _HEX; }
    else if (c >= L'a' && c <= L'z') { props |= _LOWER | 0x0100; if (c <= L'f') props |= _HEX; }
    else if (c >= L'0' && c <= L'9') { props |= _DIGIT | _HEX; }
    else if (c == L' ' || c == L'\t' || c == L'\n' || c == L'\r' || c == L'\v' || c == L'\f') { props |= _SPACE; if (c == L' ' || c == L'\t') props |= _BLANK; }
    else if (c < 0x20 || c == 0x7f) { props |= _CONTROL; }
    else if (c >= 0x21 && c <= 0x7e) { props |= _PUNCT; }
    return (props & type) != 0;
}

/* ================================================================== */
/* secure string helpers (errno_t-returning, permissive)              */
/* ================================================================== */
int __cdecl strcpy_s(char* d, size_t n, const char* s) { if (!d || !s || !n) return 22; strcpy(d, s); return 0; }
int __cdecl strncpy_s(char* d, size_t n, const char* s, size_t cnt) { if (!d || !s || !n) return 22; strncpy(d, s, cnt < n ? cnt : n - 1); return 0; }
int __cdecl strcat_s(char* d, size_t n, const char* s) { if (!d || !s || !n) return 22; strcat(d, s); return 0; }
int __cdecl wcscpy_s(wchar_t* d, size_t n, const wchar_t* s) { if (!d || !s || !n) return 22; wcscpy(d, s); return 0; }
int __cdecl wcsncpy_s(wchar_t* d, size_t n, const wchar_t* s, size_t cnt) { if (!d || !s || !n) return 22; wcsncpy(d, s, cnt < n ? cnt : n - 1); return 0; }
int __cdecl wcscat_s(wchar_t* d, size_t n, const wchar_t* s) { if (!d || !s || !n) return 22; wcscat(d, s); return 0; }
int __cdecl memcpy_s(void* d, size_t n, const void* s, size_t cnt) { if (!d || !s || !n) return 22; memcpy(d, s, cnt < n ? cnt : n); return 0; }
int __cdecl memmove_s(void* d, size_t n, const void* s, size_t cnt) { if (!d || !s || !n) return 22; memmove(d, s, cnt < n ? cnt : n); return 0; }
int __cdecl memset_s(void* d, size_t n, int c, size_t cnt) { if (!d || !n) return 22; memset(d, c, cnt < n ? cnt : n); return 0; }

/* ---- misc MSVC/CRT helpers ----------------------------------------- */
unsigned long __cdecl _byteswap_ulong(unsigned long x) {
    return ((x & 0x000000FFUL) << 24) | ((x & 0x0000FF00UL) << 8) |
           ((x & 0x00FF0000UL) >> 8)  | ((x & 0xFF000000UL) >> 24);
}
/* mingw declares __p__wpgmptr as a FUNCTION (wchar_t** __cdecl(void)); the
 * _wpgmptr "variable" is a macro (*__p__wpgmptr()). Provide the function. */
static wchar_t* g_wpgmptr = NULL;
wchar_t** __cdecl __p__wpgmptr(void) { return &g_wpgmptr; }
