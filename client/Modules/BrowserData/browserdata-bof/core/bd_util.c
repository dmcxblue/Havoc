/* bd_util.c - strings, string-builder, time, filesystem helpers.
 * BOF-safe: only kernel32 + msvcrt-resolvable CRT calls, no big stack frames. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include "bd.h"

/* ---- msvcrt (resolved by BOF loader or linked statically in the exe) ---- */
extern void  *malloc(size_t);
extern void   free(void *);
extern void  *calloc(size_t, size_t);
extern size_t strlen(const char *);
extern int    strcmp(const char *, const char *);
extern int    _stricmp(const char *, const char *);
extern int    strncmp(const char *, const char *, size_t);
extern void  *memcpy(void *, const void *, size_t);
extern void  *memset(void *, int, size_t);
extern int    _vsnprintf(char *, size_t, const char *, va_list);
extern int    _mkdir(const char *);

#define BD_CHUNK_CAP (1u << 20)   /* 1 MiB initial sb cap */

/* mingw emits calls to libgcc's stack probe when a frame exceeds ~4KB. COFF
 * BOF loaders cannot resolve that symbol (no DLL exports it), so provide a
 * no-op stub: beacon thread stacks are >=1MB while our largest frame is
 * ~16KB, making the probe unnecessary. x64 uses ___chkstk_ms, x86 __chkstk. */
#if defined(__x86_64__) || defined(__i386__)
__asm__(".text\n\t.globl ___chkstk_ms\n___chkstk_ms:\n\tret\n");
#endif

/* ------------------------------------------------------------- strings -- */
int bd_str_ieq(const char *a, const char *b) {
    if (!a || !b) return 0;
    return _stricmp(a, b) == 0;
}
int bd_str_ieq_n(const char *a, const char *b, size_t n) {
    if (!a || !b) return 0;
    while (n && *a && *b) {
        char ca = *a, cb = *b;
        if (ca >= 'A' && ca <= 'Z') ca += 32;
        if (cb >= 'A' && cb <= 'Z') cb += 32;
        if (ca != cb) return 0;
        a++; b++; n--;
    }
    return n == 0;
}
char *bd_strdup(const char *s) {
    size_t n; char *p;
    if (!s) return NULL;
    n = strlen(s);
    p = (char *)malloc(n + 1);
    if (!p) return NULL;
    memcpy(p, s, n + 1);
    return p;
}
char *bd_path_join(char *dst, size_t cap, const char *dir, const char *child) {
    size_t n = 0;
    if (!dir || !child || cap < 4) return NULL;
    while (*dir && n + 1 < cap) dst[n++] = *dir++;
    if (n && dst[n - 1] != '\\' && dst[n - 1] != '/' && n + 1 < cap) dst[n++] = '\\';
    while (*child && n + 1 < cap) dst[n++] = *child++;
    dst[n] = 0;
    return dst;
}
const char *bd_path_name(const char *path) {
    const char *p, *last = path;
    if (!path) return "";
    for (p = path; *p; p++)
        if (*p == '\\' || *p == '/') last = p + 1;
    return last;
}

/* -------------------------------------------------------- string builder -- */
static int bd_sb_grow(bd_sb *sb, size_t need) {
    size_t ncap; char *nb;
    if (sb->len + need + 1 <= sb->cap) return 0;
    ncap = sb->cap ? sb->cap : 256;
    while (ncap < sb->len + need + 1) ncap *= 2;
    nb = (char *)malloc(ncap);
    if (!nb) return -1;
    if (sb->buf) { memcpy(nb, sb->buf, sb->len); free(sb->buf); }
    sb->buf = nb; sb->cap = ncap;
    return 0;
}
int bd_sb_init(bd_sb *sb) {
    sb->buf = (char *)malloc(1024);
    if (!sb->buf) return -1;
    sb->cap = 1024; sb->len = 0; sb->buf[0] = 0;
    return 0;
}
int bd_sb_cat(bd_sb *sb, const char *s, size_t n) {
    if (bd_sb_grow(sb, n) != 0) return -1;
    memcpy(sb->buf + sb->len, s, n);
    sb->len += n; sb->buf[sb->len] = 0;
    return 0;
}
int bd_sb_put(bd_sb *sb, const char *s) {
    if (!s) return bd_sb_cat(sb, "null", 4);
    return bd_sb_cat(sb, s, strlen(s));
}
static const char HEXD[] = "0123456789abcdef";
static int bd_sb_put_utf8_escaped(bd_sb *sb, const char *s, size_t n) {
    size_t i = 0;
    if (bd_sb_put(sb, "\"") != 0) return -1;
    while (i < n) {
        unsigned char c = (unsigned char)s[i];
        char tmp[8]; int adv = 1;
        switch (c) {
        case '"':  tmp[0]='\\'; tmp[1]='"';  adv=2; break;
        case '\\': tmp[0]='\\'; tmp[1]='\\'; adv=2; break;
        case '\n': tmp[0]='\\'; tmp[1]='n';  adv=2; break;
        case '\r': tmp[0]='\\'; tmp[1]='r';  adv=2; break;
        case '\t': tmp[0]='\\'; tmp[1]='t';  adv=2; break;
        case '\b': tmp[0]='\\'; tmp[1]='b';  adv=2; break;
        case '\f': tmp[0]='\\'; tmp[1]='f';  adv=2; break;
        default:
            if (c < 0x20 || c == 0x7f) {
                tmp[0]='\\'; tmp[1]='u'; tmp[2]='0'; tmp[3]='0';
                tmp[4]=HEXD[(c>>4)&0xf]; tmp[5]=HEXD[c&0xf]; adv=6;
            } else { tmp[0]=(char)c; adv=1; }   /* pass utf-8 through */
            break;
        }
        if (bd_sb_cat(sb, tmp, (size_t)adv) != 0) return -1;
        i += 1; /* input is one byte at a time; multi-byte utf-8 chars pass raw */
    }
    return bd_sb_put(sb, "\"");
}
int bd_sb_json_str(bd_sb *sb, const char *s) {
    if (!s) return bd_sb_put(sb, "\"\"");
    return bd_sb_put_utf8_escaped(sb, s, strlen(s));
}
int bd_sb_csv_field(bd_sb *sb, const char *s) {
    int quote = 0; size_t i, n;
    if (!s) s = "";
    n = strlen(s);
    for (i = 0; i < n; i++)
        if (s[i] == '"' || s[i] == ',' || s[i] == '\n' || s[i] == '\r') { quote = 1; break; }
    if (quote) {
        if (bd_sb_put(sb, "\"") != 0) return -1;
        for (i = 0; i < n; i++) {
            if (s[i] == '"' && bd_sb_put(sb, "\"\"") != 0) return -1;
            else if (s[i] != '"' && bd_sb_cat(sb, &s[i], 1) != 0) return -1;
        }
        return bd_sb_put(sb, "\"");
    }
    return bd_sb_cat(sb, s, n);
}
void bd_sb_free(bd_sb *sb) {
    if (sb->buf) free(sb->buf);
    sb->buf = NULL; sb->len = sb->cap = 0;
}

/* ------------------------------------------------------------------ time -- */
static void bd_fmt_from_unix(char *dst, size_t cap, long long secs) {
    /* days-from-civil inverse (Howard Hinnant algorithm), UTC */
    long long z = secs / 86400, s = secs % 86400;
    long long era, yoe, y, doy, mp, doe, yy; unsigned doeU, yoeU;
    int m, d, hh, mm, ss;
    if (s < 0) { s += 86400; z -= 1; }
    z += 719468;
    era = (z >= 0 ? z : z - 146096) / 146097;
    doe = z - era * 146097; doeU = (unsigned)doe;
    yoeU = (doeU - doeU/1460 + doeU/36524 - doeU/146096) / 365;
    yoe = yoeU;
    y = yoe + era * 400;
    doy = doe - (365*yoe + yoe/4 - yoe/100);
    mp = (5*doy + 2) / 153;
    d = (int)(doy - (153*mp+2)/5 + 1);
    m = (int)(mp < 10 ? mp+3 : mp-9);
    yy = y + (m <= 2 ? 1 : 0);
    hh = (int)(s / 3600); mm = (int)((s % 3600) / 60); ss = (int)(s % 60);
    {
        extern int _snprintf(char *, size_t, const char *, ...);
        _snprintf(dst, cap, "%04lld-%02d-%02d %02d:%02d:%02d",
                  yy, m, d, hh, mm, ss);
    }
}
void bd_fmt_time(char *dst, size_t cap, long long ts, int chrome) {
    long long secs;
    if (cap < 20) return;
    if (ts <= 0) { memcpy(dst, "-", 2); return; }
    if (chrome) {
        /* webkit: us since 1601-01-01 */
        secs = ts / 1000000 - 11644473600LL;
    } else {
        secs = ts / 1000000;
    }
    if (secs < 0) { memcpy(dst, "-", 2); return; }
    bd_fmt_from_unix(dst, cap, secs);
}
