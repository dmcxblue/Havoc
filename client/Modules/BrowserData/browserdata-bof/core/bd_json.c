/* bd_json.c - minimal JSON parser (enough for Local State / Bookmarks /
 * logins.json) + object member iteration. Parser builds a tree of nodes in
 * one contiguous allocation pool; strings are unescaped into malloc'd memory. */
#include "bd.h"

extern void  *malloc(size_t);
extern void   free(void *);
extern void  *memset(void *, int, size_t);
extern void  *memcpy(void *, const void *, size_t);
extern size_t strlen(const char *);
extern int    strncmp(const char *, const char *, size_t);
extern int    strcmp(const char *, const char *);
extern char  *strchr(const char *, int);
extern double strtod(const char *, char **);

typedef enum { JNULL, JBOOL, JNUM, JSTR, JOBJ, JARR } jtype;

struct bd_json {
    jtype         type;
    /* string value (JSTR), node name is stored per-member */
    char         *str;
    double        num;
    /* object/array */
    struct jmember *members;
    int           nmembers, mcap;
};

typedef struct jmember {
    char    *key;
    bd_json *val;
} jmember;

static void jfree_val(bd_json *j);

typedef struct {
    const char *p, *end;
    int depth;
} jctx;

#define JMAXDEPTH 64

static bd_json *jparse_val(jctx *c);
static void jskip_ws(jctx *c) {
    while (c->p < c->end && (*c->p == ' ' || *c->p == '\t' || *c->p == '\n' || *c->p == '\r'))
        c->p++;
}
static int jpeek(jctx *c) {
    jskip_ws(c);
    if (c->p >= c->end) return -1;
    return (unsigned char)*c->p;
}
static int jeat(jctx *c, char ch) {
    jskip_ws(c);
    if (c->p < c->end && *c->p == ch) { c->p++; return 0; }
    return -1;
}

static void put_utf8(char **out, unsigned int cp) {
    char *o = *out;
    if (cp < 0x80) *o++ = (char)cp;
    else if (cp < 0x800) {
        *o++ = (char)(0xC0 | (cp >> 6));
        *o++ = (char)(0x80 | (cp & 0x3F));
    } else if (cp < 0x10000) {
        *o++ = (char)(0xE0 | (cp >> 12));
        *o++ = (char)(0x80 | ((cp >> 6) & 0x3F));
        *o++ = (char)(0x80 | (cp & 0x3F));
    } else {
        *o++ = (char)(0xF0 | (cp >> 18));
        *o++ = (char)(0x80 | ((cp >> 12) & 0x3F));
        *o++ = (char)(0x80 | ((cp >> 6) & 0x3F));
        *o++ = (char)(0x80 | (cp & 0x3F));
    }
    *out = o;
}

static char *jparse_string_raw(jctx *c) {
    /* assumes current char is '"' */
    const char *s; size_t cap; char *buf, *o;
    if (c->p >= c->end || *c->p != '"') return NULL;
    c->p++;
    s = c->p;
    cap = 32;
    buf = (char *)malloc(cap);
    if (!buf) return NULL;
    o = buf;
    while (c->p < c->end && *c->p != '"') {
        unsigned char ch = (unsigned char)*c->p;
        if ((size_t)(o - buf) + 8 > cap) {
            size_t used = (size_t)(o - buf);
            char *nb; size_t ncap = cap * 2;
            nb = (char *)malloc(ncap);
            if (!nb) { free(buf); return NULL; }
            memcpy(nb, buf, used);
            free(buf);
            buf = nb; cap = ncap;
            o = nb + used;   /* o must track the new buffer, not the freed one */
        }
        if (ch == '\\') {
            c->p++;
            if (c->p >= c->end) break;
            switch (*c->p) {
            case 'n': *o++ = '\n'; c->p++; break;
            case 't': *o++ = '\t'; c->p++; break;
            case 'r': *o++ = '\r'; c->p++; break;
            case 'b': *o++ = '\b'; c->p++; break;
            case 'f': *o++ = '\f'; c->p++; break;
            case '/': *o++ = '/';  c->p++; break;
            case '"': *o++ = '"';  c->p++; break;
            case '\\':*o++ = '\\'; c->p++; break;
            case 'u': {
                unsigned int cp = 0; int i;
                c->p++;
                for (i = 0; i < 4 && c->p < c->end; i++) {
                    char h = *c->p; int v;
                    if (h >= '0' && h <= '9') v = h - '0';
                    else if (h >= 'a' && h <= 'f') v = h - 'a' + 10;
                    else if (h >= 'A' && h <= 'F') v = h - 'A' + 10;
                    else break;
                    cp = (cp << 4) | (unsigned)v;
                    c->p++;
                }
                /* surrogate pair */
                if (cp >= 0xD800 && cp <= 0xDBFF && c->p + 6 <= c->end &&
                    c->p[0] == '\\' && c->p[1] == 'u') {
                    unsigned int lo = 0; int ok = 1;
                    for (i = 0; i < 4; i++) {
                        char h = c->p[2 + i]; int v;
                        if (h >= '0' && h <= '9') v = h - '0';
                        else if (h >= 'a' && h <= 'f') v = h - 'a' + 10;
                        else if (h >= 'A' && h <= 'F') v = h - 'A' + 10;
                        else { ok = 0; break; }
                        lo = (lo << 4) | (unsigned)v;
                    }
                    if (ok && lo >= 0xDC00 && lo <= 0xDFFF) {
                        cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                        c->p += 6;
                    }
                }
                put_utf8(&o, cp);
                break;
            }
            default: *o++ = *c->p; c->p++; break;
            }
        } else {
            *o++ = (char)ch;
            c->p++;
        }
    }
    if (c->p >= c->end) { free(buf); return NULL; }
    c->p++;   /* closing quote */
    *o = 0;
    return buf;
}

static void jadd_member(bd_json *obj, char *key, bd_json *val) {
    if (obj->nmembers >= obj->mcap) {
        int ncap = obj->mcap ? obj->mcap * 2 : 8;
        jmember *nm = (jmember *)malloc((size_t)ncap * sizeof(jmember));
        if (!nm) { if (key) free(key); jfree_val(val); return; }
        if (obj->members) {
            memcpy(nm, obj->members, (size_t)obj->nmembers * sizeof(jmember));
            free(obj->members);
        }
        obj->members = nm; obj->mcap = ncap;
    }
    obj->members[obj->nmembers].key = key;
    obj->members[obj->nmembers].val = val;
    obj->nmembers++;
}

void jfree_val(bd_json *j) {
    int i;
    if (!j) return;
    if (j->str) free(j->str);
    for (i = 0; i < j->nmembers; i++) {
        if (j->members[i].key) free(j->members[i].key);
        jfree_val(j->members[i].val);
    }
    if (j->members) free(j->members);
    free(j);
}

static bd_json *jnew(jtype t) {
    bd_json *j = (bd_json *)malloc(sizeof(bd_json));
    if (!j) return NULL;
    memset(j, 0, sizeof(*j));
    j->type = t;
    return j;
}

static bd_json *jparse_val(jctx *c) {
    int ch = jpeek(c);
    bd_json *j;
    if (ch < 0 || c->depth > JMAXDEPTH) return NULL;
    if (ch == '{') {
        c->p++; c->depth++;
        j = jnew(JOBJ);
        if (!j) return NULL;
        if (jeat(c, '}') == 0) { c->depth--; return j; }
        for (;;) {
            char *key;
            bd_json *val;
            if (jpeek(c) != '"') { jfree_val(j); return NULL; }
            key = jparse_string_raw(c);
            if (!key) { jfree_val(j); return NULL; }
            if (jeat(c, ':') != 0) { free(key); jfree_val(j); return NULL; }
            val = jparse_val(c);
            if (!val) { free(key); jfree_val(j); return NULL; }
            jadd_member(j, key, val);
            if (jeat(c, ',') == 0) continue;
            if (jeat(c, '}') == 0) { c->depth--; return j; }
            jfree_val(j); return NULL;
        }
    }
    if (ch == '[') {
        c->p++; c->depth++;
        j = jnew(JARR);
        if (!j) return NULL;
        if (jeat(c, ']') == 0) { c->depth--; return j; }
        for (;;) {
            bd_json *val = jparse_val(c);
            if (!val) { jfree_val(j); return NULL; }
            jadd_member(j, NULL, val);
            if (jeat(c, ',') == 0) continue;
            if (jeat(c, ']') == 0) { c->depth--; return j; }
            jfree_val(j); return NULL;
        }
    }
    if (ch == '"') {
        char *s = jparse_string_raw(c);
        if (!s) return NULL;
        j = jnew(JSTR);
        if (!j) { free(s); return NULL; }
        j->str = s;
        return j;
    }
    if (ch == 't') {
        if (c->end - c->p >= 4 && strncmp(c->p, "true", 4) == 0) {
            c->p += 4;
            j = jnew(JBOOL); if (j) j->num = 1;
            return j;
        }
        return NULL;
    }
    if (ch == 'f') {
        if (c->end - c->p >= 5 && strncmp(c->p, "false", 5) == 0) {
            c->p += 5;
            return jnew(JBOOL);
        }
        return NULL;
    }
    if (ch == 'n') {
        if (c->end - c->p >= 4 && strncmp(c->p, "null", 4) == 0) {
            c->p += 4;
            return jnew(JNULL);
        }
        return NULL;
    }
    /* number */
    {
        char *e;
        double v;
        v = strtod(c->p, &e);
        if (e == c->p || e > c->end) return NULL;
        j = jnew(JNUM);
        if (!j) return NULL;
        j->num = v;
        c->p = e;
        return j;
    }
}

bd_json *bd_json_parse(const char *data, size_t len) {
    jctx c;
    bd_json *j;
    if (!data || !len) return NULL;
    c.p = data; c.end = data + len; c.depth = 0;
    j = jparse_val(&c);
    return j;
}
void bd_json_free(bd_json *j) { jfree_val(j); }

const bd_json *bd_json_get(const bd_json *obj, const char *key) {
    int i;
    if (!obj || obj->type != JOBJ || !key) return NULL;
    for (i = 0; i < obj->nmembers; i++)
        if (obj->members[i].key && strcmp(obj->members[i].key, key) == 0)
            return obj->members[i].val;
    return NULL;
}
const bd_json *bd_json_path(const bd_json *j, const char *path) {
    const char *s = path;
    const bd_json *cur = j;
    while (cur && *s) {
        const char *dot = strchr(s, '.');
        size_t n = dot ? (size_t)(dot - s) : strlen(s);
        char tmp[64];
        const bd_json *next;
        if (cur->type != JOBJ) return NULL;
        if (n >= sizeof(tmp)) return NULL;
        memcpy(tmp, s, n); tmp[n] = 0;
        next = bd_json_get(cur, tmp);
        cur = next;
        s = dot ? dot + 1 : s + n;
    }
    return cur;
}
const char *bd_json_str(const bd_json *j) {
    if (!j || j->type != JSTR) return NULL;
    return j->str;
}
double bd_json_num(const bd_json *j) {
    if (!j || (j->type != JNUM && j->type != JBOOL)) return -1;
    return j->num;
}
int bd_json_is_obj(const bd_json *j) { return j && j->type == JOBJ; }
int bd_json_is_arr(const bd_json *j) { return j && j->type == JARR; }
int bd_json_arr_count(const bd_json *arr) {
    if (!arr || arr->type != JARR) return 0;
    return arr->nmembers;
}
const bd_json *bd_json_arr_at(const bd_json *arr, int idx) {
    if (!arr || arr->type != JARR || idx < 0 || idx >= arr->nmembers) return NULL;
    return arr->members[idx].val;
}
int bd_json_obj_at(const bd_json *obj, int idx, const char **key, const bd_json **val) {
    if (!obj || obj->type != JOBJ || idx < 0 || idx >= obj->nmembers) return 0;
    *key = obj->members[idx].key;
    *val = obj->members[idx].val;
    return 1;
}
