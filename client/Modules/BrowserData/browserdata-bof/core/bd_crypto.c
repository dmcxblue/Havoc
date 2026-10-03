/* bd_crypto.c - SHA1/SHA256, HMAC, PBKDF2, AES-GCM/AES-CBC/3DES-CBC (BCrypt),
 * DPAPI, base64, Chromium blob decryption + cookie hash stripping. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>
#include "bd.h"

/* ---- msvcrt ---- */
extern void  *malloc(size_t);
extern void   free(void *);
extern void  *memcpy(void *, const void *, size_t);
extern void  *memset(void *, int, size_t);
extern size_t strlen(const char *);
extern size_t wcslen(const wchar_t *);
extern int    memcmp(const void *, const void *, size_t);

typedef long NTSTATUS;
#define BD_STATUS_SUCCESS ((NTSTATUS)0x00000000L)

typedef NTSTATUS (WINAPI *pBCryptOpenAlgorithmProvider)(BCRYPT_ALG_HANDLE *, LPCWSTR, LPCWSTR, ULONG);
typedef NTSTATUS (WINAPI *pBCryptCloseAlgorithmProvider)(BCRYPT_ALG_HANDLE, ULONG);
typedef NTSTATUS (WINAPI *pBCryptSetProperty)(BCRYPT_HANDLE, LPCWSTR, PUCHAR, ULONG, ULONG);
typedef NTSTATUS (WINAPI *pBCryptGenerateSymmetricKey)(BCRYPT_ALG_HANDLE, BCRYPT_KEY_HANDLE *,
                    PUCHAR, ULONG, PUCHAR, ULONG, ULONG);
typedef NTSTATUS (WINAPI *pBCryptDestroyKey)(BCRYPT_KEY_HANDLE);
typedef NTSTATUS (WINAPI *pBCryptDecrypt)(BCRYPT_KEY_HANDLE, PUCHAR, ULONG, VOID *,
                    PUCHAR, ULONG, PUCHAR, ULONG, ULONG *, ULONG);

static pBCryptOpenAlgorithmProvider      fnBCOpen;
static pBCryptCloseAlgorithmProvider     fnBCClose;
static pBCryptSetProperty                fnBCSetProp;
static pBCryptGenerateSymmetricKey       fnBCGenKey;
static pBCryptDestroyKey                 fnBCDestroyKey;
static pBCryptDecrypt                    fnBCDecrypt;
static int bcLoaded = 0;

static void bc_load(void) {
    HMODULE h;
    if (bcLoaded) return;
    bcLoaded = 1;
    h = LoadLibraryA("bcrypt.dll");
    if (!h) return;
    fnBCOpen       = (pBCryptOpenAlgorithmProvider)GetProcAddress(h, "BCryptOpenAlgorithmProvider");
    fnBCClose      = (pBCryptCloseAlgorithmProvider)GetProcAddress(h, "BCryptCloseAlgorithmProvider");
    fnBCSetProp    = (pBCryptSetProperty)GetProcAddress(h, "BCryptSetProperty");
    fnBCGenKey     = (pBCryptGenerateSymmetricKey)GetProcAddress(h, "BCryptGenerateSymmetricKey");
    fnBCDestroyKey = (pBCryptDestroyKey)GetProcAddress(h, "BCryptDestroyKey");
    fnBCDecrypt    = (pBCryptDecrypt)GetProcAddress(h, "BCryptDecrypt");
    if (fnBCOpen && fnBCClose && fnBCSetProp && fnBCGenKey && fnBCDestroyKey && fnBCDecrypt)
        bcLoaded = 2;
}

/* generic CBC decrypt (BCrypt CNG) */
static int bd_bc_cbc(const wchar_t *alg, const wchar_t *chain,
                     const unsigned char *key, size_t klen,
                     const unsigned char *iv, size_t ivlen,
                     const unsigned char *ct, size_t clen,
                     unsigned char *pt, size_t *ptlen) {
    BCRYPT_ALG_HANDLE hAlg = 0;
    BCRYPT_KEY_HANDLE hKey = 0;
    unsigned char ivbuf[16];
    unsigned long done = 0, chainBytes;
    NTSTATUS st;
    int rc = -1;

    bc_load();
    if (bcLoaded != 2) return -1;
    if (clen == 0 || clen % 16 != 0 || !iv || ivlen != 16 || !key || !klen) return -1;

    if (fnBCOpen(&hAlg, alg, NULL, 0) != BD_STATUS_SUCCESS) return -1;
    chainBytes = (unsigned long)((wcslen(chain) + 1) * sizeof(wchar_t));
    if (fnBCSetProp((BCRYPT_HANDLE)hAlg, L"ChainingMode",
                    (PUCHAR)chain, chainBytes, 0) != BD_STATUS_SUCCESS)
        goto out;
    if (fnBCGenKey(hAlg, &hKey, NULL, 0, (PUCHAR)key, (ULONG)klen, 0) != BD_STATUS_SUCCESS)
        goto out;
    memcpy(ivbuf, iv, 16);
    st = fnBCDecrypt(hKey, (PUCHAR)ct, (ULONG)clen, NULL,
                     ivbuf, 16, (PUCHAR)pt, (ULONG)clen, &done, 0);
    if (st == BD_STATUS_SUCCESS) { *ptlen = done; rc = 0; }
out:
    if (hKey) fnBCDestroyKey(hKey);
    if (hAlg) fnBCClose(hAlg, 0);
    return rc;
}

int bd_aes_cbc_decrypt(const unsigned char *key, size_t klen,
                       const unsigned char *iv,
                       const unsigned char *ct, size_t clen,
                       unsigned char *pt, size_t *ptlen) {
    return bd_bc_cbc(L"AES", L"ChainingModeCBC", key, klen, iv, 16, ct, clen, pt, ptlen);
}
int bd_des3_cbc_decrypt(const unsigned char *key, size_t klen,
                        const unsigned char *iv,
                        const unsigned char *ct, size_t clen,
                        unsigned char *pt, size_t *ptlen) {
    if (klen != 24) return -1;
    return bd_bc_cbc(L"3DES", L"ChainingModeCBC", key, klen, iv, 16, ct, clen, pt, ptlen);
}

int bd_aes_gcm_decrypt(const unsigned char *key, size_t klen,
                       const unsigned char *nonce, size_t nlen,
                       const unsigned char *aad, size_t alen,
                       const unsigned char *ct, size_t clen,
                       unsigned char *pt, size_t *ptlen) {
    BCRYPT_ALG_HANDLE hAlg = 0;
    BCRYPT_KEY_HANDLE hKey = 0;
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
    unsigned long done = 0, chainBytes;
    NTSTATUS st;
    int rc = -1;

    bc_load();
    if (bcLoaded != 2) return -1;
    if (!nonce || nlen != 12 || clen < 16 || !key || !klen) return -1;

    if (fnBCOpen(&hAlg, L"AES", NULL, 0) != BD_STATUS_SUCCESS) return -1;
    chainBytes = (unsigned long)((wcslen(L"ChainingModeGCM") + 1) * sizeof(wchar_t));
    if (fnBCSetProp((BCRYPT_HANDLE)hAlg, L"ChainingMode",
                    (PUCHAR)L"ChainingModeGCM", chainBytes, 0) != BD_STATUS_SUCCESS)
        goto out;
    if (fnBCGenKey(hAlg, &hKey, NULL, 0, (PUCHAR)key, (ULONG)klen, 0) != BD_STATUS_SUCCESS)
        goto out;

    BCRYPT_INIT_AUTH_MODE_INFO(info);
    info.pbNonce = (unsigned char *)nonce; info.cbNonce = (unsigned long)nlen;
    info.pbTag   = (unsigned char *)ct + clen - 16; info.cbTag = 16;
    info.pbAuthData = (unsigned char *)aad; info.cbAuthData = (unsigned long)alen;

    st = fnBCDecrypt(hKey, (PUCHAR)ct, (ULONG)(clen - 16), &info,
                     NULL, 0, (PUCHAR)pt, (ULONG)(clen - 16), &done, 0);
    if (st == BD_STATUS_SUCCESS) { *ptlen = done; rc = 0; }
out:
    if (hKey) fnBCDestroyKey(hKey);
    if (hAlg) fnBCClose(hAlg, 0);
    return rc;
}

/* ---------------------------------------------------------------- DPAPI -- */
typedef struct { unsigned long cbData; unsigned char *pbData; } BD_DATA_BLOB;
typedef int (WINAPI *pCryptUnprotectData)(BD_DATA_BLOB *, LPWSTR *, BD_DATA_BLOB *,
                    PVOID, PVOID, DWORD, BD_DATA_BLOB *);
static pCryptUnprotectData fnUnprotect;
static int dpLoaded = 0;

int bd_dpapi_decrypt(const unsigned char *ct, size_t clen,
                     unsigned char **ptOut, size_t *ptLenOut) {
    BD_DATA_BLOB in, out;
    HMODULE h;
    if (!ct || !clen || !ptOut || !ptLenOut) return -1;
    *ptOut = NULL; *ptLenOut = 0;
    if (!dpLoaded) {
        dpLoaded = 1;
        h = LoadLibraryA("crypt32.dll");
        if (!h) return -1;
        fnUnprotect = (pCryptUnprotectData)GetProcAddress(h, "CryptUnprotectData");
        if (!fnUnprotect) return -1;
    }
    in.cbData = (unsigned long)clen; in.pbData = (unsigned char *)ct;
    memset(&out, 0, sizeof(out));
    if (!fnUnprotect(&in, NULL, NULL, NULL, NULL, 0, &out)) return -1;
    *ptOut = out.pbData;       /* caller frees via LocalFree */
    *ptLenOut = out.cbData;
    return 0;
}

unsigned long bd_local_free(unsigned long h) {
    /* kernel32!LocalFree - HLOCAL is a handle-sized value; keep ABI-clean by
     * calling through the real signature */
    typedef unsigned long (__stdcall *pLocalFree)(unsigned long);
    static pLocalFree fn = NULL;
    static int loaded = 0;
    if (!loaded) {
        HMODULE k = GetModuleHandleA("kernel32.dll");
        loaded = 1;
        if (k) fn = (pLocalFree)GetProcAddress(k, "LocalFree");
    }
    if (fn) return fn(h);
    return h;
}

/* ------------------------------------------------------------ SHA1/SHA256 */
typedef struct { unsigned int h[5]; unsigned long long len; unsigned char buf[64]; size_t blen; } bd_sha1_ctx;
typedef struct { unsigned int h[8]; unsigned long long len; unsigned char buf[64]; size_t blen; } bd_sha256_ctx;

static unsigned int rol32(unsigned int x, int n) { return (x << n) | (x >> (32 - n)); }
static unsigned int ror32(unsigned int x, int n) { return (x >> n) | (x << (32 - n)); }

static const unsigned int SHA1_IV[5] = {0x67452301u,0xEFCDAB89u,0x98BADCFEu,0x10325476u,0xC3D2E1F0u};
static const unsigned int SHA256_IV[8] = {0x6a09e667u,0xbb67ae85u,0x3c6ef372u,0xa54ff53au,
                                          0x510e527fu,0x9b05688cu,0x1f83d9abu,0x5be0cd19u};

static void sha1_block(bd_sha1_ctx *c, const unsigned char *p) {
    unsigned int w[80], a, b, cc, d, e, f, k, t; int i;
    for (i = 0; i < 16; i++)
        w[i] = ((unsigned int)p[i*4] << 24) | ((unsigned int)p[i*4+1] << 16) |
               ((unsigned int)p[i*4+2] << 8) | p[i*4+3];
    for (; i < 80; i++)
        w[i] = rol32(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1);
    a = c->h[0]; b = c->h[1]; cc = c->h[2]; d = c->h[3]; e = c->h[4];
    for (i = 0; i < 80; i++) {
        if (i < 20)      { f = (b & cc) | ((~b) & d);         k = 0x5A827999u; }
        else if (i < 40) { f = b ^ cc ^ d;                    k = 0x6ED9EBA1u; }
        else if (i < 60) { f = (b & cc) | (b & d) | (cc & d); k = 0x8F1BBCDCu; }
        else             { f = b ^ cc ^ d;                    k = 0xCA62C1D6u; }
        t = rol32(a, 5) + f + e + k + w[i];
        e = d; d = cc; cc = rol32(b, 30); b = a; a = t;
    }
    c->h[0] += a; c->h[1] += b; c->h[2] += cc; c->h[3] += d; c->h[4] += e;
}
static void sha1_update(bd_sha1_ctx *c, const unsigned char *d, size_t n) {
    c->len += n;
    while (n) {
        size_t take = 64 - c->blen; if (take > n) take = n;
        memcpy(c->buf + c->blen, d, take);
        c->blen += take; d += take; n -= take;
        if (c->blen == 64) { sha1_block(c, c->buf); c->blen = 0; }
    }
}
static void sha1_final(bd_sha1_ctx *c, unsigned char out[20]) {
    unsigned long long bits = c->len * 8; int i; unsigned char pad = 0x80;
    unsigned char lb[8];
    sha1_update(c, &pad, 1); pad = 0;
    while (c->blen != 56) sha1_update(c, &pad, 1);
    for (i = 0; i < 8; i++) lb[i] = (unsigned char)(bits >> (56 - i * 8));
    sha1_update(c, lb, 8);
    for (i = 0; i < 5; i++) {
        out[i*4]   = (unsigned char)(c->h[i] >> 24);
        out[i*4+1] = (unsigned char)(c->h[i] >> 16);
        out[i*4+2] = (unsigned char)(c->h[i] >> 8);
        out[i*4+3] = (unsigned char)(c->h[i]);
    }
}
static void sha1_reset(bd_sha1_ctx *c) {
    int i;
    for (i = 0; i < 5; i++) c->h[i] = SHA1_IV[i];
    c->len = 0; c->blen = 0;
}
int bd_sha1(const unsigned char *d, size_t n, unsigned char out[20]) {
    bd_sha1_ctx c;
    sha1_reset(&c);
    sha1_update(&c, d, n);
    sha1_final(&c, out);
    return 0;
}

static const unsigned int K256[64] = {
    0x428a2f98u,0x71374491u,0xb5c0fbcfu,0xe9b5dba5u,0x3956c25bu,0x59f111f1u,0x923f82a4u,0xab1c5ed5u,
    0xd807aa98u,0x12835b01u,0x243185beu,0x550c7dc3u,0x72be5d74u,0x80deb1feu,0x9bdc06a7u,0xc19bf174u,
    0xe49b69c1u,0xefbe4786u,0x0fc19dc6u,0x240ca1ccu,0x2de92c6fu,0x4a7484aau,0x5cb0a9dcu,0x76f988dau,
    0x983e5152u,0xa831c66du,0xb00327c8u,0xbf597fc7u,0xc6e00bf3u,0xd5a79147u,0x06ca6351u,0x14292967u,
    0x27b70a85u,0x2e1b2138u,0x4d2c6dfcu,0x53380d13u,0x650a7354u,0x766a0abbu,0x81c2c92eu,0x92722c85u,
    0xa2bfe8a1u,0xa81a664bu,0xc24b8b70u,0xc76c51a3u,0xd192e819u,0xd6990624u,0xf40e3585u,0x106aa070u,
    0x19a4c116u,0x1e376c08u,0x2748774cu,0x34b0bcb5u,0x391c0cb3u,0x4ed8aa4au,0x5b9cca4fu,0x682e6ff3u,
    0x748f82eeu,0x78a5636fu,0x84c87814u,0x8cc70208u,0x90befffau,0xa4506cebu,0xbef9a3f7u,0xc67178f2u
};
static void sha256_block(bd_sha256_ctx *c, const unsigned char *p) {
    unsigned int w[64], a, b, cc, d, e, f, g, h, t1, t2; int i;
    for (i = 0; i < 16; i++)
        w[i] = ((unsigned int)p[i*4] << 24) | ((unsigned int)p[i*4+1] << 16) |
               ((unsigned int)p[i*4+2] << 8) | p[i*4+3];
    for (; i < 64; i++) {
        unsigned int s0 = ror32(w[i-15],7) ^ ror32(w[i-15],18) ^ (w[i-15] >> 3);
        unsigned int s1 = ror32(w[i-2],17) ^ ror32(w[i-2],19) ^ (w[i-2] >> 10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    a=c->h[0];b=c->h[1];cc=c->h[2];d=c->h[3];e=c->h[4];f=c->h[5];g=c->h[6];h=c->h[7];
    for (i = 0; i < 64; i++) {
        unsigned int S1 = ror32(e,6) ^ ror32(e,11) ^ ror32(e,25);
        unsigned int ch = (e & f) ^ ((~e) & g);
        unsigned int S0 = ror32(a,2) ^ ror32(a,13) ^ ror32(a,22);
        unsigned int maj = (a & b) ^ (a & cc) ^ (b & cc);
        t1 = h + S1 + ch + K256[i] + w[i];
        t2 = S0 + maj;
        h=g; g=f; f=e; e=d+t1; d=cc; cc=b; b=a; a=t1+t2;
    }
    c->h[0]+=a;c->h[1]+=b;c->h[2]+=cc;c->h[3]+=d;c->h[4]+=e;c->h[5]+=f;c->h[6]+=g;c->h[7]+=h;
}
static void sha256_reset(bd_sha256_ctx *c) {
    int i;
    for (i = 0; i < 8; i++) c->h[i] = SHA256_IV[i];
    c->len = 0; c->blen = 0;
}
static void sha256_update(bd_sha256_ctx *c, const unsigned char *d, size_t n) {
    c->len += n;
    while (n) {
        size_t take = 64 - c->blen; if (take > n) take = n;
        memcpy(c->buf + c->blen, d, take);
        c->blen += take; d += take; n -= take;
        if (c->blen == 64) { sha256_block(c, c->buf); c->blen = 0; }
    }
}
static void sha256_final(bd_sha256_ctx *c, unsigned char out[32]) {
    unsigned long long bits = c->len * 8; int i; unsigned char pad = 0x80;
    unsigned char lb[8];
    sha256_update(c, &pad, 1); pad = 0;
    while (c->blen != 56) sha256_update(c, &pad, 1);
    for (i = 0; i < 8; i++) lb[i] = (unsigned char)(bits >> (56 - i * 8));
    sha256_update(c, lb, 8);
    for (i = 0; i < 8; i++) {
        out[i*4]   = (unsigned char)(c->h[i] >> 24);
        out[i*4+1] = (unsigned char)(c->h[i] >> 16);
        out[i*4+2] = (unsigned char)(c->h[i] >> 8);
        out[i*4+3] = (unsigned char)(c->h[i]);
    }
}
int bd_sha256(const unsigned char *d, size_t n, unsigned char out[32]) {
    bd_sha256_ctx c;
    sha256_reset(&c);
    sha256_update(&c, d, n);
    sha256_final(&c, out);
    return 0;
}

void bd_hmac_sha1(const unsigned char *key, size_t klen,
                  const unsigned char *d, size_t n, unsigned char out[20]) {
    unsigned char kop[64], kip[64], khash[20], inner[20];
    int i; bd_sha1_ctx c;
    if (klen > 64) { bd_sha1(key, klen, khash); key = khash; klen = 20; }
    memset(kop, 0x5c, 64); memset(kip, 0x36, 64);
    for (i = 0; i < (int)klen; i++) { kop[i] ^= key[i]; kip[i] ^= key[i]; }
    sha1_reset(&c);
    sha1_update(&c, kip, 64); sha1_update(&c, d, n); sha1_final(&c, inner);
    sha1_reset(&c);
    sha1_update(&c, kop, 64); sha1_update(&c, inner, 20); sha1_final(&c, out);
}

void bd_hmac_sha256(const unsigned char *key, size_t klen,
                    const unsigned char *d, size_t n, unsigned char out[32]) {
    unsigned char kop[64], kip[64], khash[32], inner[32];
    int i; bd_sha256_ctx c;
    if (klen > 64) { bd_sha256(key, klen, khash); key = khash; klen = 32; }
    memset(kop, 0x5c, 64); memset(kip, 0x36, 64);
    for (i = 0; i < (int)klen; i++) { kop[i] ^= key[i]; kip[i] ^= key[i]; }
    sha256_reset(&c);
    sha256_update(&c, kip, 64); sha256_update(&c, d, n); sha256_final(&c, inner);
    sha256_reset(&c);
    sha256_update(&c, kop, 64); sha256_update(&c, inner, 32); sha256_final(&c, out);
}

/* PBKDF2 (RFC 2898) - correct iteration: U1 = PRF(pw, salt||INT(i));
 * Uj = PRF(pw, U(j-1)); T = U1^U2^...^Uc. sha256mode=1 -> HMAC-SHA256, else SHA1. */
void bd_pbkdf2(int sha256mode, const unsigned char *pw, size_t pwlen,
               const unsigned char *salt, size_t saltlen,
               int iters, unsigned char *out, size_t dlen) {
    unsigned char slblk[520];  /* salt || INT(block) - salts here are <= 32 bytes */
    unsigned char U[32], T[32];
    size_t sofar = 0; unsigned int block = 1;
    int i, j;

    if (!pw || !out || !dlen) return;
    while (sofar < dlen) {
        size_t take;
        if (saltlen > sizeof(slblk) - 4) saltlen = sizeof(slblk) - 4;
        memcpy(slblk, salt, saltlen);
        slblk[saltlen]   = (unsigned char)(block >> 24);
        slblk[saltlen+1] = (unsigned char)(block >> 16);
        slblk[saltlen+2] = (unsigned char)(block >> 8);
        slblk[saltlen+3] = (unsigned char)block;

        if (sha256mode) {
            bd_hmac_sha256(pw, pwlen, slblk, saltlen + 4, T);
            for (j = 1; j < iters; j++) {
                bd_hmac_sha256(pw, pwlen, T, 32, U);
                for (i = 0; i < 32; i++) T[i] ^= U[i];
            }
        } else {
            unsigned char U1[20];
            bd_hmac_sha1(pw, pwlen, slblk, saltlen + 4, U1);
            memset(T, 0, 20);
            for (i = 0; i < 20; i++) T[i] = U1[i];
            for (j = 1; j < iters; j++) {
                bd_hmac_sha1(pw, pwlen, j == 1 ? U1 : U, 20, U);
                for (i = 0; i < 20; i++) T[i] ^= U[i];
            }
        }
        take = dlen - sofar; if (take > (sha256mode ? 32u : 20u)) take = (sha256mode ? 32 : 20);
        memcpy(out + sofar, T, take);
        sofar += take;
        block++;
    }
}

/* -------------------------------------------------------------- base64 --- */
static int b64val(int c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}
int bd_base64_decode(const char *in, size_t inlen, unsigned char **out, size_t *outlen) {
    unsigned char *buf; size_t n = 0, i = 0; unsigned acc = 0; int bits = 0;
    *out = NULL; *outlen = 0;
    if (!in || inlen == 0) return -1;
    buf = (unsigned char *)malloc(inlen / 4 * 3 + 4);
    if (!buf) return -1;
    for (i = 0; i < inlen; i++) {
        int v;
        char c = in[i];
        if (c == '\r' || c == '\n' || c == ' ' || c == '\t') continue;
        if (c == '=') break;
        v = b64val((unsigned char)c);
        if (v < 0) { free(buf); return -1; }
        acc = (acc << 6) | (unsigned)v; bits += 6;
        if (bits >= 8) {
            bits -= 8;
            buf[n++] = (unsigned char)((acc >> bits) & 0xff);
        }
    }
    *out = buf; *outlen = n;
    return 0;
}

/* --------------------------------------------- chromium value decryption -- */
static const unsigned char DPAPI_MAGIC[16] = {
    0x01,0x00,0x00,0x00,0xD0,0x8C,0x9D,0xDF,0x01,0x15,0xD1,0x11,0x8C,0x7A,0x00,0xC0
};
static const unsigned char ZERO_IV[16] = {0};

unsigned char *bd_chromium_decrypt(const bd_keys_t *keys,
                                   const unsigned char *ct, size_t clen,
                                   size_t *outlen) {
    unsigned char *pt; size_t ptlen = 0;
    *outlen = 0;
    if (!ct || clen == 0) return NULL;

    /* raw DPAPI blob (pre-Chrome-80 or 'DPAPI' auto-detect below) */
    if (clen >= 16 && memcmp(ct, DPAPI_MAGIC, 16) == 0) {
        unsigned char *dp = NULL; size_t dplen = 0;
        if (bd_dpapi_decrypt(ct, clen, &dp, &dplen) == 0 && dp && dplen) {
            *outlen = dplen;
            return dp;
        }
        if (dp) bd_local_free((unsigned long)(size_t)dp);
        return NULL;
    }
    if (clen >= 5 && memcmp(ct, "DPAPI", 5) == 0) {
        unsigned char *dp = NULL; size_t dplen = 0;
        if (bd_dpapi_decrypt(ct + 5, clen - 5, &dp, &dplen) == 0 && dp && dplen) {
            *outlen = dplen;
            return dp;
        }
        if (dp) bd_local_free((unsigned long)(size_t)dp);
        return NULL;
    }

    if (clen < 15) return NULL;   /* 3-byte prefix + 12-byte nonce minimum */

    if (memcmp(ct, "v10", 3) == 0) {
        if (keys->v10len == 32) {
            pt = (unsigned char *)malloc(clen);
            if (!pt) return NULL;
            if (bd_aes_gcm_decrypt(keys->v10, 32, ct + 3, 12, NULL, 0,
                                   ct + 15, clen - 15, pt, &ptlen) == 0) {
                *outlen = ptlen; return pt;
            }
            free(pt);
        }
        return NULL;
    }
    if (memcmp(ct, "v20", 3) == 0) {
        if (keys->v20len == 32) {
            pt = (unsigned char *)malloc(clen);
            if (!pt) return NULL;
            if (bd_aes_gcm_decrypt(keys->v20, 32, ct + 3, 12, NULL, 0,
                                   ct + 15, clen - 15, pt, &ptlen) == 0) {
                *outlen = ptlen; return pt;
            }
            free(pt);
        }
        return NULL;
    }
    if (memcmp(ct, "v11", 3) == 0 || memcmp(ct, "APPB", 4) == 0)
        return NULL;  /* v11 linux-only; APPB handled at key-loading stage */

    /* no known prefix: legacy pre-v80 ciphertexts are DPAPI blobs; try it */
    {
        unsigned char *dp = NULL; size_t dplen = 0;
        if (bd_dpapi_decrypt(ct, clen, &dp, &dplen) == 0 && dp && dplen) {
            *outlen = dplen;
            return dp;
        }
        if (dp) bd_local_free((unsigned long)(size_t)dp);
    }
    return NULL;
}

size_t bd_strip_cookie_hash(unsigned char *v, size_t len, const char *host) {
    unsigned char h[32];
    if (!v || len < 32 || !host) return len;
    bd_sha256((const unsigned char *)host, strlen(host), h);
    if (memcmp(v, h, 32) == 0) {
        size_t rest = len - 32;
        memmove(v, v + 32, rest);
        return rest;
    }
    return len;
}
