/* bd_asn1.c - minimal DER walker + Firefox NSS PBE decryption.
 * Mirrors crypto/asn1pbe.go of HackBrowserData:
 *
 *   privateKeyPBE    (nssPrivate.a11):  SEQ{ SEQ{ OID, SEQ{ OCTET entrySalt,
 *                                        INTEGER keyLen } }, OCTET encrypted }
 *     derive: hp = SHA1(globalSalt); ck = SHA1(hp||salt);
 *             k1 = HMAC(ck, pad0(salt,20)||salt); k2 = HMAC(ck, hmac1||salt);
 *             key = dk[:24], iv = dk[32:40]; 3DES-CBC.
 *
 *   passwordCheckPBE (metaData.item2):  SEQ{ OID, SEQ{ SEQ{ OID(pbkd2), SEQ{
 *                                       OCTET salt, INT iter, INT keysize,
 *                                       SEQ{ OID } } }, SEQ{ OID, OCTET iv } },
 *                                       OCTET encrypted }
 *     derive: pw = SHA1(globalSalt); key = PBKDF2-SHA256(pw, salt, iter, keysize);
 *             iv = 04 0E || iv(14); AES-CBC.
 *
 *   credentialPBE    (logins.json):     OCTET keycheck(16), SEQ{ OID, OCTET iv },
 *                                       OCTET encrypted
 *     iv len 8 -> 3DES-CBC(key[:24]); iv len 16 -> AES-256-CBC(key).
 */
#include "bd.h"

extern void  *malloc(size_t);
extern void   free(void *);
extern void  *memset(void *, int, size_t);
extern void  *memcpy(void *, const void *, size_t);
extern size_t strlen(const char *);
extern int    memcmp(const void *, const void *, size_t);

/* --------------------------------------------------------------- DER walk -- */
typedef struct {
    const unsigned char *p, *end;
} der;

static int der_tag(der *d, unsigned char want, const unsigned char **body, size_t *blen) {
    const unsigned char *p = d->p;
    size_t len; unsigned char tag;
    if (p + 2 > d->end) return -1;
    tag = *p++;
    if ((tag & 0x1f) == 0x1f) return -1;          /* multi-byte tags unused     */
    if (*p & 0x80) {
        int nb = *p++ & 0x7f, i;
        if (nb > 4 || p + nb > d->end) return -1;
        len = 0;
        for (i = 0; i < nb; i++) len = (len << 8) | *p++;
    } else {
        len = *p++;
    }
    if (p + len > d->end) return -1;
    if ((tag & 0x1f) != (want & 0x1f)) return -1;
    if (want != 0xff && tag != want) return -1;
    *body = p; *blen = len;
    d->p = p + len;
    return 0;
}

#define DER_SEQ   0x30
#define DER_SET   0x31
#define DER_INT   0x02
#define DER_OCTET 0x04
#define DER_OID   0x06

static int der_seq(der *d, der *inner) {
    const unsigned char *b; size_t n;
    if (der_tag(d, DER_SEQ, &b, &n) != 0) return -1;
    inner->p = b; inner->end = b + n;
    return 0;
}
static int der_oid(der *d) {
    const unsigned char *b; size_t n;
    return der_tag(d, DER_OID, &b, &n);
}
static int der_octet(der *d, const unsigned char **b, size_t *n) {
    return der_tag(d, DER_OCTET, b, n);
}
static int der_int(der *d, long *out) {
    const unsigned char *b; size_t n, i;
    if (der_tag(d, DER_INT, &b, &n) != 0 || n == 0 || n > 8) return -1;
    *out = (b[0] & 0x80) ? -1 : 0;
    for (i = 0; i < n; i++) *out = (*out << 8) | b[i];
    return 0;
}

/* -------------------------------------------------------- cipher helpers -- */
static unsigned char *bd_cipher_to_plain(int aes /*1=aes-cbc,0=3des-cbc*/,
        const unsigned char *key, size_t klen, const unsigned char *iv,
        const unsigned char *ct, size_t clen, size_t *outlen) {
    unsigned char *pt;
    size_t ptlen = 0;
    if (!ct || clen == 0 || clen % 8 != 0) return NULL;
    pt = (unsigned char *)malloc(clen + 16);
    if (!pt) return NULL;
    if (aes)
        bd_aes_cbc_decrypt(key, klen, iv, ct, clen, pt, &ptlen);
    else
        bd_des3_cbc_decrypt(key, klen, iv, ct, clen, pt, &ptlen);
    if (ptlen == 0) { free(pt); return NULL; }
    /* strip PKCS#5/7 padding */
    {
        unsigned char pad = pt[ptlen - 1];
        if (pad >= 1 && pad <= 16 && ptlen >= (size_t)pad) {
            size_t i; int ok = 1;
            for (i = ptlen - pad; i < ptlen; i++) if (pt[i] != pad) { ok = 0; break; }
            if (ok) ptlen -= pad;
        }
    }
    *outlen = ptlen;
    return pt;
}

/* pkcs5 pad to 20 bytes with zeros (NSS paddedSalt) */
static void pkcs5_zero_pad20(const unsigned char *salt, size_t slen, unsigned char out[20]) {
    memset(out, 0, 20);
    memcpy(out, salt, slen > 20 ? 20 : slen);
}

/* ------------------------------------------------------- NSS PBE structs -- */
unsigned char *bd_nss_private_pbe(const unsigned char *derbuf, size_t dlen,
                                  const unsigned char *globalSalt, size_t saltlen,
                                  size_t *outlen) {
    der t2, a2, s2;
    const unsigned char *entrySalt = 0, *enc = 0;
    size_t entrySaltLen = 0, encLen = 0;
    long keyLen = 0;
    unsigned char hp[20], ck[20], padded[20], hmac1[20], k1[20], k2[20], dk[40];
    unsigned char msg[128];
    unsigned char *pt;

    *outlen = 0;
    /* top = SEQ{ SEQ{ OID, SEQ{ OCTET entrySalt, INT keyLen } }, OCTET encrypted } */
    {
        der outer;
        t2.p = derbuf; t2.end = derbuf + dlen;
        if (der_seq(&t2, &outer) != 0) return NULL;      /* outer body         */
        if (der_seq(&outer, &a2) != 0) return NULL;      /* a2 = algo body     */
        if (der_oid(&a2) != 0) return NULL;              /* skip OID           */
        if (der_seq(&a2, &s2) != 0) return NULL;         /* s2 = saltAttr body */
        {
            const unsigned char *bb; size_t nn;
            if (der_octet(&s2, &bb, &nn) != 0) return NULL;
            entrySalt = bb; entrySaltLen = nn;
        }
        (void)der_int(&s2, &keyLen);
        {
            const unsigned char *bb; size_t nn;
            if (der_octet(&outer, &bb, &nn) != 0) return NULL;
            enc = bb; encLen = nn;
        }
    }

    /* derive */
    bd_sha1(globalSalt, saltlen, hp);
    {
        unsigned char hb[40];
        memcpy(hb, hp, 20);
        memcpy(hb + 20, entrySalt, entrySaltLen > 20 ? 20 : entrySaltLen);
        bd_sha1(hb, 20 + (entrySaltLen > 20 ? 20 : entrySaltLen), ck);
    }
    pkcs5_zero_pad20(entrySalt, entrySaltLen, padded);
    /* hmac1 = HMAC(ck, padded) */
    bd_hmac_sha1(ck, 20, padded, 20, hmac1);
    /* k1 = HMAC(ck, padded||salt) */
    if (entrySaltLen <= 44) {
        memcpy(msg, padded, 20);
        memcpy(msg + 20, entrySalt, entrySaltLen);
        bd_hmac_sha1(ck, 20, msg, 20 + entrySaltLen, k1);
        /* k2 = HMAC(ck, hmac1||salt) */
        memcpy(msg, hmac1, 20);
        memcpy(msg + 20, entrySalt, entrySaltLen);
        bd_hmac_sha1(ck, 20, msg, 20 + entrySaltLen, k2);
    } else {
        unsigned char big[128];
        if (entrySaltLen > 84) return NULL;
        memcpy(big, padded, 20); memcpy(big + 20, entrySalt, entrySaltLen);
        bd_hmac_sha1(ck, 20, big, 20 + entrySaltLen, k1);
        memcpy(big, hmac1, 20); memcpy(big + 20, entrySalt, entrySaltLen);
        bd_hmac_sha1(ck, 20, big, 20 + entrySaltLen, k2);
    }
    memcpy(dk, k1, 20);
    memcpy(dk + 20, k2, 20);

    pt = bd_cipher_to_plain(0 /*3DES*/, dk, 24, dk + 32, enc, encLen, outlen);
    return pt;
}

unsigned char *bd_nss_passwordcheck_pbe(const unsigned char *derbuf, size_t dlen,
                                        const unsigned char *globalSalt, size_t saltlen,
                                        size_t *outlen) {
    /* PBES2 / PBKDF2-SHA256 / AES-256-CBC (Firefox key4.db + logins).
     * SEQ{ SEQ{ OID(pbes2), SEQ{ SEQ{ OID(pbkdf2), SEQ{ OCTET salt, INT iter,
     *   INT keysize, SEQ{OID prf} } }, SEQ{ OID(enc), OCTET iv(14) } } },
     *   OCTET enc }
     * Key = PBKDF2-SHA256(SHA1(globalSalt), salt, iter, keysize).
     * IV  = 0x04 0x0E || iv(14). */
    der t2, outer, a2, kdf, kdfalg, kdfp, prf, ivalg;
    const unsigned char *entrySalt = 0, *iv = 0, *enc = 0;
    size_t entrySaltLen = 0, ivLen = 0, encLen = 0;
    long iters = 0, keysize = 0;
    unsigned char pw[20], key[32], ivFull[16];
    unsigned char *pt;

    *outlen = 0;
    t2.p = derbuf; t2.end = derbuf + dlen;
    if (der_seq(&t2, &outer) != 0) return NULL;       /* outer SEQ         */
    if (der_seq(&outer, &a2) != 0) return NULL;       /* algoAttr SEQ      */
    if (der_oid(&a2) != 0) return NULL;               /* OID pbes2         */
    if (der_seq(&a2, &kdf) != 0) return NULL;         /* params SEQ        */
    if (der_seq(&kdf, &kdfalg) != 0) return NULL;     /* kdf_alg SEQ       */
    if (der_oid(&kdfalg) != 0) return NULL;           /* OID pbkdf2        */
    if (der_seq(&kdfalg, &kdfp) != 0) return NULL;    /* kdf_params SEQ    */
    {
        const unsigned char *bb; size_t nn;
        if (der_octet(&kdfp, &bb, &nn) != 0) return NULL;
        entrySalt = bb; entrySaltLen = nn;
    }
    if (der_int(&kdfp, &iters) != 0) return NULL;
    if (der_int(&kdfp, &keysize) != 0) return NULL;
    if (der_seq(&kdfp, &prf) != 0) return NULL;       /* prf SEQ{OID}      */
    if (der_seq(&kdf, &ivalg) != 0) return NULL;      /* iv_alg SEQ        */
    if (der_oid(&ivalg) != 0) return NULL;            /* OID enc scheme    */
    {
        const unsigned char *bb; size_t nn;
        if (der_octet(&ivalg, &bb, &nn) != 0) return NULL;
        iv = bb; ivLen = nn;
    }
    {
        const unsigned char *bb; size_t nn;
        if (der_octet(&outer, &bb, &nn) != 0) return NULL;
        enc = bb; encLen = nn;
    }

    bd_sha1(globalSalt, saltlen, pw);
    bd_pbkdf2(1, pw, 20, entrySalt, entrySaltLen, (int)iters, key, (size_t)keysize);

    if (ivLen == 14) {
        ivFull[0] = 0x04; ivFull[1] = 0x0E;
        memcpy(ivFull + 2, iv, 14);
    } else if (ivLen == 16) {
        memcpy(ivFull, iv, 16);
    } else {
        return NULL;
    }
    pt = bd_cipher_to_plain(1 /*AES*/, key, (size_t)keysize, ivFull, enc, encLen, outlen);
    return pt;
}

unsigned char *bd_nss_credential_pbe(const unsigned char *derbuf, size_t dlen,
                                     const unsigned char *masterKey, size_t keylen,
                                     size_t *outlen) {
    der d, outer, algo;
    const unsigned char *iv = 0, *enc = 0;
    size_t ivLen = 0, encLen = 0;
    unsigned char *pt;

    *outlen = 0;
    d.p = derbuf; d.end = derbuf + dlen;
    if (der_seq(&d, &outer) != 0) return NULL;           /* outer SEQ         */
    {
        const unsigned char *bb; size_t nn;
        if (der_octet(&outer, &bb, &nn) != 0) return NULL;  /* keycheck(16)   */
    }
    {
        der oid;
        if (der_seq(&outer, &algo) != 0) return NULL;    /* SEQ{ OID, OCTET iv } */
        if (der_oid(&algo) != 0) return NULL;            /* OID                */
    }
    {
        const unsigned char *bb; size_t nn;
        if (der_octet(&algo, &bb, &nn) != 0) return NULL;
        iv = bb; ivLen = nn;
    }
    {
        const unsigned char *bb; size_t nn;
        if (der_octet(&outer, &bb, &nn) != 0) return NULL;
        enc = bb; encLen = nn;
    }

    if (ivLen == 8)          /* legacy 3DES-CBC */
        pt = bd_cipher_to_plain(0, masterKey, keylen >= 24 ? 24 : keylen, iv, enc, encLen, outlen);
    else if (ivLen == 16)    /* Firefox 144+ AES-256-CBC */
        pt = bd_cipher_to_plain(1, masterKey, keylen, iv, enc, encLen, outlen);
    else
        return NULL;
    return pt;
}
