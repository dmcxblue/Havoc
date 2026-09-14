#pragma once

#include "common.h"
#include "structs.h"
#include "beacon.h"

#ifndef INT_MAX
#define INT_MAX 2147483647
#endif

// ==================== Static helpers ====================

BOOL MemCopy(unsigned char** dst, unsigned char* src, size_t size) {
    *dst = MemAlloc(size);
    if (!*dst)
        return FALSE;
    MSVCRT$memcpy(*dst, src, size);
    return TRUE;
}

void StrToUpper(char* str) {
    while (*str != '\0') {
        if (*str >= 'a' && *str <= 'z')
            *str -= ('a' - 'A');
        str++;
    }
}

// ==================== ASN.1 serialization core ====================

int AsnToBytesEncode5(AsnElt* a, int start, int end, unsigned char* dst, int dstOff);
int ValueLength(AsnElt* a);

int TagLength(int tagValue) {
    if (tagValue < 0x1F) return 1;
    int k = 0;
    for (int v = tagValue; v > 0; v >>= 7, k += 7);
    return (k / 7) + 1;
}

int LengthLength(int vlen) {
    if (vlen < 0x80) return 1;
    int k = 0;
    for (int v = vlen; v > 0; v >>= 8, k += 8);
    return (k / 8) + 1;
}

int EncodedLength(AsnElt* a) {
    if (a->objLen < 0) {
        int vlen = ValueLength(a);
        a->objLen = TagLength(a->tagValue) + LengthLength(vlen) + vlen;
    }
    return a->objLen;
}

int ValueLength(AsnElt* a) {
    if (a->valLen < 0) {
        if (a->sub != NULL) {
            int vlen = 0;
            for (int i = 0; i < a->subCount; i++) {
                vlen += EncodedLength(&(a->sub[i]));
            }
            a->valLen = vlen;
        }
        else {
            a->valLen = a->objLen;
        }
    }
    return a->valLen;
}

int EncodeValue(AsnElt* a, int start, int end, unsigned char* dst, int dstOff) {
    if (!a)
        return 0;

    int orig = dstOff;
    if (a->objBuf == NULL) {
        int k = 0;
        for (int i = 0; i < a->subCount; i++) {
            int slen = EncodedLength(&(a->sub[i]));
            dstOff += AsnToBytesEncode5(&(a->sub[i]), start - k, end - k, dst, dstOff);
            k += slen;
        }
    }
    else {
        int from = (start > 0) ? start : 0;
        int to = (end > a->valLen) ? a->valLen : end;
        int len = to - from;
        if (len > 0) {
            MSVCRT$memcpy(dst + dstOff, a->objBuf + (a->valOff + from), len);
            dstOff += len;
        }
    }
    return dstOff - orig;
}

int AsnToBytesEncode5(AsnElt* a, int start, int end, unsigned char* dst, int dstOff) {
    if (a->hasEncodedHeader) {
        int from = a->objOff + ((start > 0) ? start : 0);
        int to = a->objOff + ((end > a->objLen) ? a->objLen : end);
        int len = to - from;
        if (len > 0) {
            MSVCRT$memcpy(&dst[dstOff], &a->objBuf[from], len);
            return len;
        }
        else {
            return 0;
        }
    }

    int off = 0;
    int fb = (a->tagClass << 6) + ((a->sub != NULL) ? 0x20 : 0x00);
    if (a->tagValue < 0x1F) {
        fb |= (a->tagValue & 0x1F);
        if (start <= off && off < end)
            dst[dstOff++] = (unsigned char)fb;
        off++;
    }
    else {
        fb |= 0x1F;
        if (start <= off && off < end)
            dst[dstOff++] = (unsigned char)fb;
        off++;
        int k = 0;
        for (int v = a->tagValue; v > 0; v >>= 7, k += 7);
        while (k > 0) {
            k -= 7;
            int v = (a->tagValue >> k) & 0x7F;
            if (k != 0)
                v |= 0x80;
            if (start <= off && off < end)
                dst[dstOff++] = (unsigned char)v;
            off++;
        }
    }

    int vlen = ValueLength(a);
    if (vlen < 0x80) {
        if (start <= off && off < end)
            dst[dstOff++] = (unsigned char)vlen;
        off++;
    }
    else {
        int k = 0;
        for (int v = vlen; v > 0; v >>= 8, k += 8);
        if (start <= off && off < end)
            dst[dstOff++] = (unsigned char)(0x80 + (k >> 3));
        off++;
        while (k > 0) {
            k -= 8;
            if (start <= off && off < end)
                dst[dstOff++] = (unsigned char)(vlen >> k);
            off++;
        }
    }

    EncodeValue(a, start - off, end - off, dst, dstOff);
    off += vlen;

    return (off > 0) ? off : 0;
}

int AsnToBytesEncode3(AsnElt* a, unsigned char* dst, int dstOff) {
    return AsnToBytesEncode5(a, 0, INT_MAX, dst, dstOff);
}

BOOL AsnToBytesEncode(AsnElt* a, int* size, unsigned char** ret) {
    *ret = MemAlloc(EncodedLength(a));
    if (!*ret) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed alloc memory");
        return FALSE;
    }
    *size = AsnToBytesEncode3(a, *ret, 0);
    return TRUE;
}

// ==================== ASN.1 DER decoding core ====================

BOOL BytesToAsnDecode9(unsigned char* buf, int off, int maxLen, int* tc, int* tv, BOOL* cons, int* valOff, int* valLen, int* ret);

BOOL CheckOff(int off, int lim) {
    return (off >= lim) ? TRUE : FALSE;
}

int Dec2(unsigned char* s, int off, BOOL* good) {
    if (off < 0 || off >= ((int)MSVCRT$strlen((char*)s) - 1)) {
        *good = FALSE;
        return -1;
    }
    char c1 = s[off];
    char c2 = s[off + 1];
    if (c1 < '0' || c1 > '9' || c2 < '0' || c2 > '9') {
        *good = FALSE;
        return -1;
    }
    return 10 * (c1 - '0') + (c2 - '0');
}

int IndexOf(unsigned char* str, int len, unsigned char c) {
    for (int i = 0; i < len; i++) {
        if (str[i] == c)
            return i;
    }
    return -1;
}

BOOL CheckTag(AsnElt* a, int tc, int tv) {
    return (a->tagClass != tc || a->tagValue != tv) ? TRUE : FALSE;
}

BOOL ValueByte(AsnElt* a, int off, int* ret) {
    if (off < 0) {
        BeaconPrintf(CALLBACK_ERROR, "invalid value offset: %d\n", off);
        return FALSE;
    }
    if (a->objBuf == NULL) {
        int k = 0;
        for (int i = 0; i < a->subCount; i++) {
            int slen = EncodedLength(&(a->sub[i]));
            if ((k + slen) > off)
                return ValueByte(&(a->sub[i]), off - k, ret);
            k += slen;
        }
    }
    else {
        if (off < a->valLen) {
            *ret = a->objBuf[a->valOff + off];
            return TRUE;
        }
    }
    BeaconPrintf(CALLBACK_ERROR, "invalid value offset");
    return FALSE;
}

int CopyValue3(AsnElt* a, unsigned char* dst, int off) {
    return EncodeValue(a, 0, INT_MAX, dst, off);
}

BOOL DecodeUTF8(unsigned char* buf, int off, int len, unsigned char** ret, int* ret_length) {
    if (len >= 3 && buf[off] == 0xEF && buf[off + 1] == 0xBB && buf[off + 2] == 0xBF) {
        off += 3;
        len -= 3;
    }
    wchar_t* tc = MemAlloc(len * 2 + 2);
    int tcOff = 0;
    for (int k = 0; k < 2; k++) {
        tcOff = 0;
        for (int i = 0; i < len; i++) {
            int c = buf[off + i];
            int e = 0;
            if (c < 0x80) {
                e = 0;
            }
            else if (c < 0xC0) {
            }
            else if (c < 0xE0) {
                c &= 0x1F;
                e = 1;
            }
            else if (c < 0xF0) {
                c &= 0x0F;
                e = 2;
            }
            else if (c < 0xF8) {
                c &= 0x07;
                e = 3;
            }
            else {
                return FALSE;
            }
            while (e-- > 0) {
                if (++i >= len) return FALSE;
                int d = buf[off + i];
                if (d < 0x80 || d > 0xBF)
                    return FALSE;
                c = (c << 6) + (d & 0x3F);
            }
            if (c > 0x10FFFF) return FALSE;
            if (c > 0xFFFF) {
                c -= 0x10000;
                int hi = 0xD800 + (c >> 10);
                int lo = 0xDC00 + (c & 0x3FF);
                tc[tcOff] = (wchar_t)hi;
                tc[tcOff + 1] = (wchar_t)lo;
                tcOff += 2;
            }
            else {
                tc[tcOff] = (wchar_t)c;
                tcOff++;
            }
        }
    }
    tc[tcOff] = 0;
    *ret_length = tcOff + 1;
    *ret = (unsigned char*)tc;
    return TRUE;
}

BOOL DecodeMono(unsigned char* buf, int off, int len, int type, unsigned char** outBuf, int* outLen) {
    if (!MemCopy(outBuf, buf + off, len + 1)) return FALSE;
    (*outBuf)[len] = 0;
    *outLen = len;
    return TRUE;
}

BOOL DecodeNoCopyLength(unsigned char* buf, int off, int len, int* ret) {
    int tc, tv, valOff, valLen, objLen;
    BOOL cons;
    if (!BytesToAsnDecode9(buf, off, len, &tc, &tv, &cons, &valOff, &valLen, &objLen))
        return FALSE;
    if (cons) {
        off = valOff;
        int lim = valOff + valLen;
        while (off < lim) {
            int oLength = 0;
            if (!DecodeNoCopyLength(buf, off, lim - off, &oLength))
                return FALSE;
            off += oLength;
        }
    }
    *ret = objLen;
    return TRUE;
}

BOOL DecodeNoCopy(unsigned char* buf, int off, int len, AsnElt* a) {
    int tc, tv, valOff, valLen, objLen;
    BOOL cons;
    if (!BytesToAsnDecode9(buf, off, len, &tc, &tv, &cons, &valOff, &valLen, &objLen))
        return FALSE;

    a->tagClass = tc;
    a->tagValue = tv;
    a->objBuf = buf;
    a->objBufSize = len;
    a->objOff = off;
    a->objLen = objLen;
    a->valOff = valOff;
    a->valLen = valLen;
    a->hasEncodedHeader = TRUE;

    if (cons) {
        off = valOff;
        int lim = valOff + valLen;
        int count = 0;
        while (off < lim) {
            int oLength = 0;
            if (!DecodeNoCopyLength(buf, off, lim - off, &oLength))
                return FALSE;
            off += oLength;
            count++;
        }

        off = valOff;
        lim = valOff + valLen;
        int index = 0;
        AsnElt* subs = MemAlloc(sizeof(AsnElt) * count);
        if (!subs) {
            BeaconPrintf(CALLBACK_ERROR, "[-] Failed alloc memory");
            return FALSE;
        }
        while (off < lim && index <= count) {
            AsnElt b = { 0 };
            if (!DecodeNoCopy(buf, off, lim - off, &b))
                return FALSE;
            off += b.objLen;
            subs[index] = b;
            index++;
        }
        a->sub = subs;
        a->subCount = count;
    }
    else {
        a->sub = NULL;
        a->subCount = 0;
    }
    return TRUE;
}

BOOL BytesToAsnDecode9(unsigned char* buf, int off, int maxLen, int* tc, int* tv, BOOL* cons, int* valOff, int* valLen, int* ret) {
    int lim = off + maxLen;
    int orig = off;

    if (CheckOff(off, lim)) return FALSE;
    *tv = buf[off++];
    *cons = (*tv & 0x20) != 0;
    *tc = *tv >> 6;
    *tv &= 0x1F;
    if (*tv == 0x1F) {
        *tv = 0;
        for (;;) {
            if (CheckOff(off, lim)) return FALSE;
            int c = buf[off++];
            if (*tv > 0xFFFFFF) {
                BeaconPrintf(CALLBACK_ERROR, "tag value overflow\n");
                return FALSE;
            }
            *tv = (*tv << 7) | (c & 0x7F);
            if ((c & 0x80) == 0)
                break;
        }
    }

    if (CheckOff(off, lim)) return FALSE;
    int vlen = buf[off++];
    if (vlen == 0x80) {
        vlen = -1;
        if (!(*cons)) {
            BeaconPrintf(CALLBACK_ERROR, "indefinite length but not constructed\n");
            return FALSE;
        }
    }
    else if (vlen > 0x80) {
        int lenlen = vlen - 0x80;
        if (CheckOff(off + lenlen - 1, lim)) return FALSE;
        vlen = 0;
        while (lenlen-- > 0) {
            if (vlen > 0x7FFFFF) {
                BeaconPrintf(CALLBACK_ERROR, "length overflow\n");
                return FALSE;
            }
            vlen = (vlen << 8) + buf[off++];
        }
    }

    *valOff = off;
    if (vlen < 0) {
        for (;;) {
            int tc2, tv2, valOff2, valLen2;
            BOOL cons2;
            int slen = 0;
            if (!BytesToAsnDecode9(buf, off, lim - off, &tc2, &tv2, &cons2, &valOff2, &valLen2, &slen))
                return FALSE;
            if (tc2 == 0 && tv2 == 0) {
                if (cons2 || valLen2 != 0) {
                    BeaconPrintf(CALLBACK_ERROR, "invalid null tag\n");
                    return FALSE;
                }
                *valLen = off - *valOff;
                off += slen;
                break;
            }
            else {
                off += slen;
            }
        }
    }
    else {
        if (vlen > (lim - off)) {
            BeaconPrintf(CALLBACK_ERROR, "value overflow\n");
            return FALSE;
        }
        off += vlen;
        *valLen = off - *valOff;
    }
    *ret = off - orig;
    return TRUE;
}

BOOL BytesToAsnDecode4(unsigned char* buf, int off, int len, BOOL exactLength, AsnElt* a) {
    int tc, tv, valOff, valLen, objLen;
    BOOL cons;
    if (!BytesToAsnDecode9(buf, off, len, &tc, &tv, &cons, &valOff, &valLen, &objLen)) return FALSE;
    if (exactLength && objLen != len) {
        BeaconPrintf(CALLBACK_ERROR, "trailing garbage\n");
        return FALSE;
    }
    unsigned char* nbuf = 0;
    if (!MemCopy(&nbuf, buf + off, objLen)) return FALSE;
    return DecodeNoCopy(nbuf, 0, objLen, a);
}

BOOL BytesToAsnDecode3(unsigned char* buf, int len, BOOL exactLength, AsnElt* a) {
    return BytesToAsnDecode4(buf, 0, len, exactLength, a);
}

BOOL BytesToAsnDecode(unsigned char* buf, int len, AsnElt* a) {
    return BytesToAsnDecode4(buf, 0, len, TRUE, a);
}

// ==================== Element construction primitives ====================

BOOL IsLittleEndian() {
    int num = 1;
    return (*((unsigned char*)&num) == 1);
}

void ReverseBytes(unsigned char* bytes, size_t length) {
    unsigned char temp;
    for (size_t i = 0; i < length / 2; i++) {
        temp = bytes[i];
        bytes[i] = bytes[length - i - 1];
        bytes[length - i - 1] = temp;
    }
}

void FlasToBytes(UINT32 Options, unsigned char* OptionsBytes) {
    *((UINT32*)OptionsBytes) = Options;
    if (IsLittleEndian())
        ReverseBytes(OptionsBytes, sizeof(UINT32));
}

int CodePoint(wchar_t* str, int* offset) {
    int c = str[(*offset)++];
    if (c >= 0xD800 && c < 0xDC00 && *offset < (int)MSVCRT$wcslen(str)) {
        int d = str[(*offset)];
        if (d >= 0xDC00 && d < 0xE000) {
            (*offset)++;
            c = ((c & 0x3FF) << 10) + (d & 0x3FF) + 0x10000;
        }
    }
    return c;
}

BOOL EncodeMono(wchar_t* str, int* len, unsigned char** ms) {
    *len = (int)MSVCRT$wcslen(str);
    *ms = MemAlloc(*len);
    int k = 0;
    while (*str != L'\0') {
        (*ms)[k++] = (unsigned char)*str;
        str++;
    }
    return TRUE;
}

BOOL EncodeUTF8(wchar_t* str, int* len, unsigned char** ms) {
    int k = 0;
    int n = (int)MSVCRT$wcslen(str);
    int size = 0;
    *ms = MemAlloc(n * 4);
    while (k < n) {
        int cp = CodePoint(str, &k);
        if (cp < 0x80) {
            (*ms)[size++] = (unsigned char)cp;
        }
        else if (cp < 0x800) {
            (*ms)[size++] = (unsigned char)(0xC0 + (cp >> 6));
            (*ms)[size++] = (unsigned char)(0x80 + (cp & 63));
        }
        else if (cp < 0x10000) {
            (*ms)[size++] = (unsigned char)(0xE0 + (cp >> 12));
            (*ms)[size++] = (unsigned char)(0x80 + ((cp >> 6) & 63));
            (*ms)[size++] = (unsigned char)(0x80 + (cp & 63));
        }
        else {
            (*ms)[size++] = (unsigned char)(0xF0 + (cp >> 18));
            (*ms)[size++] = (unsigned char)(0x80 + ((cp >> 12) & 63));
            (*ms)[size++] = (unsigned char)(0x80 + ((cp >> 6) & 63));
            (*ms)[size++] = (unsigned char)(0x80 + (cp & 63));
        }
    }
    *len = size;
    return TRUE;
}

BOOL EncodeUTF16(const wchar_t* str, int* lenr, unsigned char** buf) {
    size_t len = MSVCRT$wcslen(str);
    *buf = MemAlloc(len * 2);
    int k = 0;
    for (size_t i = 0; i < len; i++) {
        char c = (char)str[i];
        (*buf)[k++] = (unsigned char)(c >> 8);
        (*buf)[k++] = (unsigned char)c;
    }
    *lenr = (int)(len * 2);
    return TRUE;
}

BOOL EncodeUTF32(const wchar_t* str, int* len, unsigned char** ms) {
    size_t k = 0;
    size_t n = MSVCRT$wcslen(str);
    size_t size = 0;
    *ms = MemAlloc(n * 4);
    while (k < n) {
        int cp = CodePoint((wchar_t*)str, (int*)&k);
        (*ms)[size++] = (unsigned char)(cp >> 24);
        (*ms)[size++] = (unsigned char)(cp >> 16);
        (*ms)[size++] = (unsigned char)(cp >> 8);
        (*ms)[size++] = (unsigned char)cp;
    }
    *len = (int)size;
    return TRUE;
}

BOOL MakePrimitiveInner(int tagClass, int tagValue, unsigned char* val, int off, int len, AsnElt* a) {
    a->objBufSize = len;
    if (!MemCopy(&(a->objBuf), val + off, len)) return FALSE;
    a->objOff = 0;
    a->objLen = -1;
    a->valOff = 0;
    a->valLen = len;
    a->hasEncodedHeader = FALSE;
    a->tagClass = tagClass;
    a->tagValue = tagValue;
    a->sub = NULL;
    a->subCount = 0;
    return TRUE;
}

BOOL MakeIntegerLong(long long x, AsnElt* asn_elt) {
    int k = 1;
    if (x >= 0) {
        for (unsigned long long w = x; w >= 0x80; w >>= 8)
            k++;
    }
    else {
        for (long long w = x; w <= -(long)0x80; w >>= 8)
            k++;
    }
    unsigned char* v = MemAlloc(k);
    if (!v) return FALSE;
    int len = k;
    for (long long w = x; k > 0; w >>= 8)
        v[--k] = (unsigned char)w;
    return MakePrimitiveInner(ASN_UNIVERSAL, ASN_INTEGER, v, 0, len, asn_elt);
}

BOOL Make4(int tagClass, int tagValue, AsnElt* subs, int subsCount, AsnElt* a) {
    if (!a) return FALSE;
    if (tagClass < 0 || tagClass > 3 || tagValue < 0) {
        BeaconPrintf(CALLBACK_ERROR, "Invalid: tag class - %d, tag value - %d\n", tagClass, tagValue);
        return FALSE;
    }
    a->objBuf = NULL;
    a->objBufSize = 0;
    a->objOff = 0;
    a->objLen = -1;
    a->valOff = 0;
    a->valLen = -1;
    a->hasEncodedHeader = FALSE;
    a->tagClass = tagClass;
    a->tagValue = tagValue;
    if (subs == NULL) {
        a->subCount = 0;
        a->sub = 0;
    }
    else {
        a->subCount = subsCount;
        a->sub = MemAlloc(subsCount * sizeof(AsnElt));
        if (!a->sub) {
            BeaconPrintf(CALLBACK_ERROR, "[-] Failed alloc memory");
            return FALSE;
        }
        for (int i = 0; i < subsCount; i++)
            a->sub[i] = subs[i];
    }
    return TRUE;
}

BOOL Make3(int tagValue, AsnElt* subs, int subsCount, AsnElt* a) {
    return Make4(ASN_UNIVERSAL, tagValue, subs, subsCount, a);
}

BOOL MakeBlob(unsigned char* buf, int off, int len, AsnElt* a) {
    return MakePrimitiveInner(ASN_UNIVERSAL, ASN_OCTET_STRING, buf, off, len, a);
}

BOOL MakeExplicit(int tagClass, int tagValue, AsnElt* subs, int subsCount, AsnElt* a) {
    return Make4(tagClass, tagValue, subs, subsCount, a);
}

BOOL MakeImplicit(int tagClass, int tagValue, AsnElt* x, AsnElt* a) {
    if (x->sub != NULL)
        return Make4(tagClass, tagValue, x->sub, x->subCount, a);

    a->objOff = 0;
    a->objLen = -1;
    a->hasEncodedHeader = FALSE;
    a->tagClass = tagClass;
    a->tagValue = tagValue;
    a->sub = NULL;
    a->subCount = 0;
    if (x->objBuf) {
        a->objBuf = x->objBuf;
        a->objBufSize = x->objBufSize;
        a->valOff = x->valOff;
        a->valLen = x->valLen;
    }
    else {
        a->objBuf = MemAlloc(EncodedLength(x));
        a->objBufSize = EncodeValue(x, 0, EncodedLength(x), a->objBuf, 0);
        a->valOff = 0;
        a->valLen = x->objBufSize;
    }
    return TRUE;
}

BOOL MakeBitString(unsigned char* buf, size_t off, size_t len, AsnElt* a) {
    unsigned char* tmp = MemAlloc(len + 1);
    if (tmp == NULL)
        return FALSE;
    *tmp = 0;
    MSVCRT$memcpy(tmp + 1, buf + off, len);
    return MakePrimitiveInner(ASN_UNIVERSAL, ASN_BIT_STRING, tmp, 0, (int)(len + 1), a);
}

BOOL MakeString(int type, char* str, AsnElt* a) {
    int wlength = KERNEL32$MultiByteToWideChar(CP_ACP, 0, str, -1, NULL, 0);
    wchar_t* wstr = MemAlloc((wlength) * sizeof(wchar_t));
    KERNEL32$MultiByteToWideChar(CP_ACP, 0, str, -1, wstr, wlength);
    unsigned char* buf = NULL;
    int len = 0;
    if (type == ASN_NumericString || type == ASN_PrintableString || type == ASN_UTCTime || type == ASN_GeneralizedTime || type == ASN_TeletexString || type == ASN_IA5String || type == ASN_GeneralString) {
        if (!EncodeMono(wstr, &len, &buf)) return FALSE;
    }
    if (type == ASN_UTF8String) {
        if (!EncodeUTF8(wstr, &len, &buf)) return FALSE;
    }
    if (type == ASN_BMPString) {
        if (!EncodeUTF16(wstr, &len, &buf)) return FALSE;
    }
    if (type == ASN_UniversalString) {
        if (!EncodeUTF32(wstr, &len, &buf)) return FALSE;
    }
    return MakePrimitiveInner(ASN_UNIVERSAL, type, buf, 0, len, a);
}

BOOL PackIntegerLong(int tagValue, int var, AsnElt* varSeqContext) {
    AsnElt varAsn = { 0 }, varSeq = { 0 };
    if (!MakeIntegerLong(var, &varAsn)
         || !Make3(ASN_SEQUENCE, &varAsn, 1, &varSeq)
         || !MakeImplicit(ASN_CONTEXT, tagValue, &varSeq, varSeqContext))
        return FALSE;
    return TRUE;
}

BOOL PackString(int tagValue, int type, char* var, AsnElt* varSeqContext) {
    AsnElt varAsn = { 0 }, varSeq = { 0 };
    if (!MakeString(type, var, &varAsn)
         || !Make3(ASN_SEQUENCE, &varAsn, 1, &varSeq)
         || !MakeImplicit(ASN_CONTEXT, tagValue, &varSeq, varSeqContext))
        return FALSE;
    return TRUE;
}

BOOL PackStringExt(int tagValue, int type, int imp_type, char* var, AsnElt* varSeqContext) {
    AsnElt varAsn = { 0 }, var2Asn = { 0 }, varSeq = { 0 };
    if (!MakeString(type, var, &varAsn)
         || !MakeImplicit(ASN_UNIVERSAL, imp_type, &varAsn, &var2Asn)
         || !Make3(ASN_SEQUENCE, &var2Asn, 1, &varSeq)
         || !MakeImplicit(ASN_CONTEXT, tagValue, &varSeq, varSeqContext))
        return FALSE;
    return TRUE;
}

BOOL PackBitString(int tagValue, unsigned char* var, int varLen, AsnElt* varSeqContext) {
    AsnElt varAsn = { 0 }, varSeq = { 0 };
    if (!MakeBitString(var, 0, varLen, &varAsn)
         || !Make3(ASN_SEQUENCE, &varAsn, 1, &varSeq)
         || !MakeImplicit(ASN_CONTEXT, tagValue, &varSeq, varSeqContext))
        return FALSE;
    return TRUE;
}

BOOL PackBlock(int tagValue, unsigned char* var, int varLen, AsnElt* varSeqContext) {
    AsnElt varAsn = { 0 }, varSeq = { 0 };
    if (!MakeBlob(var, 0, varLen, &varAsn)
         || !Make3(ASN_SEQUENCE, &varAsn, 1, &varSeq)
         || !MakeImplicit(ASN_CONTEXT, tagValue, &varSeq, varSeqContext))
        return FALSE;
    return TRUE;
}

// ==================== Time helpers ====================

DateTime GetLocalTimeAdd(unsigned int add) {
    SYSTEMTIME systemTime;
    KERNEL32$GetSystemTime(&systemTime);
    FILETIME fileTime;
    KERNEL32$SystemTimeToFileTime(&systemTime, &fileTime);
    ULARGE_INTEGER uli;
    uli.LowPart = fileTime.dwLowDateTime;
    uli.HighPart = fileTime.dwHighDateTime;
    uli.QuadPart += ((ULONGLONG)add) * 10000000ULL;
    fileTime.dwLowDateTime = uli.LowPart;
    fileTime.dwHighDateTime = uli.HighPart;
    KERNEL32$FileTimeToSystemTime(&fileTime, &systemTime);
    DateTime dt = { 0 };
    dt.year = systemTime.wYear;
    dt.month = systemTime.wMonth;
    dt.day = systemTime.wDay;
    dt.hour = systemTime.wHour;
    dt.minute = systemTime.wMinute;
    dt.second = systemTime.wSecond;
    return dt;
}

DateTime GetGmTimeAdd(unsigned int add) {
    SYSTEMTIME systemTime;
    KERNEL32$GetSystemTime(&systemTime);
    DateTime dt = { 0 };
    dt.year = systemTime.wYear;
    dt.month = systemTime.wMonth;
    dt.day = systemTime.wDay;
    dt.hour = systemTime.wHour;
    dt.minute = systemTime.wMinute;
    dt.second = systemTime.wSecond;
    return dt;
}

// ==================== High-level decoders ====================

BOOL AsnGetInteger(AsnElt* a, long* ret) {
    if (!a)
        return TRUE;
    if (a->sub) {
        return FALSE;
    }
    int vlen = ValueLength(a);
    if (vlen == 0)
        return FALSE;

    int v = 0;
    if (!ValueByte(a, 0, &v)) return FALSE;

    long long x;
    if ((v & 0x80) != 0) {
        x = -1;
        for (int k = 0; k < vlen; k++) {
            long long l = -1;
            l = l << 55;
            if (x < l)
                return FALSE;
            int ll = 0;
            if (!ValueByte(a, k, &ll))
                return FALSE;
            x = (x << 8) + (long)ll;
        }
    }
    else {
        x = 0;
        for (int k = 0; k < vlen; k++) {
            long long l = 1;
            l = l << 55;
            if (x >= l)
                return FALSE;
            int ll = 0;
            if (!ValueByte(a, k, &ll))
                return FALSE;
            x = (x << 8) + (long)ll;
        }
    }
    *ret = (long)x;
    return TRUE;
}

BOOL AsnGetOctetString3(AsnElt* a, unsigned char* dst, int off, int* ret) {
    if (!a)
        return FALSE;
    if (a->sub) {
        int orig = off;
        for (int i = 0; i < a->subCount; i++) {
            if (CheckTag(&(a->sub[i]), ASN_UNIVERSAL, ASN_OCTET_STRING))
                return FALSE;
            int ii = 0;
            if (!AsnGetOctetString3(&(a->sub[i]), dst, off, &ii))
                return FALSE;
            off += ii;
        }
        *ret = off - orig;
        return TRUE;
    }
    if (dst) {
        *ret = CopyValue3(a, dst, off);
        return TRUE;
    }
    else {
        *ret = ValueLength(a);
        return TRUE;
    }
}

BOOL AsnGetOctetString(AsnElt* a, unsigned char** ret, int* len) {
    if (!AsnGetOctetString3(a, NULL, 0, len)) return FALSE;
    *ret = MemAlloc(*len);
    if (!*ret) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed alloc memory");
        return FALSE;
    }
    if (!AsnGetOctetString3(a, *ret, 0, len))
        return FALSE;
    return TRUE;
}

BOOL AsnGetString(AsnElt* a, unsigned char** ret) {
    int len = 0;
    char* r = 0;
    if (!AsnGetOctetString(a, (unsigned char**)&r, &len)) return FALSE;
    if (!MemCopy(ret, (unsigned char*)r, len + 1))
        return FALSE;
    (*ret)[len] = 0;
    return TRUE;
}

BOOL AsnGetPrincipalName(AsnElt* a, PrincipalName* pname) {
    if (!AsnGetInteger(&(a->sub[0].sub[0]), &(pname->name_type))) return FALSE;
    pname->name_count = a->sub[1].sub[0].subCount;
    pname->name_string = MemAlloc(sizeof(void*) * pname->name_count);
    for (unsigned int i = 0; i < pname->name_count; i++) {
        unsigned char* s = 0;
        int len = ValueLength(&(a->sub[1].sub[0].sub[i]));
        if (!AsnGetString(&(a->sub[1].sub[0].sub[i]), &s))
            return FALSE;
        wchar_t* ws = 0;
        int ws_length = 0;
        if (!DecodeUTF8(s, 0, len, (unsigned char**)&ws, &ws_length)) return FALSE;
        pname->name_string[i] = MemAlloc(ws_length);
        KERNEL32$WideCharToMultiByte(CP_ACP, 0, ws, ws_length, pname->name_string[i], ws_length, NULL, 0);
    }
    return TRUE;
}

BOOL AsnGetEncryptedData(AsnElt* a, EncryptedData* encdata) {
    long tmpLong = 0;
    for (int i = 0; i < a->subCount; i++) {
        switch (a->sub[i].tagValue) {
            case 0:
                if (!AsnGetInteger(&(a->sub[i].sub[0]), &tmpLong)) return FALSE;
                encdata->etype = (int)tmpLong;
                break;
            case 1:
                if (!AsnGetInteger(&(a->sub[i].sub[0]), &tmpLong)) return FALSE;
                encdata->kvno = (unsigned int)(tmpLong & 0x00000000ffffffff);
                break;
            case 2:
                if (!AsnGetOctetString(&(a->sub[i].sub[0]), &(encdata->cipher), (int*)&(encdata->cipher_size))) return FALSE;
                break;
            default:
                break;
        }
    }
    return TRUE;
}

BOOL AsnGetTicket(AsnElt* a, Ticket* ticket) {
    long tmpLong = 0;
    for (int i = 0; i < a->subCount; i++) {
        switch (a->sub[i].tagValue) {
            case 0:
                if (!AsnGetInteger(&(a->sub[i].sub[0]), &tmpLong)) return FALSE;
                ticket->tkt_vno = (int)tmpLong;
                break;
            case 1:
                if (!AsnGetString(&(a->sub[i].sub[0]), (unsigned char**)&(ticket->realm))) return FALSE;
                break;
            case 2:
                if (!AsnGetPrincipalName(&(a->sub[i].sub[0]), &(ticket->sname))) return FALSE;
                break;
            case 3:
                if (!AsnGetEncryptedData(&(a->sub[i].sub[0]), &(ticket->enc_part))) return FALSE;
                break;
            default:
                break;
        }
    }
    return TRUE;
}

BOOL AsnGetErrorCode(AsnElt* a, unsigned int* error) {
    long tmpLong = 0;
    for (int i = 0; i < a->subCount; i++) {
        if (a->sub[i].tagValue == 6) {
            if (!AsnGetInteger(&(a->sub[i].sub[0]), &tmpLong))
                return FALSE;
            *error = (unsigned int)tmpLong;
            break;
        }
    }
    return TRUE;
}

BOOL AsnGetEncryptionKey(AsnElt* a, EncryptionKey* enc_key) {
    long tmpLong = 0;
    AsnElt s = a->sub[0];
    for (int i = 0; i < s.subCount; i++) {
        switch (s.sub[i].tagValue) {
            case 0:
                if (!AsnGetInteger(&(s.sub[i].sub[0]), &tmpLong)) return FALSE;
                enc_key->key_type = (int)tmpLong;
                break;
            case 1:
                if (!AsnGetOctetString(&(s.sub[i].sub[0]), &(enc_key->key_value), (int*)&(enc_key->key_size))) return FALSE;
                break;
            case 2:
                if (!AsnGetOctetString(&(s.sub[i].sub[0]), &(enc_key->key_value), (int*)&(enc_key->key_size))) return FALSE;
                break;
            default:
                break;
        }
    }
    return TRUE;
}

BOOL NodeAsnGetSting(AsnElt* a, int type, int* len, unsigned char** ret) {
    if (a->sub != NULL) {
        BeaconPrintf(CALLBACK_ERROR, "invalid string (constructed)");
        return FALSE;
    }
    if (type == ASN_NumericString || type == ASN_PrintableString || type == ASN_IA5String || type == ASN_TeletexString || type == ASN_UTCTime || type == ASN_GeneralizedTime) {
        if (!DecodeMono(a->objBuf, a->valOff, a->valLen, type, ret, len)) return FALSE;
    }
    else {
        BeaconPrintf(CALLBACK_ERROR, "unsupported string type: %d\n", type);
        return FALSE;
    }
    return TRUE;
}

BOOL AsnGetTime2(AsnElt* a, int type, DateTime* dt) {
    BOOL isGen = FALSE;
    switch (type) {
        case ASN_UTCTime:
            break;
        case ASN_GeneralizedTime:
            isGen = TRUE;
            break;
        default:
            BeaconPrintf(CALLBACK_ERROR, "unsupported date type: %d\n", type);
            return FALSE;
    }

    int sLen = 0;
    unsigned char* s = 0;
    if (!NodeAsnGetSting(a, type, &sLen, &s)) return FALSE;

    for (int i = 0; i < sLen; i++) {
        if (s[i] >= '0' && s[i] <= '9')
            continue;
        if (s[i] == '.' || s[i] == '+' || s[i] == '-' || s[i] == 'Z')
            continue;
        BeaconPrintf(CALLBACK_ERROR, "invalid time string");
        return FALSE;
    }

    BOOL good = TRUE;
    BOOL noTZ = FALSE;
    if (s[sLen - 1] == 'Z') {
        s[sLen - 1] = 0;
        sLen--;
    }
    else {
        int j = IndexOf(s, sLen, '+');
        if (j < 0) {
            j = IndexOf(s, sLen, '-');
        }
        if (j < 0) {
            noTZ = TRUE;
        }
    }

    if ((noTZ && !isGen) || (sLen < 4)) {
        BeaconPrintf(CALLBACK_ERROR, "invalid time string");
        return FALSE;
    }
    unsigned char* stime = s;
    int year = Dec2(stime, 0, &good);
    if (isGen) {
        year = year * 100 + Dec2(stime, 2, &good);
        stime += 4;
        sLen -= 4;
    }
    else {
        if (year < 50) year += 100;
        year += 1900;
        stime += 2;
        sLen -= 2;
    }
    int month = Dec2(stime, 0, &good);
    int day = Dec2(stime, 2, &good);
    int hour = Dec2(stime, 4, &good);
    int minute = Dec2(stime, 6, &good);
    int second = 0;
    int millisecond = 0;
    if (isGen) {
        second = Dec2(stime, 8, &good);
        if (sLen >= 12 && stime[10] == '.') {
            stime += 11;
            for (int i = 0; stime[i]; i++) {
                if (stime[i] < '0' || stime[i] > '9') {
                    good = FALSE;
                    break;
                }
            }
            millisecond = 10 * Dec2(stime, 0, &good) + Dec2(stime, 2, &good) / 10;
        }
        else if (sLen != 10) {
            good = FALSE;
        }
    }
    else {
        switch (sLen) {
            case 8:
                break;
            case 10:
                second = Dec2(s, 8, &good);
                break;
            default:
                BeaconPrintf(CALLBACK_ERROR, "invalid time string");
                return FALSE;
        }
    }

    if (!good) {
        BeaconPrintf(CALLBACK_ERROR, "invalid time string");
        return FALSE;
    }
    if (second == 60)
        second = 59;

    dt->isSet = TRUE;
    dt->year = year;
    dt->month = month;
    dt->day = day;
    dt->hour = hour;
    dt->minute = minute;
    dt->second = second;
    dt->millisecond = millisecond;
    return TRUE;
}

BOOL AsnGetTime(AsnElt* a, DateTime* dt) {
    if (a->tagClass != ASN_UNIVERSAL) {
        BeaconPrintf(CALLBACK_ERROR, "cannot infer date type: %d:%d\n", a->tagClass, a->tagValue);
        return FALSE;
    }
    return AsnGetTime2(a, a->tagValue, dt);
}

BOOL AsnGetLastReq(AsnElt* a, LastReq* last_req) {
    long tmpLong = 0;
    AsnElt s = a->sub[0];
    for (int i = 0; i < s.subCount; i++) {
        switch (s.sub[i].tagValue) {
            case 0:
                if (!AsnGetInteger(&(s.sub[i].sub[0]), &tmpLong)) return FALSE;
                last_req->lr_type = (int)tmpLong;
                break;
            case 1:
                if (!AsnGetTime(&(s.sub[i].sub[0]), &(last_req->lr_value))) return FALSE;
                break;
            default:
                break;
        }
    }
    return TRUE;
}

BOOL AsnGetEncryptedPAData(AsnElt* body, EncryptedPAData* data) {
    for (int i = 0; i < body->sub[0].subCount; i++) {
        long ll = 0;
        switch (body->sub[0].sub[i].tagValue) {
            case 1:
                if (!AsnGetInteger(&(body->sub[0].sub[i].sub[0]), &ll)) return FALSE;
                data->keytype = (int)ll;
                break;
            case 2:
                if (!AsnGetOctetString(&(body->sub[0].sub[i].sub[0]), &(data->keyvalue), &(data->keysize))) return FALSE;
                break;
            default:
                break;
        }
    }
    if (data->keytype == 162) {
        AsnElt ae = { 0 };
        if (!BytesToAsnDecode(data->keyvalue, data->keysize, &ae)) return FALSE;
        if (!AsnGetEncryptionKey(&ae, &(data->encryptionKey))) return FALSE;
    }
    return TRUE;
}

BOOL AsnGetEncKDCRepPart(AsnElt* a, EncKDCRepPart* rep_part) {
    for (int i = 0; i < a->subCount; i++) {
        int tagValue = a->sub[i].tagValue;
        if (tagValue == 0) {
            if (!AsnGetEncryptionKey(&(a->sub[i]), &(rep_part->key))) return FALSE;
        }
        if (tagValue == 1) {
            if (!AsnGetLastReq(&(a->sub[i].sub[0]), &(rep_part->lastReq))) return FALSE;
        }
        if (tagValue == 2) {
            long tmpLong = 0;
            if (!AsnGetInteger(&(a->sub[i].sub[0]), &tmpLong)) return FALSE;
            rep_part->nonce = (unsigned int)tmpLong;
        }
        if (tagValue == 3) {
            if (!AsnGetTime(&(a->sub[i].sub[0]), &(rep_part->key_expiration))) return FALSE;
        }
        if (tagValue == 4) {
            long tmpLong = 0;
            if (!AsnGetInteger(&(a->sub[i].sub[0]), &tmpLong)) return FALSE;
            rep_part->flags = (unsigned int)tmpLong;
        }
        if (tagValue == 5) {
            if (!AsnGetTime(&(a->sub[i].sub[0]), &(rep_part->authtime))) return FALSE;
        }
        if (tagValue == 6) {
            if (!AsnGetTime(&(a->sub[i].sub[0]), &(rep_part->starttime))) return FALSE;
        }
        if (tagValue == 7) {
            if (!AsnGetTime(&(a->sub[i].sub[0]), &(rep_part->endtime))) return FALSE;
        }
        if (tagValue == 8) {
            if (!AsnGetTime(&(a->sub[i].sub[0]), &(rep_part->renew_till))) return FALSE;
        }
        if (tagValue == 9) {
            if (!AsnGetString(&(a->sub[i].sub[0]), (unsigned char**)&(rep_part->realm))) return FALSE;
        }
        if (tagValue == 10) {
            if (!AsnGetPrincipalName(&(a->sub[i].sub[0]), &(rep_part->sname))) return FALSE;
        }
        if (tagValue == 12) {
            if (!AsnGetEncryptedPAData(&(a->sub[i].sub[0]), &(rep_part->encryptedPaData))) return FALSE;
        }
    }
    return TRUE;
}

BOOL AsnGetKrbCredInfo(AsnElt* body, KrbCredInfo* info) {
    for (int i = 0; i < body->subCount; i++) {
        int tagValue = body->sub[i].tagValue;
        if (tagValue == 0) {
            if (!AsnGetEncryptionKey(&(body->sub[i]), &(info->key))) return FALSE;
        }
        if (tagValue == 1) {
            if (!AsnGetString(&(body->sub[i].sub[0]), (unsigned char**)&(info->prealm))) return FALSE;
        }
        if (tagValue == 2) {
            if (!AsnGetPrincipalName(&(body->sub[i].sub[0]), &(info->pname))) return FALSE;
        }
        if (tagValue == 3) {
            long tmpLong = 0;
            if (!AsnGetInteger(&(body->sub[i].sub[0]), &tmpLong)) return FALSE;
            info->flags = (unsigned int)tmpLong;
        }
        if (tagValue == 4) {
            if (!AsnGetTime(&(body->sub[i].sub[0]), &(info->authtime))) return FALSE;
        }
        if (tagValue == 5) {
            if (!AsnGetTime(&(body->sub[i].sub[0]), &(info->starttime))) return FALSE;
        }
        if (tagValue == 6) {
            if (!AsnGetTime(&(body->sub[i].sub[0]), &(info->endtime))) return FALSE;
        }
        if (tagValue == 7) {
            if (!AsnGetTime(&(body->sub[i].sub[0]), &(info->renew_till))) return FALSE;
        }
        if (tagValue == 8) {
            if (!AsnGetString(&(body->sub[i].sub[0]), (unsigned char**)&(info->srealm))) return FALSE;
        }
        if (tagValue == 9) {
            if (!AsnGetPrincipalName(&(body->sub[i].sub[0]), &(info->sname))) return FALSE;
        }
    }
    return TRUE;
}

BOOL AsnGetEncKrbCredPart(AsnElt* body, EncKrbCredPart* cred_part) {
    int octetStringLength = 0;
    unsigned char* octetString = 0;
    if (!AsnGetOctetString(&(body->sub[1].sub[0]), &octetString, &octetStringLength)) return FALSE;

    AsnElt body2 = { 0 };
    if (!BytesToAsnDecode3(octetString, octetStringLength, FALSE, &body2)) return FALSE;

    KrbCredInfo info = { 0 };
    if (!AsnGetKrbCredInfo(&(body2.sub[0].sub[0].sub[0].sub[0]), &info)) return FALSE;

    cred_part->ticket_count = 1;
    cred_part->ticket_info = MemAlloc(cred_part->ticket_count * sizeof(KrbCredInfo));
    cred_part->ticket_info[0] = info;

    return TRUE;
}

BOOL AsnGetKrbCred(AsnElt* body, KRB_CRED* cred) {
    for (int i = 0; i < body->subCount; i++) {
        switch (body->sub[i].tagValue) {
            case 0:
                if (!AsnGetInteger(&(body->sub[i].sub[0]), &(cred->pvno))) return FALSE;
                break;
            case 1:
                if (!AsnGetInteger(&(body->sub[i].sub[0]), &(cred->msg_type))) return FALSE;
                break;
            case 2:
                cred->ticket_count = body->sub[i].sub[0].sub[0].subCount;
                if (cred->ticket_count) {
                    cred->tickets = MemAlloc(sizeof(Ticket) * cred->ticket_count);
                    for (unsigned int j = 0; j < cred->ticket_count; j++) {
                        Ticket ticket = { 0 };
                        if (!AsnGetTicket(&(body->sub[i].sub[0].sub[0].sub[j]), &ticket)) return FALSE;
                        cred->tickets[j] = ticket;
                    }
                }
                break;
            case 3:
                if (!AsnGetEncKrbCredPart(&(body->sub[i].sub[0]), &(cred->enc_part))) return FALSE;
                break;
            default:
                break;
        }
    }
    return TRUE;
}

BOOL AsnGetPaData(AsnElt* body, PA_DATA* padata) {
    unsigned char* valueBytes = NULL;
    int   valueBytesLength = 0;

    if (body->subCount > 1 && body->sub[0].subCount && body->sub[1].subCount) {
        AsnGetInteger(&(body->sub[0].sub[0]), (long*)&(padata->type));
        AsnGetOctetString(&(body->sub[1].sub[0]), &valueBytes, &valueBytesLength);
    }
    else if (body->subCount && body->sub[0].subCount > 1 && body->sub[0].sub[0].subCount && body->sub[0].sub[1].subCount) {
        AsnGetInteger(&(body->sub[0].sub[0].sub[0]), (long*)&(padata->type));
        AsnGetOctetString(&(body->sub[0].sub[1].sub[0]), &valueBytes, &valueBytesLength);
    }
    else {
        return FALSE;
    }

    switch (padata->type) {
        case PADATA_ETYPE_INFO2: {
            padata->value = MemAlloc(sizeof(ETYPE_INFO2_ENTRY));
            int masLength = ValueLength(&(body->sub[1].sub[0]));
            unsigned char* mas = MemAlloc(masLength);
            masLength = EncodeValue(&(body->sub[1].sub[0]), 0, masLength, mas, 0);
            AsnElt ae = { 0 };
            if (!BytesToAsnDecode(mas, masLength, &ae)) return FALSE;

            ETYPE_INFO2_ENTRY* entry = (ETYPE_INFO2_ENTRY*)padata->value;
            long ll = 0;
            for (int i2 = 0; i2 < ae.sub[0].subCount; i2++) {
                switch (ae.sub[0].sub[i2].tagValue) {
                    case 0:
                        if (!AsnGetInteger(&(ae.sub[0].sub[i2].sub[0]), &ll)) return FALSE;
                        entry->etype = (int)ll;
                        break;
                    case 1:
                        if (!AsnGetString(&(ae.sub[0].sub[i2].sub[0]), (unsigned char**)&(entry->salt))) return FALSE;
                        break;
                    default:
                        break;
                }
            }
            break;
        }
        default:
            break;
    }
    return TRUE;
}

BOOL AsnGetTGS_REP(AsnElt* asn_TGS_REP, TGS_REP* tgs_rep) {
    if ((asn_TGS_REP->subCount != 1) || (asn_TGS_REP->sub[0].tagValue != 16)) {
        BeaconPrintf(CALLBACK_ERROR, "First TGS-REP sub should be a sequence\n");
        return FALSE;
    }
    AsnElt* kdc_rep = asn_TGS_REP->sub[0].sub;
    for (int i = 0; i < asn_TGS_REP->sub[0].subCount; i++) {
        int tagValue = kdc_rep[i].tagValue;
        if (tagValue == 0) {
            if (!AsnGetInteger(&(kdc_rep[i].sub[0]), &(tgs_rep->pvno))) return FALSE;
        }
        if (tagValue == 1) {
            if (!AsnGetInteger(&(kdc_rep[i].sub[0]), &(tgs_rep->msg_type))) return FALSE;
        }
        if (tagValue == 2) {
            if (!AsnGetPaData(&(kdc_rep[i].sub[0]), &(tgs_rep->padata))) return FALSE;
        }
        if (tagValue == 3) {
            if (!AsnGetString(&(kdc_rep[i].sub[0]), (unsigned char**)&(tgs_rep->crealm))) return FALSE;
        }
        if (tagValue == 4) {
            if (!AsnGetPrincipalName(&(kdc_rep[i].sub[0]), &(tgs_rep->cname))) return FALSE;
        }
        if (tagValue == 5) {
            if (!AsnGetTicket(&(kdc_rep[i].sub[0].sub[0]), &(tgs_rep->ticket))) return FALSE;
        }
        if (tagValue == 6) {
            if (!AsnGetEncryptedData(&(kdc_rep[i].sub[0]), &(tgs_rep->enc_part))) return FALSE;
        }
    }
    return TRUE;
}

// ==================== High-level encoders ====================

BOOL AsnEncTimeStampToPaDataEncode(EncryptionKey encKey, PA_DATA* pa_data) {
    pa_data->type = PADATA_ENC_TIMESTAMP;

    char datatime[18];
    DateTime dt = GetLocalTimeAdd(0);
    MSVCRT$sprintf(datatime, "%04d%02d%02d%02d%02d%02dZ", dt.year, dt.month, dt.day, dt.hour, dt.minute, dt.second);

    AsnElt patimestampSeqContext = { 0 };
    if (!PackString(0, ASN_GeneralizedTime, datatime, &patimestampSeqContext)) return FALSE;

    AsnElt totalSeq = { 0 };
    if (!Make3(ASN_SEQUENCE, &patimestampSeqContext, 1, &totalSeq)) return FALSE;

    int rawBytesSize = 0;
    unsigned char* rawBytes = 0;
    if (!AsnToBytesEncode(&totalSeq, &rawBytesSize, &rawBytes)) return FALSE;

    unsigned char* encBytes;
    DWORD encSize = 0;
    if (!encrypt(rawBytes, rawBytesSize, encKey.key_value, encKey.key_type, KRB_KEY_USAGE_AS_REQ_PA_ENC_TIMESTAMP, &encBytes, &encSize)) return FALSE;

    EncryptedData* pEncData = MemAlloc(sizeof(EncryptedData));
    if (!pEncData) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed alloc memory");
        return FALSE;
    }
    pEncData->etype = encKey.key_type;
    pEncData->kvno = 0;
    pEncData->cipher = encBytes;
    pEncData->cipher_size = encSize;

    pa_data->value = pEncData;
    return TRUE;
}

BOOL AsnPrincipalNameEncode(PrincipalName* cname, AsnElt* RET) {
    AsnElt nameTypeSeqContext = { 0 };
    if (!PackIntegerLong(0, cname->name_type, &nameTypeSeqContext)) return FALSE;

    AsnElt* strings = MemAlloc(sizeof(AsnElt) * cname->name_count);
    for (unsigned int i = 0; i < cname->name_count; ++i) {
        AsnElt nameStringElt = { 0 }, nameStringEltContext = { 0 };
        if (!MakeString(ASN_UTF8String, cname->name_string[i], &nameStringElt)) return FALSE;
        if (!MakeImplicit(ASN_UNIVERSAL, ASN_GeneralString, &nameStringElt, &nameStringEltContext)) return FALSE;
        strings[i] = nameStringEltContext;
    }

    AsnElt stringSeq = { 0 }, stringSeq2 = { 0 }, stringSeq2Context = { 0 };
    if (!Make3(ASN_SEQUENCE, strings, cname->name_count, &stringSeq)) return FALSE;
    if (!Make3(ASN_SEQUENCE, &stringSeq, 1, &stringSeq2)) return FALSE;
    if (!MakeImplicit(ASN_CONTEXT, 1, &stringSeq2, &stringSeq2Context)) return FALSE;

    AsnElt preseq[] = { nameTypeSeqContext, stringSeq2Context };
    AsnElt seq = { 0 };
    if (!Make3(ASN_SEQUENCE, preseq, 2, &seq)) return FALSE;
    if (!Make3(ASN_SEQUENCE, &seq, 1, RET)) return FALSE;
    return TRUE;
}

BOOL AsnHostAddressEncode(HostAddress* addr, AsnElt* seq) {
    AsnElt addrTypeSeqContext = { 0 };
    if (!PackIntegerLong(0, addr->addr_type, &addrTypeSeqContext)) return FALSE;

    AsnElt addrStringSeqContext = { 0 };
    if (!PackStringExt(1, ASN_TeletexString, ASN_OCTET_STRING, addr->addr_string, &addrStringSeqContext)) return FALSE;

    AsnElt seqTotal[] = { addrTypeSeqContext, addrStringSeqContext };
    if (!Make3(ASN_SEQUENCE, seqTotal, 2, seq)) return FALSE;

    return TRUE;
}

BOOL AsnKerbPaPacRequestEncode(KERB_PA_PAC_REQUEST* value, AsnElt* totalSeq) {
    AsnElt ret = { 0 };
    if (value->include_pac) {
        if (!MakeBlob((unsigned char[]){ 0x30, 0x05, 0xa0, 0x03, 0x01, 0x01, 0x01 }, 0, 7, &ret)) return FALSE;
    }
    else {
        if (!MakeBlob((unsigned char[]){ 0x30, 0x05, 0xa0, 0x03, 0x01, 0x01, 0x00 }, 0, 7, &ret)) return FALSE;
    }
    if (!Make3(ASN_SEQUENCE, &ret, 1, totalSeq)) return FALSE;
    return TRUE;
}

BOOL AsnEncryptedDataEncode(EncryptedData* value, AsnElt* totalSeq) {
    AsnElt etypeSeqContext = { 0 };
    if (!PackIntegerLong(0, (long)value->etype, &etypeSeqContext)) return FALSE;

    AsnElt cipherSeqContext = { 0 };
    if (!PackBlock(2, value->cipher, value->cipher_size, &cipherSeqContext)) return FALSE;

    if (value->kvno != 0) {
        AsnElt kvnoSeqContext = { 0 };
        if (!PackIntegerLong(1, (long)value->kvno, &kvnoSeqContext)) return FALSE;
        AsnElt allSeq[] = { etypeSeqContext, kvnoSeqContext, cipherSeqContext };
        if (!Make3(ASN_SEQUENCE, allSeq, 3, totalSeq)) return FALSE;
    }
    else {
        AsnElt allSeq[] = { etypeSeqContext, cipherSeqContext };
        if (!Make3(ASN_SEQUENCE, allSeq, 2, totalSeq)) return FALSE;
    }
    return TRUE;
}

BOOL AsnEncryptionKeyEncode(EncryptionKey* key, AsnElt* seq2) {
    AsnElt keyTypeSeqContext = { 0 };
    if (!PackIntegerLong(0, (long)key->key_type, &keyTypeSeqContext)) return FALSE;

    AsnElt blobSeqContext = { 0 };
    if (!PackBlock(1, key->key_value, key->key_size, &blobSeqContext)) return FALSE;

    AsnElt seqTotal[] = { keyTypeSeqContext, blobSeqContext };
    AsnElt seq = { 0 };
    if (!Make3(ASN_SEQUENCE, seqTotal, 2, &seq)) return FALSE;
    if (!Make3(ASN_SEQUENCE, &seq, 1, seq2)) return FALSE;
    return TRUE;
}

BOOL AsnTicketEncode(Ticket* ticket, AsnElt* totalSeq2Context) {
    AsnElt tkt_vnoSeqContext = { 0 };
    if (!PackIntegerLong(0, ticket->tkt_vno, &tkt_vnoSeqContext)) return FALSE;

    AsnElt realmAsnSeqContext = { 0 };
    if (!PackStringExt(1, ASN_IA5String, ASN_GeneralString, ticket->realm, &realmAsnSeqContext)) return FALSE;

    AsnElt snameAsn = { 0 }, snameAsnContext = { 0 };
    if (!AsnPrincipalNameEncode(&(ticket->sname), &snameAsn)) return FALSE;
    if (!MakeImplicit(ASN_CONTEXT, 2, &snameAsn, &snameAsnContext)) return FALSE;

    AsnElt enc_partAsn = { 0 }, enc_partSeq = { 0 }, enc_partSeqContext = { 0 };
    if (!AsnEncryptedDataEncode(&(ticket->enc_part), &enc_partAsn)) return FALSE;
    if (!Make3(ASN_SEQUENCE, &enc_partAsn, 1, &enc_partSeq)) return FALSE;
    if (!MakeImplicit(ASN_CONTEXT, 3, &enc_partSeq, &enc_partSeqContext)) return FALSE;

    AsnElt seqTotal[] = { tkt_vnoSeqContext, realmAsnSeqContext, snameAsnContext, enc_partSeqContext };
    AsnElt totalSeq = { 0 }, totalSeq2 = { 0 };
    if (!Make3(ASN_SEQUENCE, seqTotal, 4, &totalSeq)) return FALSE;
    if (!Make3(ASN_SEQUENCE, &totalSeq, 1, &totalSeq2)) return FALSE;
    if (!MakeImplicit(ASN_APPLICATION, 1, &totalSeq2, totalSeq2Context)) return FALSE;

    return TRUE;
}

BOOL AsnKDCReqBodyEncode(KDCReqBody* req_body, AsnElt* RET) {
    DWORD allNodesCount = 6;
    DWORD allNodesIndex = 0;
    if (req_body->cname.name_count)                     allNodesCount++;
    if (req_body->rtime > 0)                            allNodesCount++;
    if (req_body->addresses_count > 0)                  allNodesCount++;
    if (req_body->enc_authorization_data.cipher_size > 0) allNodesCount++;
    if (req_body->additional_tickets_count > 0)         allNodesCount++;
    AsnElt* allNodes = MemAlloc(sizeof(AsnElt) * allNodesCount);

    unsigned char kdcOptionsBytes[sizeof(UINT32)];
    FlasToBytes(req_body->kdc_options, kdcOptionsBytes);
    AsnElt kdcOptionsSeqContext = { 0 };
    if (!PackBitString(0, kdcOptionsBytes, sizeof(UINT32), &kdcOptionsSeqContext)) return FALSE;
    allNodes[allNodesIndex++] = kdcOptionsSeqContext;

    if (req_body->cname.name_count) {
        AsnElt cnameElt = { 0 }, cnameEltContext = { 0 };
        if (!AsnPrincipalNameEncode(&(req_body->cname), &cnameElt)) return FALSE;
        if (!MakeImplicit(ASN_CONTEXT, 1, &cnameElt, &cnameEltContext)) return FALSE;
        allNodes[allNodesIndex++] = cnameEltContext;
    }

    AsnElt realmSeqContext = { 0 };
    if (!PackStringExt(2, ASN_IA5String, ASN_GeneralString, req_body->realm, &realmSeqContext)) return FALSE;
    allNodes[allNodesIndex++] = realmSeqContext;

    AsnElt snameElt = { 0 }, snameEltContext = { 0 };
    if (!AsnPrincipalNameEncode(&(req_body->sname), &snameElt)) return FALSE;
    if (!MakeImplicit(ASN_CONTEXT, 3, &snameElt, &snameEltContext)) return FALSE;
    allNodes[allNodesIndex++] = snameEltContext;

    char datatime[18];
    DateTime dt = GetLocalTimeAdd(req_body->till);
    MSVCRT$sprintf(datatime, "%04d%02d%02d%02d%02d%02dZ", dt.year, dt.month, dt.day, dt.hour, dt.minute, dt.second);
    AsnElt tillSeqContext = { 0 };
    if (!PackString(5, ASN_GeneralizedTime, datatime, &tillSeqContext)) return FALSE;
    allNodes[allNodesIndex++] = tillSeqContext;

    if (req_body->rtime > 0) {
        char tilltime[18];
        dt = GetLocalTimeAdd(req_body->rtime);
        MSVCRT$sprintf(tilltime, "%04d%02d%02d%02d%02d%02dZ", dt.year, dt.month, dt.day, dt.hour, dt.minute, dt.second);
        AsnElt rtimeSeqContext = { 0 };
        if (!PackString(6, ASN_GeneralizedTime, tilltime, &rtimeSeqContext)) return FALSE;
        allNodes[allNodesIndex++] = rtimeSeqContext;
    }

    AsnElt nonceSeqContext = { 0 };
    if (!PackIntegerLong(7, (LONG)req_body->nonce, &nonceSeqContext)) return FALSE;
    allNodes[allNodesIndex++] = nonceSeqContext;

    AsnElt* etypeList = MemAlloc(sizeof(AsnElt) * req_body->etypes_count);
    for (unsigned int i = 0; i < req_body->etypes_count; ++i) {
        AsnElt etypeAsn = { 0 };
        if (!MakeIntegerLong((LONG)req_body->etypes[i], &etypeAsn)) return FALSE;
        etypeList[i] = etypeAsn;
    }
    AsnElt etypeSeqTotal1 = { 0 }, etypeSeqTotal2 = { 0 }, etypeSeqTotalContext = { 0 };
    if (!Make3(ASN_SEQUENCE, etypeList, req_body->etypes_count, &etypeSeqTotal1)) return FALSE;
    if (!Make3(ASN_SEQUENCE, &etypeSeqTotal1, 1, &etypeSeqTotal2)) return FALSE;
    if (!MakeImplicit(ASN_CONTEXT, 8, &etypeSeqTotal2, &etypeSeqTotalContext)) return FALSE;
    allNodes[allNodesIndex++] = etypeSeqTotalContext;

    if (req_body->addresses_count > 0) {
        AsnElt* addrList = MemAlloc(sizeof(AsnElt) * req_body->addresses_count);
        for (unsigned int i = 0; i < req_body->addresses_count; i++) {
            AsnElt addrElt = { 0 };
            if (!AsnHostAddressEncode(&(req_body->addresses[i]), &addrElt)) return FALSE;
            addrList[i] = addrElt;
        }
        AsnElt addrSeqTotal1 = { 0 }, addrSeqTotal2 = { 0 }, addrSeqTotal2Context = { 0 };
        if (!Make3(ASN_SEQUENCE, addrList, req_body->addresses_count, &addrSeqTotal1)) return FALSE;
        if (!Make3(ASN_SEQUENCE, &addrSeqTotal1, 1, &addrSeqTotal2)) return FALSE;
        if (!MakeImplicit(ASN_CONTEXT, 9, &addrSeqTotal2, &addrSeqTotal2Context)) return FALSE;
        allNodes[allNodesIndex++] = addrSeqTotal2Context;
    }

    if (req_body->enc_authorization_data.cipher_size > 0) {
        AsnElt authEncASN = { 0 }, authEncSeq = { 0 }, authEncSeqContext = { 0 };
        if (!AsnEncryptedDataEncode(&(req_body->enc_authorization_data), &authEncASN)) return FALSE;
        if (!Make3(ASN_SEQUENCE, &authEncASN, 1, &authEncSeq)) return FALSE;
        if (!MakeImplicit(ASN_CONTEXT, 10, &authEncSeq, &authEncSeqContext)) return FALSE;
        allNodes[allNodesIndex++] = authEncSeqContext;
    }

    if (req_body->additional_tickets_count > 0) {
        AsnElt ticketASN = { 0 }, ticketSeq = { 0 }, ticketSeq2 = { 0 }, ticketSeq2Context = { 0 };
        if (!AsnTicketEncode(&(req_body->additional_tickets[0]), &ticketASN)) return FALSE;
        if (!Make3(ASN_SEQUENCE, &ticketASN, 1, &ticketSeq)) return FALSE;
        if (!Make3(ASN_SEQUENCE, &ticketSeq, 1, &ticketSeq2)) return FALSE;
        if (!MakeImplicit(ASN_CONTEXT, 11, &ticketSeq2, &ticketSeq2Context)) return FALSE;
        allNodes[allNodesIndex++] = ticketSeq2Context;
    }

    if (!Make3(ASN_SEQUENCE, allNodes, allNodesCount, RET)) return FALSE;
    return TRUE;
}

BOOL AsnChecksumEncode(Checksum* cksum, AsnElt* totalSeq2) {
    AsnElt cksumtypeSeqContext = { 0 };
    if (!PackIntegerLong(0, cksum->cksumtype, &cksumtypeSeqContext)) return FALSE;

    AsnElt checksumSeqContext = { 0 };
    if (!PackBlock(1, cksum->checksum, cksum->checksum_length, &checksumSeqContext)) return FALSE;

    AsnElt seq[] = { cksumtypeSeqContext, checksumSeqContext };
    AsnElt totalSeq = { 0 };
    if (!Make3(ASN_SEQUENCE, seq, 2, &totalSeq)) return FALSE;
    if (!Make3(ASN_SEQUENCE, &totalSeq, 1, totalSeq2)) return FALSE;
    return TRUE;
}

BOOL AsnAuthenticatorEncode(Authenticator* authenticator, AsnElt* finalContext) {
    DWORD allNodesCount = 5;
    DWORD allNodesIndex = 0;
    if (authenticator->cksum.checksum_length > 0) allNodesCount++;
    if (authenticator->subkey.key_size)           allNodesCount++;
    if (authenticator->seq_number)                allNodesCount++;

    AsnElt* allNodes = MemAlloc(sizeof(AsnElt) * allNodesCount);

    AsnElt pvnoSeqContext = { 0 };
    if (!PackIntegerLong(0, (long)authenticator->authenticator_vno, &pvnoSeqContext)) return FALSE;
    allNodes[allNodesIndex++] = pvnoSeqContext;

    AsnElt prealmAsnSeqContext = { 0 };
    if (!PackStringExt(1, ASN_IA5String, ASN_GeneralString, authenticator->crealm, &prealmAsnSeqContext)) return FALSE;
    allNodes[allNodesIndex++] = prealmAsnSeqContext;

    AsnElt snameElt = { 0 }, snameEltContext = { 0 };
    if (!AsnPrincipalNameEncode(&(authenticator->cname), &snameElt)) return FALSE;
    if (!MakeImplicit(ASN_CONTEXT, 2, &snameElt, &snameEltContext)) return FALSE;
    allNodes[allNodesIndex++] = snameEltContext;

    if (authenticator->cksum.checksum_length > 0) {
        AsnElt checksumAsn = { 0 }, checksumAsnContext = { 0 };
        if (!AsnChecksumEncode(&(authenticator->cksum), &checksumAsn)) return FALSE;
        if (!MakeImplicit(ASN_CONTEXT, 3, &checksumAsn, &checksumAsnContext)) return FALSE;
        allNodes[allNodesIndex++] = checksumAsnContext;
    }

    AsnElt cusecSeqContext = { 0 };
    if (!PackIntegerLong(4, (long)authenticator->cusec, &cusecSeqContext)) return FALSE;
    allNodes[allNodesIndex++] = cusecSeqContext;

    char datatime[18];
    MSVCRT$sprintf(datatime, "%04d%02d%02d%02d%02d%02dZ", authenticator->ctime.year, authenticator->ctime.month, authenticator->ctime.day, authenticator->ctime.hour, authenticator->ctime.minute, authenticator->ctime.second);
    AsnElt tillSeqContext = { 0 };
    if (!PackString(5, ASN_GeneralizedTime, datatime, &tillSeqContext)) return FALSE;
    allNodes[allNodesIndex++] = tillSeqContext;

    if (authenticator->subkey.key_size) {
        AsnElt keyAsn = { 0 }, keyAsnContext = { 0 };
        if (!AsnEncryptionKeyEncode(&(authenticator->subkey), &keyAsn)) return FALSE;
        if (!MakeImplicit(ASN_CONTEXT, 6, &keyAsn, &keyAsnContext)) return FALSE;
        allNodes[allNodesIndex++] = keyAsnContext;
    }

    if (authenticator->seq_number) {
        AsnElt seq_numberSeqContext = { 0 };
        if (!PackIntegerLong(7, (long)authenticator->seq_number, &seq_numberSeqContext)) return FALSE;
        allNodes[allNodesIndex++] = seq_numberSeqContext;
    }

    AsnElt seq = { 0 };
    if (!Make3(ASN_SEQUENCE, allNodes, allNodesCount, &seq)) return FALSE;

    AsnElt finalAsn = { 0 };
    if (!Make3(ASN_SEQUENCE, &seq, 1, &finalAsn)) return FALSE;
    if (!MakeImplicit(ASN_APPLICATION, 2, &finalAsn, finalContext)) return FALSE;

    return TRUE;
}

BOOL AsnApReqEncode(AP_REQ* value, AsnElt* totalSeqContext) {
    AsnElt pvnoSeqContext = { 0 };
    if (!PackIntegerLong(0, (long)value->pvno, &pvnoSeqContext)) return FALSE;

    AsnElt msg_typeSeqContext = { 0 };
    if (!PackIntegerLong(1, (long)value->msg_type, &msg_typeSeqContext)) return FALSE;

    unsigned char ap_optionsBytes[sizeof(UINT32)];
    FlasToBytes(value->ap_options, ap_optionsBytes);
    AsnElt ap_optionsSeqContext = { 0 };
    if (!PackBitString(2, ap_optionsBytes, sizeof(UINT32), &ap_optionsSeqContext)) return FALSE;

    AsnElt ticketASN = { 0 }, ticktSeq = { 0 }, ticktSeqContext = { 0 };
    if (!AsnTicketEncode(&(value->ticket), &ticketASN)) return FALSE;
    if (!Make3(ASN_SEQUENCE, &ticketASN, 1, &ticktSeq)) return FALSE;
    if (!MakeImplicit(ASN_CONTEXT, 3, &ticktSeq, &ticktSeqContext)) return FALSE;

    if (value->key.key_size == 0) {
        BeaconPrintf(CALLBACK_ERROR, "[X] A key for the authenticator is needed to build an AP-REQ\n");
        return FALSE;
    }

    AsnElt authenticatorAsn = { 0 };
    if (!AsnAuthenticatorEncode(&(value->authenticator), &authenticatorAsn)) return FALSE;

    unsigned char* authenticatorBytes = NULL;
    int authenticatorBytesLength = 0;
    if (!AsnToBytesEncode(&authenticatorAsn, &authenticatorBytesLength, &authenticatorBytes)) return FALSE;

    unsigned char* encBytes = NULL;
    DWORD encSize = 0;
    if (!encrypt(authenticatorBytes, authenticatorBytesLength, value->key.key_value, value->key.key_type, value->keyUsage, &encBytes, &encSize)) return FALSE;

    EncryptedData authenticatorEncryptedData = { 0 };
    authenticatorEncryptedData.etype = value->key.key_type;
    authenticatorEncryptedData.cipher = encBytes;
    authenticatorEncryptedData.cipher_size = encSize;

    AsnElt authEncASN = { 0 }, authEncSeq = { 0 }, authEncSeqContext = { 0 };
    if (!AsnEncryptedDataEncode(&authenticatorEncryptedData, &authEncASN)) return FALSE;
    if (!Make3(ASN_SEQUENCE, &authEncASN, 1, &authEncSeq)) return FALSE;
    if (!MakeImplicit(ASN_CONTEXT, 4, &authEncSeq, &authEncSeqContext)) return FALSE;

    AsnElt totalAsn[] = { pvnoSeqContext, msg_typeSeqContext, ap_optionsSeqContext, ticktSeqContext, authEncSeqContext };
    AsnElt seq = { 0 }, totalSeq = { 0 };
    if (!Make3(ASN_SEQUENCE, totalAsn, 5, &seq)) return FALSE;
    if (!Make3(ASN_SEQUENCE, &seq, 1, &totalSeq)) return FALSE;
    if (!MakeImplicit(ASN_APPLICATION, 14, &totalSeq, totalSeqContext)) return FALSE;

    return TRUE;
}

BOOL AsnPaPacOptionsEncode(PA_PAC_OPTIONS* value, AsnElt* seq) {
    AsnElt kerberosFlagsAsn = { 0 }, kerberosFlagsAsnContext = { 0 }, parent = { 0 };
    if (!MakeBitString(value->kerberosFlags, 0, 4, &kerberosFlagsAsn)) return FALSE;
    if (!MakeImplicit(ASN_UNIVERSAL, 3, &kerberosFlagsAsn, &kerberosFlagsAsnContext)) return FALSE;
    if (!Make4(ASN_CONTEXT, 0, &kerberosFlagsAsnContext, 1, &parent)) return FALSE;
    if (!Make3(ASN_SEQUENCE, &parent, 1, seq)) return FALSE;
    return TRUE;
}

BOOL AsnPaDataEncode(PA_DATA padata, AsnElt* seq) {
    AsnElt nameTypeSeqContext = { 0 };
    if (!PackIntegerLong(1, (long)padata.type, &nameTypeSeqContext)) return FALSE;

    if (padata.type == PADATA_PA_PAC_REQUEST) {
        AsnElt paDataElt = { 0 }, paDataEltContext = { 0 };
        if (!AsnKerbPaPacRequestEncode(padata.value, &paDataElt)) return FALSE;
        if (!MakeImplicit(ASN_CONTEXT, 2, &paDataElt, &paDataEltContext)) return FALSE;

        AsnElt seqSubs[] = { nameTypeSeqContext, paDataEltContext };
        if (!Make3(ASN_SEQUENCE, seqSubs, 2, seq)) return FALSE;
    }
    else if (padata.type == PADATA_ENC_TIMESTAMP) {
        AsnElt encData = { 0 };
        if (!AsnEncryptedDataEncode(padata.value, &encData)) return FALSE;

        int encDataBytesSize = 0;
        unsigned char* encDataBytes = 0;
        if (!AsnToBytesEncode(&encData, &encDataBytesSize, &encDataBytes)) return FALSE;

        AsnElt blobSeqContext = { 0 };
        if (!PackBlock(2, encDataBytes, encDataBytesSize, &blobSeqContext)) return FALSE;

        AsnElt allSeq[] = { nameTypeSeqContext, blobSeqContext };
        if (!Make3(ASN_SEQUENCE, allSeq, 2, seq)) return FALSE;
    }
    else if (padata.type == PADATA_AP_REQ) {
        AsnElt encData = { 0 };
        if (!AsnApReqEncode(padata.value, &encData)) return FALSE;

        unsigned char* encDataBytes = NULL;
        int   encDataBytesSize = 0;
        if (!AsnToBytesEncode(&encData, &encDataBytesSize, &encDataBytes)) return FALSE;

        AsnElt paDataElt = { 0 };
        if (!PackBlock(2, encDataBytes, encDataBytesSize, &paDataElt)) return FALSE;

        AsnElt allSeq[] = { nameTypeSeqContext, paDataElt };
        if (!Make3(ASN_SEQUENCE, allSeq, 2, seq)) return FALSE;
    }
    else if (padata.type == PADATA_PA_PAC_OPTIONS) {
        AsnElt encData = { 0 };
        if (!AsnPaPacOptionsEncode(padata.value, &encData)) return FALSE;

        unsigned char* encDataBytes = NULL;
        int   encDataBytesSize = 0;
        if (!AsnToBytesEncode(&encData, &encDataBytesSize, &encDataBytes)) return FALSE;

        AsnElt paDataElt = { 0 };
        if (!PackBlock(2, encDataBytes, encDataBytesSize, &paDataElt)) return FALSE;

        AsnElt allSeq[] = { nameTypeSeqContext, paDataElt };
        if (!Make3(ASN_SEQUENCE, allSeq, 2, seq)) return FALSE;
    }
    else {
        return FALSE;
    }
    return TRUE;
}

BOOL AsnKrbCredInfoEncode(KrbCredInfo* cred_info, AsnElt* seq) {
    DWORD allNodesCount = 2;
    DWORD allNodesIndex = 0;
    if (cred_info->prealm)          allNodesCount++;
    if (cred_info->pname.name_count) allNodesCount++;
    if (cred_info->authtime.isSet)   allNodesCount++;
    if (cred_info->starttime.isSet)  allNodesCount++;
    if (cred_info->endtime.isSet)    allNodesCount++;
    if (cred_info->renew_till.isSet) allNodesCount++;
    if (cred_info->srealm)           allNodesCount++;
    if (cred_info->sname.name_count) allNodesCount++;

    AsnElt* asnElements = MemAlloc(sizeof(AsnElt) * allNodesCount);

    AsnElt keyAsn = { 0 }, keyAsnContext = { 0 };
    if (!AsnEncryptionKeyEncode(&(cred_info->key), &keyAsn)) return FALSE;
    if (!MakeImplicit(ASN_CONTEXT, 0, &keyAsn, &keyAsnContext)) return FALSE;
    asnElements[allNodesIndex++] = keyAsnContext;

    if (cred_info->prealm) {
        AsnElt prealmAsnSeqContext = { 0 };
        if (!PackStringExt(1, ASN_IA5String, ASN_GeneralString, cred_info->prealm, &prealmAsnSeqContext)) return FALSE;
        asnElements[allNodesIndex++] = prealmAsnSeqContext;
    }

    if (cred_info->pname.name_count) {
        AsnElt pnameAsn = { 0 }, pnameAsnContext = { 0 };
        if (!AsnPrincipalNameEncode(&(cred_info->pname), &pnameAsn)) return FALSE;
        if (!MakeImplicit(ASN_CONTEXT, 2, &pnameAsn, &pnameAsnContext)) return FALSE;
        asnElements[allNodesIndex++] = pnameAsnContext;
    }

    unsigned char flagBytes[sizeof(UINT32)];
    FlasToBytes(cred_info->flags, flagBytes);
    AsnElt flagBytesSeqContext = { 0 };
    if (!PackBitString(3, flagBytes, sizeof(UINT32), &flagBytesSeqContext)) return FALSE;
    asnElements[allNodesIndex++] = flagBytesSeqContext;

    if (cred_info->authtime.isSet) {
        char dt[18];
        MSVCRT$sprintf(dt, "%04d%02d%02d%02d%02d%02dZ", cred_info->authtime.year, cred_info->authtime.month, cred_info->authtime.day, cred_info->authtime.hour, cred_info->authtime.minute, cred_info->authtime.second);
        AsnElt ctx = { 0 };
        if (!PackString(4, ASN_GeneralizedTime, dt, &ctx)) return FALSE;
        asnElements[allNodesIndex++] = ctx;
    }

    if (cred_info->starttime.isSet) {
        char dt[18];
        MSVCRT$sprintf(dt, "%04d%02d%02d%02d%02d%02dZ", cred_info->starttime.year, cred_info->starttime.month, cred_info->starttime.day, cred_info->starttime.hour, cred_info->starttime.minute, cred_info->starttime.second);
        AsnElt ctx = { 0 };
        if (!PackString(5, ASN_GeneralizedTime, dt, &ctx)) return FALSE;
        asnElements[allNodesIndex++] = ctx;
    }

    if (cred_info->endtime.isSet) {
        char dt[18];
        MSVCRT$sprintf(dt, "%04d%02d%02d%02d%02d%02dZ", cred_info->endtime.year, cred_info->endtime.month, cred_info->endtime.day, cred_info->endtime.hour, cred_info->endtime.minute, cred_info->endtime.second);
        AsnElt ctx = { 0 };
        if (!PackString(6, ASN_GeneralizedTime, dt, &ctx)) return FALSE;
        asnElements[allNodesIndex++] = ctx;
    }

    if (cred_info->renew_till.isSet) {
        char dt[18];
        MSVCRT$sprintf(dt, "%04d%02d%02d%02d%02d%02dZ", cred_info->renew_till.year, cred_info->renew_till.month, cred_info->renew_till.day, cred_info->renew_till.hour, cred_info->renew_till.minute, cred_info->renew_till.second);
        AsnElt ctx = { 0 };
        if (!PackString(7, ASN_GeneralizedTime, dt, &ctx)) return FALSE;
        asnElements[allNodesIndex++] = ctx;
    }

    if (cred_info->srealm) {
        AsnElt srealmAsnSeqContext = { 0 };
        if (!PackStringExt(8, ASN_IA5String, ASN_GeneralString, cred_info->srealm, &srealmAsnSeqContext)) return FALSE;
        asnElements[allNodesIndex++] = srealmAsnSeqContext;
    }

    if (cred_info->sname.name_count) {
        AsnElt pnameAsn = { 0 }, pnameAsnContext = { 0 };
        if (!AsnPrincipalNameEncode(&(cred_info->sname), &pnameAsn)) return FALSE;
        if (!MakeImplicit(ASN_CONTEXT, 9, &pnameAsn, &pnameAsnContext)) return FALSE;
        asnElements[allNodesIndex++] = pnameAsnContext;
    }

    if (!Make3(ASN_SEQUENCE, asnElements, allNodesCount, seq)) return FALSE;
    return TRUE;
}

BOOL AsnEncKrbCredPartEncode(EncKrbCredPart* cred_part, AsnElt* totalSeq2Context) {
    AsnElt infoAsn = { 0 }, seq1 = { 0 }, seq2 = { 0 }, seq2Context = { 0 };
    if (!AsnKrbCredInfoEncode(&(cred_part->ticket_info[0]), &infoAsn)) return FALSE;
    if (!Make3(ASN_SEQUENCE, &infoAsn, 1, &seq1)) return FALSE;
    if (!Make3(ASN_SEQUENCE, &seq1, 1, &seq2)) return FALSE;
    if (!MakeImplicit(ASN_CONTEXT, 0, &seq2, &seq2Context)) return FALSE;

    AsnElt totalSeq = { 0 }, totalSeq2 = { 0 };
    if (!Make3(ASN_SEQUENCE, &seq2Context, 1, &totalSeq)) return FALSE;
    if (!Make3(ASN_SEQUENCE, &totalSeq, 1, &totalSeq2)) return FALSE;
    if (!MakeImplicit(ASN_APPLICATION, 29, &totalSeq2, totalSeq2Context)) return FALSE;

    return TRUE;
}

BOOL AsnKrbCredEncode(KRB_CRED* krb_cred, AsnElt* finalContext) {
    AsnElt pvnoSeqContext = { 0 };
    if (!PackIntegerLong(0, krb_cred->pvno, &pvnoSeqContext)) return FALSE;

    AsnElt msg_typeSeqContext = { 0 };
    if (!PackIntegerLong(1, krb_cred->msg_type, &msg_typeSeqContext)) return FALSE;

    AsnElt ticketAsn = { 0 }, ticketSeq = { 0 }, ticketSeq2 = { 0 }, ticketSeq2Context = { 0 };
    if (!AsnTicketEncode(&(krb_cred->tickets[0]), &ticketAsn)) return FALSE;
    if (!Make3(ASN_SEQUENCE, &ticketAsn, 1, &ticketSeq)) return FALSE;
    if (!Make3(ASN_SEQUENCE, &ticketSeq, 1, &ticketSeq2)) return FALSE;
    if (!MakeImplicit(ASN_CONTEXT, 2, &ticketSeq2, &ticketSeq2Context)) return FALSE;

    AsnElt enc_partAsn = { 0 };
    if (!AsnEncKrbCredPartEncode(&(krb_cred->enc_part), &enc_partAsn)) return FALSE;
    int blobBytesSize = 0;
    unsigned char* blobBytes = 0;
    if (!AsnToBytesEncode(&enc_partAsn, &blobBytesSize, &blobBytes)) return FALSE;

    AsnElt blobSeqContext = { 0 };
    if (!PackBlock(2, blobBytes, blobBytesSize, &blobSeqContext)) return FALSE;

    AsnElt etypeSeqContext = { 0 };
    if (!PackIntegerLong(0, 0, &etypeSeqContext)) return FALSE;

    AsnElt encSeq[] = { etypeSeqContext, blobSeqContext };
    AsnElt infoSeq = { 0 }, infoSeq2 = { 0 }, infoSeq2Context = { 0 };
    if (!Make3(ASN_SEQUENCE, encSeq, 2, &infoSeq)) return FALSE;
    if (!Make3(ASN_SEQUENCE, &infoSeq, 1, &infoSeq2)) return FALSE;
    if (!MakeImplicit(ASN_CONTEXT, 3, &infoSeq2, &infoSeq2Context)) return FALSE;

    AsnElt seqTotal[] = { pvnoSeqContext, msg_typeSeqContext, ticketSeq2Context, infoSeq2Context };
    AsnElt total = { 0 };
    if (!Make3(ASN_SEQUENCE, seqTotal, 4, &total)) return FALSE;

    AsnElt finalAsn = { 0 };
    if (!Make3(ASN_SEQUENCE, &total, 1, &finalAsn)) return FALSE;
    if (!MakeImplicit(ASN_APPLICATION, 22, &finalAsn, finalContext)) return FALSE;

    return TRUE;
}

BOOL ReqToAsnEncode(AS_REQ as_req, int APP_NUM, AsnElt* totalSeqApp) {
    AsnElt pvnoContext = { 0 };
    if (!PackIntegerLong(1, as_req.pvno, &pvnoContext)) return FALSE;

    AsnElt msg_type_ASNSeqContext = { 0 };
    if (!PackIntegerLong(2, as_req.msg_type, &msg_type_ASNSeqContext)) return FALSE;

    AsnElt* padatas = MemAlloc(sizeof(AsnElt) * as_req.pa_data_count);
    if (!padatas && as_req.pa_data_count) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed alloc memory\n");
        return FALSE;
    }
    for (unsigned int i = 0; i < as_req.pa_data_count; ++i) {
        AsnElt pd = { 0 };
        if (!AsnPaDataEncode(as_req.pa_data[i], &pd)) return FALSE;
        padatas[i] = pd;
    }

    AsnElt padata_ASNSeq = { 0 }, padata_ASNSeq2 = { 0 }, padata_ASNSeqContext = { 0 };
    if (!Make3(ASN_SEQUENCE, padatas, as_req.pa_data_count, &padata_ASNSeq)) return FALSE;
    if (!Make3(ASN_SEQUENCE, &padata_ASNSeq, 1, &padata_ASNSeq2)) return FALSE;
    if (!MakeImplicit(ASN_CONTEXT, 3, &padata_ASNSeq2, &padata_ASNSeqContext)) return FALSE;

    AsnElt req_Body_ASN = { 0 }, req_Body_ASNSeq = { 0 }, req_Body_ASNSeqContext = { 0 };
    if (!AsnKDCReqBodyEncode(&(as_req.req_body), &req_Body_ASN)) return FALSE;
    if (!Make3(ASN_SEQUENCE, &req_Body_ASN, 1, &req_Body_ASNSeq)) return FALSE;
    if (!MakeImplicit(ASN_CONTEXT, 4, &req_Body_ASNSeq, &req_Body_ASNSeqContext)) return FALSE;

    AsnElt total[] = { pvnoContext, msg_type_ASNSeqContext, padata_ASNSeqContext, req_Body_ASNSeqContext };
    AsnElt seq = { 0 };
    if (!Make3(ASN_SEQUENCE, total, 4, &seq)) return FALSE;

    AsnElt totalSeq = { 0 };
    if (!Make3(ASN_SEQUENCE, &seq, 1, &totalSeq)) return FALSE;
    if (!MakeImplicit(ASN_APPLICATION, APP_NUM, &totalSeq, totalSeqApp)) return FALSE;

    return TRUE;
}
