/*
 * sd_walker — caller-token SID set, self-relative SD → DACL walk, SID match.
 *
 * Token-group attribute bits and ACE-object flags come from winnt.h
 * (SE_GROUP_USE_FOR_DENY_ONLY is 0x10 — do NOT hand-define them here).
 */

#include <windows.h>

extern "C" {
    /* ADVAPI32 */
    DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$OpenProcessToken(HANDLE ProcessHandle, DWORD DesiredAccess, PHANDLE TokenHandle);
    DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$GetTokenInformation(HANDLE TokenHandle, TOKEN_INFORMATION_CLASS TokenInformationClass, LPVOID TokenInformation, DWORD TokenInformationLength, PDWORD ReturnLength);
    DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$GetSecurityDescriptorDacl(PSECURITY_DESCRIPTOR pSecurityDescriptor, LPBOOL lpbDaclPresent, PACL* pDacl, LPBOOL lpbDaclDefaulted);
    DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$GetAclInformation(PACL pAcl, LPVOID pAclInformation, DWORD nAclInformationLength, ACL_INFORMATION_CLASS dwAclInformationClass);
    DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$GetAce(PACL pAcl, DWORD dwAceIndex, LPVOID* pAce);
    DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$EqualSid(PSID Sid1, PSID Sid2);

    /* KERNEL32 */
    DECLSPEC_IMPORT HANDLE  WINAPI KERNEL32$GetCurrentProcess(VOID);
    DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$CloseHandle(HANDLE hObject);
    DECLSPEC_IMPORT HLOCAL  WINAPI KERNEL32$LocalAlloc(UINT uFlags, SIZE_T dwBytes);
    DECLSPEC_IMPORT HLOCAL  WINAPI KERNEL32$LocalFree(HLOCAL hMem);

    /* MSVCRT */
    DECLSPEC_IMPORT int   __cdecl MSVCRT$sprintf(char* d, const char* fmt, ...);
}

#include "sd_walker.h"

static int TokenHasSid(const TokenSidSet* t, void* sid)
{
    for (int i = 0; i < t->count; i++)
        if (ADVAPI32$EqualSid((PSID)t->sids[i], (PSID)sid)) return 1;
    return 0;
}

int TokenSidsBuild(TokenSidSet* out)
{
    HANDLE hTok = NULL;
    DWORD  need = 0;

    out->count = 0;
    out->bufUser = out->bufGroups = out->bufPrimary = NULL;

    if (!ADVAPI32$OpenProcessToken(KERNEL32$GetCurrentProcess(), TOKEN_QUERY, &hTok))
        return -1;

    /* TokenUser */
    need = 0;
    ADVAPI32$GetTokenInformation(hTok, TokenUser, NULL, 0, &need);
    if (need) {
        out->bufUser = KERNEL32$LocalAlloc(LMEM_FIXED, need);
        if (out->bufUser &&
            ADVAPI32$GetTokenInformation(hTok, TokenUser, out->bufUser, need, &need)) {
            TOKEN_USER* tu = (TOKEN_USER*)out->bufUser;
            if (tu && tu->User.Sid)
                out->sids[out->count++] = tu->User.Sid;
        }
    }

    /* TokenGroups — only groups that actually grant access: enabled and not
     * deny-only. Disabled / deny-only SIDs would produce phantom findings. */
    need = 0;
    ADVAPI32$GetTokenInformation(hTok, TokenGroups, NULL, 0, &need);
    if (need) {
        out->bufGroups = KERNEL32$LocalAlloc(LMEM_FIXED, need);
        if (out->bufGroups &&
            ADVAPI32$GetTokenInformation(hTok, TokenGroups, out->bufGroups, need, &need)) {
            TOKEN_GROUPS* tg = (TOKEN_GROUPS*)out->bufGroups;
            for (DWORD i = 0; i < tg->GroupCount && out->count < SD_MAX_SIDS; i++) {
                PSID  sid   = tg->Groups[i].Sid;
                DWORD attrs = tg->Groups[i].Attributes;
                if (!sid) continue;
                if (attrs & SE_GROUP_USE_FOR_DENY_ONLY) continue;
                if (!(attrs & SE_GROUP_ENABLED)) continue;
                if (TokenHasSid(out, sid)) continue;
                out->sids[out->count++] = sid;
            }
        }
    }

    /* TokenPrimaryGroup — not always present in TokenGroups */
    need = 0;
    ADVAPI32$GetTokenInformation(hTok, TokenPrimaryGroup, NULL, 0, &need);
    if (need) {
        out->bufPrimary = KERNEL32$LocalAlloc(LMEM_FIXED, need);
        if (out->bufPrimary &&
            ADVAPI32$GetTokenInformation(hTok, TokenPrimaryGroup, out->bufPrimary, need, &need)) {
            TOKEN_PRIMARY_GROUP* tp = (TOKEN_PRIMARY_GROUP*)out->bufPrimary;
            if (tp && tp->PrimaryGroup && out->count < SD_MAX_SIDS &&
                !TokenHasSid(out, tp->PrimaryGroup))
                out->sids[out->count++] = tp->PrimaryGroup;
        }
    }

    KERNEL32$CloseHandle(hTok);
    return out->count ? 0 : -1;
}

void TokenSidsFree(TokenSidSet* t)
{
    if (t->bufUser)    KERNEL32$LocalFree((HLOCAL)t->bufUser);
    if (t->bufGroups)  KERNEL32$LocalFree((HLOCAL)t->bufGroups);
    if (t->bufPrimary) KERNEL32$LocalFree((HLOCAL)t->bufPrimary);
    t->bufUser = t->bufGroups = t->bufPrimary = NULL;
    t->count = 0;
}

static void GuidToStr(const GUID* g, char* out)
{
    MSVCRT$sprintf(out, "{%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
                   (unsigned)g->Data1, (unsigned)g->Data2, (unsigned)g->Data3,
                   g->Data4[0], g->Data4[1], g->Data4[2], g->Data4[3],
                   g->Data4[4], g->Data4[5], g->Data4[6], g->Data4[7]);
}

int SdWalkDacl(const void* sdSelfRel, const TokenSidSet* toks, AceHitFn cb, void* ctx)
{
    BOOL present = FALSE, defaulted = FALSE;
    PACL dacl = NULL;
    ACL_SIZE_INFORMATION sz;
    int hits = 0;

    if (!sdSelfRel || !toks || toks->count == 0) return -1;
    if (!ADVAPI32$GetSecurityDescriptorDacl((PSECURITY_DESCRIPTOR)sdSelfRel, &present, &dacl, &defaulted))
        return -1;
    if (!present || !dacl) return -1;
    if (!ADVAPI32$GetAclInformation(dacl, &sz, sizeof(sz), AclSizeInformation))
        return -1;

    for (DWORD i = 0; i < sz.AceCount; i++) {
        void*          ace = NULL;
        unsigned char  type, flags;
        unsigned long  mask;
        unsigned char* sid = NULL;
        char           guid[40];
        int            emitType = -1;

        guid[0] = '\0';
        if (!ADVAPI32$GetAce(dacl, i, &ace) || !ace) continue;

        type  = ((unsigned char*)ace)[0];
        flags = ((unsigned char*)ace)[1];
        mask  = *(unsigned long*)((unsigned char*)ace + 4);

        switch (type) {
        case SD_ACE_ALLOWED:
        case SD_ACE_DENIED:
            sid = (unsigned char*)ace + 8;
            emitType = (int)type;
            break;
        case SD_ACE_ALLOWED_OBJ:
        case SD_ACE_DENIED_OBJ: {
            unsigned char* p = (unsigned char*)ace + 8;
            if (flags & ACE_OBJECT_TYPE_PRESENT) {
                GuidToStr((const GUID*)p, guid);
                p += 16;
            }
            if (flags & ACE_INHERITED_OBJECT_TYPE_PRESENT)
                p += 16;
            sid = p;
            emitType = (int)type;
            break;
        }
        default:
            continue;   /* audit/alarm/callback types are out of scope */
        }

        if (!sid) continue;

        for (int t = 0; t < toks->count; t++) {
            if (ADVAPI32$EqualSid((PSID)sid, (PSID)toks->sids[t])) {
                cb(ctx, mask, emitType, guid, sid, (flags & INHERITED_ACE) ? 1 : 0);
                hits++;
                break;   /* one finding per ACE */
            }
        }
    }
    return hits;
}
