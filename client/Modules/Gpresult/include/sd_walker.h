#ifndef SD_WALKER_H
#define SD_WALKER_H

/*
 * DACL walking + caller-token SID matching for `gpresult domain`.
 * Works on raw self-relative security descriptors straight from LDAP
 * (nTSecurityDescriptor) or from GetFileSecurityA (SYSVOL GPT).
 */

#define SD_MAX_SIDS 256
#define SD_SID_MAX_BYTES 68

typedef struct TokenSidSet {
    void* sids[SD_MAX_SIDS];   /* point into the token buffers below */
    int   count;
    void* bufUser;
    void* bufGroups;
    void* bufPrimary;
} TokenSidSet;

/*
 * Builds the caller's identity from the beacon process token:
 * TokenUser + TokenGroups (enabled, non deny-only) + TokenPrimaryGroup,
 * deduplicated. Returns 0 on success, -1 if no SID could be read.
 */
int  TokenSidsBuild(TokenSidSet* out);
void TokenSidsFree(TokenSidSet* t);

/* ACE types emitted by SdWalkDacl */
#define SD_ACE_ALLOWED     0
#define SD_ACE_DENIED      1
#define SD_ACE_ALLOWED_OBJ 5
#define SD_ACE_DENIED_OBJ  6

/*
 * Invoked for every ACE whose SID is in `toks`.
 * objGuid is "{...}" for object ACEs carrying an ObjectType, else "".
 */
typedef void (*AceHitFn)(void* ctx, unsigned long mask, int aceType,
                         const char* objGuid, void* aceSid, int inherited);

/*
 * Walks the DACL of a raw self-relative SD. Returns the number of matching
 * ACEs, or -1 if the SD carries no readable DACL.
 */
int SdWalkDacl(const void* sdSelfRel, const TokenSidSet* toks, AceHitFn cb, void* ctx);

#endif /* SD_WALKER_H */
