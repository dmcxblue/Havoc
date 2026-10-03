/*
 * gpo_rights_table — mask/GUID classification for `gpresult domain`.
 *
 * Deliberately self-contained (no windows.h) so it can be smoke-tested
 * natively on the build host: only MSVCRT$sprintf is imported, via a
 * dllimport guard that turns into a plain extern for the native test.
 *
 * Classification precedece: deny → full control → WriteDacl → WriteOwner →
 * SYSVOL file write bits → GenericWrite → WriteProperty (per ObjectType) →
 * SELF → ControlAccess → CreateChild → DELETE → read-only.
 *
 * Attribute Schema-ID-GUIDs verified against Microsoft Learn
 * (learn.microsoft.com/windows/win32/adschema/a-<name>):
 *   gPLink                  f30e3bbe-9ff0-11d1-b603-0000f80367c1
 *   gPOptions               f30e3bbf-9ff0-11d1-b603-0000f80367c1
 *   gPCFileSysPath          f30e3bc1-9ff0-11d1-b603-0000f80367c1
 *   gPCMachineExtensionNames 32ff8ecc-783f-11d2-9916-0000f87a57d4
 *   gPCUserExtensionNames   42a75fc6-783f-11d2-9916-0000f87a57d4
 *   nTSecurityDescriptor    bf9679e3-0de6-11d0-a285-00aa003049e2
 *   versionNumber           bf967a76-0de6-11d0-a285-00aa003049e2
 *   msWMI-Parm1             27e81485-b1b0-4a8b-bedd-ce19a837e26e
 *   msWMI-Parm2             0003508e-9c42-4a76-a8f4-38bf64bab0de
 */

#ifdef _WIN32
#define DFR_IMPORT __declspec(dllimport)
#else
#define DFR_IMPORT extern
#endif
#ifndef __cdecl
#define __cdecl
#endif

extern "C" {
DFR_IMPORT int __cdecl MSVCRT$sprintf(char* d, const char* fmt, ...);
}

#include "gpo_rights_table.h"
#include "sd_walker.h"   /* SD_ACE_* */

/* ADS_RIGHT_* (winnt.h values) */
#define ADS_RIGHT_CREATE_CHILD      0x00000001
#define ADS_RIGHT_DELETE_CHILD      0x00000002
#define ADS_RIGHT_ACTRL_DS_LIST     0x00000004
#define ADS_RIGHT_DS_SELF           0x00000008
#define ADS_RIGHT_DS_READ_PROP      0x00000010
#define ADS_RIGHT_DS_WRITE_PROP     0x00000020
#define ADS_RIGHT_DS_DELETE_TREE    0x00000040
#define ADS_RIGHT_DS_LIST_OBJECT    0x00000080
#define ADS_RIGHT_DS_CONTROL_ACCESS 0x00000100
#define ADS_RIGHT_DELETE            0x00010000
#define ADS_RIGHT_READ_CONTROL      0x00020000
#define ADS_RIGHT_WRITE_DAC         0x00040000
#define ADS_RIGHT_WRITE_OWNER       0x00080000
#define ADS_GENERIC_READ            0x80000000
#define ADS_GENERIC_WRITE           0x40000000
#define ADS_GENERIC_ALL             0x10000000

/* generic-mapped full control on AD objects (what GENERIC_ALL maps to) */
#define GPO_FULL_MASK 0x000F01FF

/* FILE_* write bits (winnt.h values) — note FILE_WRITE_EA is 0x10;
 * 0x08 is FILE_READ_EA and lives inside FILE_GENERIC_READ */
#define FILE_WRITE_DATA         0x00000002
#define FILE_APPEND_DATA        0x00000004
#define FILE_WRITE_EA           0x00000010
#define FILE_WRITE_ATTRIBUTES   0x00000100
#define FILE_GENERIC_WRITE_MASK 0x00120116

static const struct GuidName {
    const char* guid;
    const char* name;
} kAttrGuids[] = {
    /* braces: must match the string form SdWalkDacl's GuidToStr() emits */
    { "{F30E3BBE-9FF0-11D1-B603-0000F80367C1}", "gPLink" },
    { "{F30E3BBF-9FF0-11D1-B603-0000F80367C1}", "gPOptions" },
    { "{F30E3BC1-9FF0-11D1-B603-0000F80367C1}", "gPCFileSysPath" },
    { "{32FF8ECC-783F-11D2-9916-0000F87A57D4}", "gPCMachineExtensionNames" },
    { "{42A75FC6-783F-11D2-9916-0000F87A57D4}", "gPCUserExtensionNames" },
    { "{BF9679E3-0DE6-11D0-A285-00AA003049E2}", "nTSecurityDescriptor" },
    { "{BF967A76-0DE6-11D0-A285-00AA003049E2}", "versionNumber" },
    { "{27E81485-B1B0-4A8B-BEDD-CE19A837E26E}", "msWMI-Parm1" },
    { "{0003508E-9C42-4A76-A8F4-38BF64BAB0DE}", "msWMI-Parm2" },
};

/* ---- tiny string helpers (no extra CRT) ---- */

static int SLen(const char* s)
{
    int n = 0;
    while (s && s[n]) n++;
    return n;
}

static void SCopy(char* d, int cap, const char* s)
{
    int i = 0;
    if (!s) s = "";
    while (s[i] && i < cap - 1) { d[i] = s[i]; i++; }
    d[i] = '\0';
}

static char IC(char c)
{
    return (c >= 'A' && c <= 'Z') ? (char)(c + ('a' - 'A')) : c;
}

static int SIEq(const char* a, const char* b)
{
    if (!a || !b) return 0;
    while (*a && *b) {
        if (IC(*a) != IC(*b)) return 0;
        a++; b++;
    }
    return (*a == '\0' && *b == '\0');
}

static int SEndsWith(const char* s, const char* suf)
{
    int ls = SLen(s), lf = SLen(suf), i;
    if (lf > ls) return 0;
    for (i = 0; i < lf; i++)
        if (IC(s[ls - lf + i]) != IC(suf[i])) return 0;
    return 1;
}

const char* GuidToAttrName(const char* guid)
{
    for (unsigned i = 0; i < sizeof(kAttrGuids) / sizeof(kAttrGuids[0]); i++)
        if (SIEq(kAttrGuids[i].guid, guid)) return kAttrGuids[i].name;
    return 0;
}

static const char* LinkKind(int surface)
{
    if (surface == SURF_DOMAINROOT) return "domain";
    if (surface == SURF_SITE)       return "site";
    return "OU";
}

static void Set3(ClassOut* o, int sev, const char* label, const char* verb, const char* hint)
{
    o->sev = sev;
    SCopy(o->label, (int)sizeof(o->label), label);
    SCopy(o->verb,  (int)sizeof(o->verb),  verb);
    SCopy(o->hint,  (int)sizeof(o->hint),  hint);
}

void ClassifyAce(const ClassCtx* c, ClassOut* out)
{
    const unsigned long m = c->mask;
    const char* attrName = 0;
    char attrFallback[64];

    attrFallback[0] = '\0';
    if (c->objGuid && c->objGuid[0]) {
        attrName = GuidToAttrName(c->objGuid);
        if (!attrName) {
            SCopy(attrFallback, (int)sizeof(attrFallback), c->objGuid);
            attrName = attrFallback;   /* honest: raw GUID, no guessing */
        }
    }

    /* default: read-only */
    Set3(out, SEV_READ, "ReadProperty+ListChildren", "READ only", "enumeration surface");

    if (c->aceType == SD_ACE_DENIED || c->aceType == SD_ACE_DENIED_OBJ) {
        Set3(out, SEV_READ, "ACCESS_DENIED", "DENY", "deny ACE matches the caller's token");
        return;
    }

    /* full control — raw generic bit or the generic-mapped full mask */
    if ((m & ADS_GENERIC_ALL) || (m & GPO_FULL_MASK) == GPO_FULL_MASK) {
        const char* label = (c->surface == SURF_GPO && m == GPO_FULL_MASK)
                            ? "GpoEditDeleteModifySecurity" : "GenericAll";
        switch (c->surface) {
        case SURF_GPO:    Set3(out, SEV_ACTIONABLE, label, "EDIT",  "plant computer task via SharpGPOAbuse"); break;
        case SURF_SYSVOL: Set3(out, SEV_ACTIONABLE, label, "PLANT", "GPT tree writable"); break;
        case SURF_WMI:    Set3(out, SEV_ACTIONABLE, label, "SCOPE", "replace the WMI filter (full control)"); break;
        default:          Set3(out, SEV_ACTIONABLE, label, "LINK",  "attach any GPO to this object (full control)"); break;
        }
        return;
    }

    if (m & ADS_RIGHT_WRITE_DAC) {
        Set3(out, SEV_ACTIONABLE, "WriteDacl", "WRITE", "rewrite the DACL — grant self FullControl");
        return;
    }
    if (m & ADS_RIGHT_WRITE_OWNER) {
        Set3(out, SEV_ACTIONABLE, "WriteOwner", "TAKEOWN", "take ownership, then rewrite the DACL");
        return;
    }

    if (c->surface == SURF_SYSVOL) {
        const unsigned long wbits = FILE_WRITE_DATA | FILE_APPEND_DATA |
                                    FILE_WRITE_EA | FILE_WRITE_ATTRIBUTES |
                                    ADS_GENERIC_WRITE;
        if (m & wbits) {
            const char* label = ((m & FILE_GENERIC_WRITE_MASK) == FILE_GENERIC_WRITE_MASK)
                                ? "FILE_GENERIC_WRITE" : "FILE_WRITE_*";
            const char* hint = (c->filePath && SEndsWith(c->filePath, "Machine\\Preferences\\ScheduledTasks"))
                               ? "ScheduledTasks.xml writable"
                               : "GPT writable — plant scripts / ScheduledTasks.xml";
            Set3(out, SEV_ACTIONABLE, label, "PLANT", hint);
            return;
        }
        if (m & ADS_RIGHT_DELETE) {
            Set3(out, SEV_LIMITED, "DELETE", "DELETE", "can delete GPT content");
            return;
        }
        return;   /* read-only file ACE */
    }

    if (m & ADS_GENERIC_WRITE) {
        switch (c->surface) {
        case SURF_GPO: Set3(out, SEV_ACTIONABLE, "GenericWrite", "EDIT",  "modify any GPO attribute"); break;
        case SURF_WMI: Set3(out, SEV_ACTIONABLE, "GenericWrite", "SCOPE", "rewrite the WMI filter"); break;
        default:       Set3(out, SEV_ACTIONABLE, "GenericWrite", "LINK",  "write any attribute incl. gPLink"); break;
        }
        return;
    }

    if (m & ADS_RIGHT_DS_WRITE_PROP) {
        if (!attrName) {
            /* blanket WriteProperty = every attribute on the object */
            switch (c->surface) {
            case SURF_GPO: Set3(out, SEV_ACTIONABLE, "WriteProperty (all attributes)", "EDIT",  "modify any GPO attribute"); break;
            case SURF_WMI: Set3(out, SEV_ACTIONABLE, "WriteProperty (all attributes)", "SCOPE", "rewrite the WMI filter"); break;
            default:       Set3(out, SEV_ACTIONABLE, "WriteProperty (all attributes)", "LINK",  "write gPLink on this object"); break;
            }
            return;
        }

        if (SIEq(attrName, "gPLink")) {
            out->sev = SEV_ACTIONABLE;
            SCopy(out->label, (int)sizeof(out->label), "WriteProperty on gPLink");
            SCopy(out->verb,  (int)sizeof(out->verb),  "LINK");
            MSVCRT$sprintf(out->hint, "attach any GPO to this %s", LinkKind(c->surface));
            return;
        }
        if (SIEq(attrName, "gPOptions")) {
            out->sev = SEV_LIMITED;
            SCopy(out->label, (int)sizeof(out->label), "WriteProperty on gPOptions");
            SCopy(out->verb,  (int)sizeof(out->verb),  "LINK");
            MSVCRT$sprintf(out->hint, "toggle link enforcement on this %s", LinkKind(c->surface));
            return;
        }

        if (c->surface == SURF_GPO) {
            if (SIEq(attrName, "nTSecurityDescriptor")) {
                Set3(out, SEV_ACTIONABLE, "WriteProperty on nTSecurityDescriptor", "WRITE",
                     "rewrite the GPO ACL — grant self FullControl");
            } else if (SIEq(attrName, "gPCFileSysPath")) {
                Set3(out, SEV_LIMITED, "WriteProperty on gPCFileSysPath", "WRITE",
                     "retarget the GPT path — plant via SYSVOL");
            } else if (SIEq(attrName, "gPCMachineExtensionNames") ||
                       SIEq(attrName, "gPCUserExtensionNames")) {
                out->sev = SEV_LIMITED;
                MSVCRT$sprintf(out->label, "WriteProperty on %s", attrName);
                SCopy(out->verb, (int)sizeof(out->verb), "EDIT");
                SCopy(out->hint, (int)sizeof(out->hint), "client-side extension injection (needs SYSVOL write too)");
            } else if (SIEq(attrName, "versionNumber")) {
                Set3(out, SEV_LIMITED, "WriteProperty on versionNumber", "WRITE",
                     "bump the version to force GP re-apply");
            } else {
                out->sev = SEV_LIMITED;
                MSVCRT$sprintf(out->label, "WriteProperty on %s", attrName);
                SCopy(out->verb, (int)sizeof(out->verb), "WRITE");
                SCopy(out->hint, (int)sizeof(out->hint), "write a single schema attribute");
            }
            return;
        }

        if (c->surface == SURF_WMI) {
            if (SIEq(attrName, "msWMI-Parm1") || SIEq(attrName, "msWMI-Parm2")) {
                out->sev = SEV_ACTIONABLE;
                MSVCRT$sprintf(out->label, "WriteProperty on %s", attrName);
                SCopy(out->verb, (int)sizeof(out->verb), "SCOPE");
                SCopy(out->hint, (int)sizeof(out->hint), "alter the WMI filter — silently retarget GPO scope");
            } else {
                out->sev = SEV_LIMITED;
                MSVCRT$sprintf(out->label, "WriteProperty on %s", attrName);
                SCopy(out->verb, (int)sizeof(out->verb), "WRITE");
                SCopy(out->hint, (int)sizeof(out->hint), "write a single WMI-filter attribute");
            }
            return;
        }

        /* link surfaces — some other single attribute */
        out->sev = SEV_LIMITED;
        MSVCRT$sprintf(out->label, "WriteProperty on %s", attrName);
        SCopy(out->verb, (int)sizeof(out->verb), "WRITE");
        SCopy(out->hint, (int)sizeof(out->hint), "write a single schema attribute");
        return;
    }

    if (m & ADS_RIGHT_DS_SELF) {
        Set3(out, SEV_LIMITED, "Validated write (SELF)", "WRITE", "validated write right");
        return;
    }
    if (m & ADS_RIGHT_DS_CONTROL_ACCESS) {
        out->sev = SEV_LIMITED;
        if (attrName) MSVCRT$sprintf(out->label, "ControlAccess %s", attrName);
        else          SCopy(out->label, (int)sizeof(out->label), "ControlAccess (unknown GUID)");
        SCopy(out->verb, (int)sizeof(out->verb), "CONTROL");
        SCopy(out->hint, (int)sizeof(out->hint), "extended control-access right");
        return;
    }
    if (m & ADS_RIGHT_CREATE_CHILD) {
        if (c->surface == SURF_OU || c->surface == SURF_DOMAINROOT)
            Set3(out, SEV_LIMITED, "CreateChild", "CREATE", "create child objects under this container");
        else
            Set3(out, SEV_LIMITED, "CreateChild", "CREATE", "create child objects");
        return;
    }
    if (m & (ADS_RIGHT_DELETE | ADS_RIGHT_DELETE_CHILD | ADS_RIGHT_DS_DELETE_TREE)) {
        Set3(out, SEV_LIMITED, "DELETE", "DELETE", "delete object(s)");
        return;
    }
    /* default read-only stands */
}
