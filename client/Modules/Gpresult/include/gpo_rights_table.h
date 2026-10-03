#ifndef GPO_RIGHTS_TABLE_H
#define GPO_RIGHTS_TABLE_H

/*
 * ACCESS_MASK (+ optional ObjectType GUID) → human-readable label,
 * severity tag and abuse hint, per ACL surface.
 */

/* ACL surfaces swept by `gpresult domain` */
enum {
    SURF_GPO = 0,      /* groupPolicyContainer objects            */
    SURF_SYSVOL,       /* \\dom\SYSVOL\dom\Policies\{guid}\ DACLs */
    SURF_DOMAINROOT,   /* <domainDN> root object (gPLink)         */
    SURF_OU,           /* organizationalUnit objects (gPLink)     */
    SURF_SITE,         /* site objects in the config NC (gPLink)  */
    SURF_WMI,          /* msWMI-Som WMI filters                   */
    SURF_COUNT
};

/* severity */
#define SEV_ACTIONABLE 0   /* [!] — edit / link / plant / scope / take-ownership */
#define SEV_LIMITED    1   /* [+] — write-capable but limited                   */
#define SEV_READ       2   /* [ ] — read-only (suppressed unless -v)            */

struct ClassCtx {
    int           surface;
    unsigned long mask;
    int           aceType;    /* SD_ACE_* (see sd_walker.h) */
    const char*   objGuid;    /* "{GUID}" for object ACEs, else ""  */
    const char*   filePath;   /* SURF_SYSVOL: the GPT path          */
};

struct ClassOut {
    int  sev;
    char label[80];
    char verb[24];
    char hint[160];
};

void ClassifyAce(const ClassCtx* c, ClassOut* out);

/* schema-ID-GUID → attribute name; NULL when unknown */
const char* GuidToAttrName(const char* guid);

#endif /* GPO_RIGHTS_TABLE_H */
