/*
 * Native (Linux) smoke test for src/gpo_rights_table.cpp.
 *
 * gpo_rights_table.cpp is deliberately windows.h-free — it only imports
 * MSVCRT$sprintf through a macro that degrades to `extern` off-Windows.
 * The host g++ rejects `$` in C++ identifiers, so the test build compiles a
 * sed-rewritten copy of the classifier (MSVCRT$sprintf -> bof_shim_sprintf):
 *
 *   sed 's/MSVCRT\$sprintf/bof_shim_sprintf/g' src/gpo_rights_table.cpp \
 *       > /tmp/grt_test.cpp
 *   g++ -Wall -I include test/classify_test.cpp /tmp/grt_test.cpp \
 *       -o /tmp/classify_test && /tmp/classify_test
 *
 * It exercises the classifier against the expected findings from
 * PLAN-DOMAIN.md's testing matrix.
 */

#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <stdarg.h>

/* shim for the DFR import used inside gpo_rights_table.cpp */
extern "C" int bof_shim_sprintf(char* d, const char* fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(d, 4096, fmt, ap);
    va_end(ap);
    return n;
}

#include "gpo_rights_table.h"
#include "sd_walker.h"

static int g_fail = 0;

#define CHECK(cond, msg) do { \
    if (!(cond)) { printf("FAIL: %s\n", msg); g_fail++; } \
    else         { printf("ok:   %s\n", msg); } \
} while (0)

static ClassOut Run(int surface, unsigned long mask, int aceType,
                    const char* guid, const char* path)
{
    ClassCtx c;
    c.surface = surface;
    c.mask    = mask;
    c.aceType = aceType;
    c.objGuid = guid;
    c.filePath = path;
    ClassOut o;
    ClassifyAce(&c, &o);
    return o;
}

int main()
{
    ClassOut o;

    /* PLAN-DOMAIN.md example: full control on a GPO */
    o = Run(SURF_GPO, 0x000F01FF, SD_ACE_ALLOWED, "", NULL);
    CHECK(o.sev == SEV_ACTIONABLE, "GPO 0xF01FF -> [!]");
    CHECK(strcasecmp(o.label, "GpoEditDeleteModifySecurity") == 0, "GPO 0xF01FF label");
    CHECK(strstr(o.hint, "SharpGPOAbuse") != NULL, "GPO EDIT hint");

    /* raw GENERIC_ALL on an OU -> LINK */
    o = Run(SURF_OU, 0x10000000, SD_ACE_ALLOWED, "", NULL);
    CHECK(o.sev == SEV_ACTIONABLE, "OU GenericAll -> [!]");
    CHECK(strcasecmp(o.verb, "LINK") == 0, "OU GenericAll verb LINK");

    /* PLAN-DOMAIN.md example: Authenticated Users read mask */
    o = Run(SURF_GPO, 0x00020014, SD_ACE_ALLOWED, "", NULL);
    CHECK(o.sev == SEV_READ, "0x00020014 -> [ ]");
    CHECK(strcasecmp(o.verb, "READ only") == 0, "0x00020014 verb");

    /* WriteProperty on gPLink via ObjectType GUID */
    o = Run(SURF_OU, 0x00000020, SD_ACE_ALLOWED_OBJ,
            "{F30E3BBE-9FF0-11D1-B603-0000F80367C1}", NULL);
    CHECK(o.sev == SEV_ACTIONABLE, "gPLink write -> [!]");
    CHECK(strcasecmp(o.label, "WriteProperty on gPLink") == 0, "gPLink label");
    CHECK(strstr(o.hint, "attach any GPO to this OU") != NULL, "gPLink hint names the OU");

    /* lowercase GUID — schema table match must be case-insensitive */
    o = Run(SURF_DOMAINROOT, 0x00000020, SD_ACE_ALLOWED_OBJ,
            "{f30e3bbe-9ff0-11d1-b603-0000f80367c1}", NULL);
    CHECK(o.sev == SEV_ACTIONABLE && strcasecmp(o.verb, "LINK") == 0, "lowercase gPLink GUID");

    /* unknown GUID must stay honest, not guessed */
    o = Run(SURF_GPO, 0x00000020, SD_ACE_ALLOWED_OBJ,
            "{DEADBEEF-0000-0000-0000-000000000000}", NULL);
    CHECK(o.sev == SEV_LIMITED, "unknown GUID write -> [+]");
    CHECK(strstr(o.label, "DEADBEEF") != NULL, "unknown GUID printed raw");

    /* GPO attribute severities */
    o = Run(SURF_GPO, 0x00000020, SD_ACE_ALLOWED_OBJ,
            "{BF9679E3-0DE6-11D0-A285-00AA003049E2}", NULL);
    CHECK(o.sev == SEV_ACTIONABLE, "nTSecurityDescriptor write -> [!]");
    o = Run(SURF_GPO, 0x00000020, SD_ACE_ALLOWED_OBJ,
            "{32FF8ECC-783F-11D2-9916-0000F87A57D4}", NULL);
    CHECK(o.sev == SEV_LIMITED, "gPCMachineExtensionNames write -> [+]");
    o = Run(SURF_GPO, 0x00000020, SD_ACE_ALLOWED_OBJ,
            "{BF967A76-0DE6-11D0-A285-00AA003049E2}", NULL);
    CHECK(o.sev == SEV_LIMITED, "versionNumber write -> [+]");

    /* WMI filter scope */
    o = Run(SURF_WMI, 0x00000020, SD_ACE_ALLOWED_OBJ,
            "{0003508E-9C42-4A76-A8F4-38BF64BAB0DE}", NULL);
    CHECK(o.sev == SEV_ACTIONABLE && strcasecmp(o.verb, "SCOPE") == 0, "msWMI-Parm2 -> SCOPE [!]");

    /* SYSVOL: generic file write on the ScheduledTasks dir */
    o = Run(SURF_SYSVOL, 0x00120116, SD_ACE_ALLOWED, "",
            "\\\\d\\SYSVOL\\d\\Policies\\{G}\\Machine\\Preferences\\ScheduledTasks");
    CHECK(o.sev == SEV_ACTIONABLE && strcasecmp(o.verb, "PLANT") == 0, "SYSVOL write -> PLANT [!]");
    CHECK(strstr(o.hint, "ScheduledTasks.xml") != NULL, "ScheduledTasks.xml hint");
    CHECK(strcasecmp(o.label, "FILE_GENERIC_WRITE") == 0, "FILE_GENERIC_WRITE label");

    /* SYSVOL: read-only (FILE_GENERIC_READ) */
    o = Run(SURF_SYSVOL, 0x00120089, SD_ACE_ALLOWED, "", "\\\\d\\SYSVOL\\d\\Policies\\{G}");
    CHECK(o.sev == SEV_READ, "SYSVOL read-only -> [ ]");

    /* DACL / owner */
    o = Run(SURF_SITE, 0x00040000, SD_ACE_ALLOWED, "", NULL);
    CHECK(o.sev == SEV_ACTIONABLE && strcasecmp(o.label, "WriteDacl") == 0, "WriteDacl -> [!]");
    o = Run(SURF_GPO, 0x00080000, SD_ACE_ALLOWED, "", NULL);
    CHECK(o.sev == SEV_ACTIONABLE && strcasecmp(o.verb, "TAKEOWN") == 0, "WriteOwner -> TAKEOWN [!]");

    /* deny ACE is informational even with a huge mask */
    o = Run(SURF_GPO, 0x000F01FF, SD_ACE_DENIED, "", NULL);
    CHECK(o.sev == SEV_READ, "deny ACE -> [ ]");

    printf("\n%s (%d failures)\n", g_fail ? "TESTS FAILED" : "all tests passed", g_fail);
    return g_fail ? 1 : 0;
}
