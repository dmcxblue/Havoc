# gpresult `domain` subcommand — plan

Extend the existing `gpresult` BOF with a new subcommand, `gpresult domain`,
that enumerates every GPO-related access the current beacon token holds across
the domain. Not limited to "writable" — a wildcard sweep of any ACE that
touches Group Policy from the caller's identity.

Existing subcommands stay untouched:

```
gpresult             # RSoP user + computer (unchanged)
gpresult user        # RSoP user only     (unchanged)
gpresult computer    # RSoP computer only (unchanged)
gpresult domain      # NEW: domain-wide GPO ACE sweep for the current user
```

## What "domain" enumerates

Six ACL surfaces where GPO permissions live in AD. All are ACE walks against
the caller's token SIDs (user SID + every group SID from
`GetTokenInformation(TokenGroups)`). The command reports every non-trivial ACE
that hits any of those SIDs, with a per-object severity tag.

| # | Container / object | What ACEs mean there |
|---|-------------------|----------------------|
| 1 | Each `groupPolicyContainer` under `CN=Policies,CN=System,<domainDN>` | GPO-object ACL: edit settings, modify security, delete, link |
| 2 | GPT under `\\<domain>\SYSVOL\<domain>\Policies\{GUID}\` | File-system DACL on the settings tree (script planting, ScheduledTasks.xml write) |
| 3 | Domain root object (`<domainDN>`) | `WriteProperty` on `gPLink` → attach any GPO domain-wide |
| 4 | Every OU (`(objectClass=organizationalUnit)`) | Same — link a GPO to a specific OU |
| 5 | Every Site under `CN=Sites,CN=Configuration,<forestDN>` | Same — link a GPO to a site |
| 6 | `CN=SOM,CN=WMIPolicy,CN=System,<domainDN>` (WMI filters) | Own/write WMI filter → change GPO scope silently |

Coverage across those six surfaces catches: `GpoEditDeleteModifySecurity`,
`GenericAll`, `GenericWrite`, `WriteDacl`, `WriteOwner`, per-attribute
`WriteProperty` on `gPCFileSysPath` / `gPCMachineExtensionNames` /
`gPCUserExtensionNames` / `versionNumber` / `nTSecurityDescriptor`, control
access rights, and the `gPLink` / `gPOptions` link controls.

## Output shape

One line per finding. Grouped by surface, severity-tagged so an operator
scanning the buffer sees the abuse-path immediately.

```
[GPO]    Workstation Configuration Policy   {31B2F340-016D-11D2-945F-00C04FB984F9}
         via HALCYON\lkim                   GpoEditDeleteModifySecurity (mask=0x000F01FF)
         [!] EDIT: plant computer task via SharpGPOAbuse

[GPO]    Default Domain Policy              {6AC1786C-016F-11D2-945F-00C04fB984F9}
         via HALCYON\Authenticated Users    ReadProperty+ListChildren (mask=0x00020014)
         [ ] READ only: enumeration surface

[SYSVOL] \\halcyon.local\SYSVOL\...\{31B2...}\Machine\Preferences\ScheduledTasks
         via HALCYON\lkim                   FILE_GENERIC_WRITE
         [!] PLANT: ScheduledTasks.xml writable

[LINK]   OU=Workstations,DC=halcyon,DC=local
         via HALCYON\ITOps                  WriteProperty on gPLink
         [!] LINK: attach any GPO to this OU

[WMI]    CN={GUID},CN=SOM,CN=WMIPolicy,...
         via HALCYON\lkim                   WriteProperty on msWMI-Parm2
         [!] SCOPE: alter WMI filter, silently retarget GPO
```

Severity tags:
- `[!]` — actionable abuse (edit / link / plant / scope / take-ownership)
- `[+]` — write-capable but limited (single attribute the caller controls)
- `[ ]` — read-only ACE (informational, filtered out unless `-v`)

## Command shape

```
gpresult domain                # actionable only, current user's token
gpresult domain -v             # include read-only ACEs and the SID resolutions
gpresult domain -u <SAM>       # future: enumerate for another principal
                               # (requires binding as that principal; skip for v1)
```

`-u` is documented but out of scope for v1 — v1 uses the beacon's token so no
credentials are handled.

## Data path

Roughly the same style as the existing RSoP path (WinAPI + one WMI namespace),
but the source is LDAP + SMB instead of WMI.

1. **Token SIDs.** `OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, ...)` +
   `GetTokenInformation(TokenGroups)` and `TokenUser`. Build a
   `std::vector<PSID>` of the caller's identity for later matching.

2. **DC + domain DN.** `DsGetDcNameA(NULL, NULL, NULL, NULL, DS_RETURN_DNS_NAME)`
   (already used in the header). Extract `DomainName` (DNS) and
   `DomainControllerName`. Derive base DN via `LdapGetDN` or by mapping
   `foo.bar.local` → `DC=foo,DC=bar,DC=local` on the fly.

3. **LDAP bind.** `ldap_initA(dc, LDAP_PORT)` → `ldap_set_option(LDAP_OPT_VERSION, 3)`
   → `ldap_bind_sA(ld, NULL, NULL, LDAP_AUTH_NEGOTIATE)`. Runs as the
   beacon token — no creds handled.

4. **Fetch objects and their SDs.** One `ldap_search_ext_sA` per surface.
   Request `nTSecurityDescriptor` with an `LDAP_SERVER_SD_FLAGS_OID`
   control set to `OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION
   | DACL_SECURITY_INFORMATION` (0x7), otherwise DACL isn't returned to
   non-admin binds.
   - `(objectClass=groupPolicyContainer)` under `CN=Policies,CN=System,<domainDN>`
     — attrs: `cn`, `displayName`, `gPCFileSysPath`, `nTSecurityDescriptor`.
   - Domain root object — attrs: `distinguishedName`, `gPLink`, `nTSecurityDescriptor`.
   - `(objectClass=organizationalUnit)` under domain root, subtree — same attrs.
   - `(objectClass=site)` under `CN=Sites,CN=Configuration,<forestDN>`
     (needs the config NC — pull via rootDSE `configurationNamingContext`).
   - `(objectClass=msWMI-Som)` under `CN=SOM,CN=WMIPolicy,CN=System,<domainDN>`.

5. **Parse SDs.** `MakeAbsoluteSD` isn't needed for read; use
   `GetSecurityDescriptorDacl` on the raw self-relative SD, then
   `GetAclInformation` + `GetAce` to iterate. For each `ACCESS_ALLOWED_ACE`
   (and `ACCESS_ALLOWED_OBJECT_ACE`), check the ACE SID against the caller's
   token SID list with `EqualSid`.

6. **Classify the mask.** Central lookup that turns the raw
   `ACCESS_MASK` + optional `ObjectType GUID` (for object-ACEs) into a
   human string. This is where the six surfaces get their tag:
   - `0x000F01FF` = `GenericAll`
   - `0x00020028` = `.NET GenericWrite` (WriteProperty + Self)
   - `0x00020000` = `WriteDacl` bit in the standard rights portion
   - `0x00040000` = `WriteOwner`
   - `WriteProperty` (0x20) with ObjectType matching `gPLink`,
     `gPCFileSysPath`, `gPCMachineExtensionNames`, `gPCUserExtensionNames`,
     `versionNumber`, `nTSecurityDescriptor`, `msWMI-Parm2` — resolve GUID
     via a small compile-time table.
   - `Extended right` (0x100) with control-access GUID for GPO — table it.

   ACEs that come out as pure `ReadProperty` / `ListChildren` / `ReadControl`
   are tagged read-only and suppressed unless `-v`.

7. **SYSVOL DACLs.** For each GPC whose `gPCFileSysPath` we captured, resolve
   its UNC and call `GetFileSecurityA(path, DACL_SECURITY_INFORMATION,
   ...)`. Walk the file ACL the same way, but the mask is
   `FILE_GENERIC_WRITE` / `FILE_APPEND_DATA` / `FILE_WRITE_DATA` /
   `WRITE_DAC` / `WRITE_OWNER`. This is what catches SYSVOL-side planting
   even when the GPC-side ACL looks safe.
   Fallback if the beacon can't reach SYSVOL directly (unusual):
   `NetShareGetInfo` + `WNetAddConnection2` with default creds, or skip
   with a `[SKIP] SYSVOL unreachable` line — never guess.

8. **SID resolution.** For every ACE that hits, `LookupAccountSidA` on the
   SID that granted it (may be the caller's user SID or one of the caller's
   groups). Falls back to `ConvertSidToStringSidA` when the SID doesn't
   resolve.

9. **Buffered output.** Same `bprintf()` / final `BeaconOutput` pattern as
   the RSoP subcommand. One chunk out, no interleaving.

## New source files (proposed)

```
src/
  entry.cpp                 (existing dispatcher — add "domain" branch)
  rsop_user.cpp             (existing — unchanged)
  rsop_computer.cpp         (existing — unchanged)
  domain_enum.cpp           NEW — main sweep, calls helpers below
  ldap_helper.cpp           NEW — bind, search, SD-flags control
  sd_walker.cpp             NEW — DACL walk, SID matching, mask classify
  gpo_rights_table.cpp      NEW — GUID→attribute name, mask→label
include/
  domain_enum.h
  ldap_helper.h
  sd_walker.h
  gpo_rights_table.h
```

## Undefined-symbol contract

Every symbol added must remain `__imp_*` per the module's rule. Expected new
imports (per `nm -u`, all `__imp_` prefixed):

- `wldap32.dll`: `ldap_initA`, `ldap_set_optionA`, `ldap_bind_sA`,
  `ldap_search_ext_sA`, `ldap_first_entry`, `ldap_next_entry`,
  `ldap_get_values_lenA`, `ldap_value_free_len`, `ldap_msgfree`,
  `ldap_unbind`, `ldap_create_page_control` (paging past 1000).
- `netapi32.dll`: `DsGetDcNameA` (already imported).
- `advapi32.dll`: `OpenProcessToken`, `GetTokenInformation`,
  `GetSecurityDescriptorDacl`, `GetAclInformation`, `GetAce`,
  `EqualSid`, `ConvertSidToStringSidA`, `LookupAccountSidA`,
  `GetFileSecurityA` (SYSVOL DACL).
- `kernel32.dll`: `GetCurrentProcess`, `LocalAlloc`/`LocalFree` (SD copies).

No CRT beyond what the existing module already declares. No `___chkstk_ms`.

## Failure modes and how each prints

| Case | Line printed |
|------|--------------|
| Cannot resolve DC | `[!!] DsGetDcNameA failed: <NTSTATUS>` |
| LDAP bind fails | `[!!] ldap_bind_sA failed: <ldap-error>` (often means beacon token is not a domain user) |
| SD flags control not honored (rare, non-AD LDAP) | `[!!] SD not returned; retry with fallback query` |
| SYSVOL unreachable | `[SKIP] SYSVOL DACL not read for {GUID}: <win32>` |
| Zero findings | `[=] No GPO-touching ACEs matched the caller's token` |
| Truncation risk (very permissioned account) | Paged LDAP result; per-surface soft cap 500, print `[!] surface truncated at 500` |

## Testing plan (in the RTO lab)

Run from a Demon on WKS01 in three identities. Each run is a self-check
against a known-answer state seeded by `ADSetup.ps1`.

| Identity | Expected `gpresult domain` findings |
|----------|-------------------------------------|
| `mnovoa` (baseline user) | `Authenticated Users` read on every applied GPO; no `[!]` lines |
| `lkim` (this course's target) | `[!] EDIT` on `Workstation Configuration Policy`; SYSVOL FILE_GENERIC_WRITE under that GPO's `{GUID}`; nothing else |
| `HALCYON\Administrator` | `[!]` on effectively every GPO + link surface (sanity: matches BloodHound's admin edge count) |

Cross-check: for each `[!] EDIT` line, `SharpGPOAbuse.exe --AddComputerTask
--GPOName "<name>"` must succeed. For each `[!] LINK` line, `New-GPLink` (or
`ldap_modify` on `gPLink`) must succeed.

## Docs to update in this repo

- `GPRESULT.md` — add the `domain` command under **Commands**, add a **Domain
  ACE surfaces** section pointing at this plan.
- `README` (top of module dir) if one exists — bump the one-liner.

## Non-goals (v1)

- No credential handling (`-u` for other principals is future work).
- No writing / abuse — pure enumeration. SharpGPOAbuse remains the exploit.
- No BloodHound-style graphing / chaining — one flat list per beacon run.
- No cross-forest / trust traversal — single domain per invocation.
