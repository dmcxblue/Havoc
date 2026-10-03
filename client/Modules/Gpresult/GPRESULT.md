# Gpresult — RSoP reporter + domain GPO-ACE sweep BOF

A BOF that reimplements the useful core of `gpresult /R` without spawning
`gpresult.exe`, plus a `domain` subcommand that sweeps **every GPO-related
ACL the caller's token holds** across the domain (see `PLAN-DOMAIN.md`).

## Why not just `shell gpresult /R`

`gpresult.exe` works, but it spawns a child process and its output is
text-scraped. This BOF pulls the same data straight from the RSoP WMI
provider (`root\rsop\user` / `root\rsop\computer`), which is the same source
`gpresult /R` reads — no child process, single buffered output chunk.

`gpresult domain` goes further: it answers "what could this token do to Group
Policy?" — one pass over the six ACL surfaces where GPO power lives.

## Commands

```
gpresult             user + computer RSoP (matches gpresult /R)
gpresult user        user settings only
gpresult computer    computer settings only
gpresult domain      domain-wide GPO ACE sweep for the current token
gpresult domain -v   include read-only ACEs + the token SID list
```

`-u <SAM>` (enumerate for another principal) is documented in
`PLAN-DOMAIN.md` but out of scope for v1 — v1 uses the beacon's token, so no
credentials are handled.

## `gpresult domain` — Domain ACE surfaces

Six ACL surfaces, all ACE-walked against the caller's token SIDs
(`TokenUser` + enabled, non-deny-only `TokenGroups` + `TokenPrimaryGroup`):

| # | Surface | Source | What it catches |
|---|---------|--------|-----------------|
| 1 | GPO objects | `(objectClass=groupPolicyContainer)` under `CN=Policies,CN=System,<domainDN>` | edit / modify-security / delete on the GPO object |
| 2 | SYSVOL GPT | `GetFileSecurityA` on each `gPCFileSysPath` | script planting, `ScheduledTasks.xml` write even when the GPC ACL looks safe |
| 3 | Domain root | `<domainDN>` base object | `WriteProperty` on `gPLink` → attach any GPO domain-wide |
| 4 | OUs | `(objectClass=organizationalUnit)`, subtree, paged | same, per-OU |
| 5 | Sites | `(objectClass=site)` under `CN=Sites,CN=Configuration` | same, per-site |
| 6 | WMI filters | `(objectClass=msWMI-Som)` under `CN=SOM,CN=WMIPolicy,CN=System` | own/write a filter → silently retarget GPO scope |

### Severity tags

- `[!]` — actionable abuse (edit / link / plant / scope / take-ownership)
- `[+]` — write-capable but limited (single attribute the caller controls)
- `[ ]` — read-only ACE (suppressed unless `-v`)

### Output shape

```
[GPO]    Workstation Configuration Policy   {31B2F340-016D-11D2-945F-00C04FB984F9}
         via HALCYON\lkim                   GpoEditDeleteModifySecurity (mask=0x000F01FF)
         [!] EDIT: plant computer task via SharpGPOAbuse

[LINK]   OU=Workstations,DC=halcyon,DC=local
         via HALCYON\ITOps                  WriteProperty on gPLink (mask=0x00000020)
         [!] LINK: attach any GPO to this OU

[SYSVOL] \\halcyon.local\SYSVOL\...\{31B2...}\Machine\Preferences\ScheduledTasks
         via HALCYON\lkim                   FILE_GENERIC_WRITE (mask=0x00120116)
         [!] PLANT: ScheduledTasks.xml writable
```

Attribute-level `WriteProperty` ACEs are resolved to attribute names via a
compile-time schema-ID-GUID table (`gPLink`, `gPOptions`, `gPCFileSysPath`,
`gPCMachineExtensionNames`, `gPCUserExtensionNames`, `nTSecurityDescriptor`,
`versionNumber`, `msWMI-Parm1/2` — GUIDs verified against Microsoft Learn).
Unknown GUIDs print raw — never guessed.

### Data path

1. `OpenProcessToken`/`GetTokenInformation` → caller SID set (deny-only and
   disabled groups excluded — they grant nothing).
2. `DsGetDcNameA(DS_RETURN_DNS_NAME)` → DC + DNS domain; DN from rootDSE
   (`defaultNamingContext` / `configurationNamingContext`), DNS-derived as
   fallback.
3. `ldap_initA(dc, 389)` → `LDAP_OPT_VERSION 3` → `ldap_bind_sA(NULL, NULL,
   LDAP_AUTH_NEGOTIATE)` — runs as the beacon token, no creds handled.
4. One LDAP search per surface, each carrying an `LDAP_SERVER_SD_FLAGS_OID`
   control (`1.2.840.113556.1.4.801`, flags `0x7` OWNER|GROUP|DACL) so the
   DACL is returned to non-admin binds. Subtree sweeps use the paged-results
   control (`1.2.840.113556.1.4.319`, page 1000) to get past MaxPageSize.
5. `GetSecurityDescriptorDacl` → `GetAclInformation` → `GetAce`; SID match
   with `EqualSid`; `ACCESS_ALLOWED(_OBJECT)` and `ACCESS_DENIED(_OBJECT)`
   ACEs handled, ObjectType GUIDs formatted and classified.
6. SYSVOL: `GetFileSecurityA(DACL_SECURITY_INFORMATION)` two-call pattern on
   every collected `gPCFileSysPath`; file masks classified against
   `FILE_GENERIC_WRITE` / `WRITE_DAC` / `WRITE_OWNER`.
7. `LookupAccountSidA` per hitting SID (cached), falling back to
   `ConvertSidToStringSidA`.

Per-surface soft cap: 500 objects (`[!] <surface> surface truncated at 500
objects`). Output is buffered through the shared engine (`src/bofout.cpp`)
and flushed via `BeaconOutput`.

### Failure modes

| Case | Line |
|------|------|
| Cannot resolve DC | `[!!] DsGetDcNameA failed: 0x…` |
| Bind fails | `[!!] ldap_bind_sA failed: … — beacon token likely not a domain principal` |
| Container absent (e.g. no WMI filters ever created) | `-v`: `[*] <surface>: container not present in this domain` |
| SYSVOL unreadable | `[SKIP] SYSVOL DACL not read for {GUID}: win32 <code>` |
| Zero findings | `[=] No GPO-touching ACEs matched the caller's token` |

Lab validation (mnovoa / lkim / Administrator expectations) is specified in
`PLAN-DOMAIN.md` § Testing plan.

## RSoP data sources (`gpresult` / `user` / `computer`)

### Header (WinAPI, once)
| Field | Source |
|---|---|
| Hostname | `GetComputerNameExA(ComputerNameDnsHostname)` |
| Domain | `GetComputerNameExA(ComputerNameDnsDomain)` |
| Domain controller | `DsGetDcNameA` → `DomainControllerName` (strips `\\`) |
| OS version | `RtlGetVersion` from `ntdll.dll` (GetVersionEx lies without a manifest) |
| OS configuration | `HKLM\...\ProductOptions\ProductType` (Workstation/Server/DC) |
| User DN | `GetUserNameExA(NameFullyQualifiedDN)` |
| Local profile | `%USERPROFILE%` |

### RSoP (WMI)
| Class | What it provides |
|---|---|
| `RSOP_Session` | `targetName`, `creationTime` (→ "Last applied"), `SecurityGroups[]` |
| `RSOP_GPO` | `name`, `enabled`, `filterAllowed`, `accessDenied` → applied vs filtered-out GPOs |

Medium-integrity fallback: `Group Policy\History` registry + the token's own
groups (see `src/entry.cpp`).

## Build

```
make
```

- `x86_64-w64-mingw32-g++ -Os -w -mno-stack-arg-probe -fno-exceptions
  -fno-rtti -fno-builtin` per TU (`build/*.o`), then
  `x86_64-w64-mingw32-ld -r` partial-links them into `bin/gpresult.x64.o`
  (multi-source BOF — partial link preserves relocations and `__imp_*`
  undefineds).
- `-mno-stack-arg-probe` avoids `___chkstk_ms`; `-fno-builtin` stops gcc from
  pattern-matching loops into plain `strlen`/`memcpy` libc calls (which would
  break the DFR contract).
- Output buffered via `bof_printf()` (`src/bofout.cpp`), flushed in one
  `BeaconOutput` per run.
- Native smoke test for the classifier (no Windows needed):
  ```
  sed 's/MSVCRT\$sprintf/bof_shim_sprintf/g' src/gpo_rights_table.cpp > /tmp/grt_test.cpp
  g++ -Wall -I include test/classify_test.cpp /tmp/grt_test.cpp -o /tmp/classify_test
  /tmp/classify_test
  ```

## Layout

```
src/
  entry.cpp           dispatcher (RSoP path) + `domain` branch
  bofout.cpp          shared buffered-output engine
  domain_enum.cpp     six-surface sweep, SYSVOL walk, emission
  ldap_helper.cpp     bind, rootDSE, SD-flags control, paged search
  sd_walker.cpp       token SID set, DACL walk, SID matching
  gpo_rights_table.cpp mask/GUID classification (windows.h-free, testable)
include/              matching headers + beacon.h
test/classify_test.cpp native smoke test
```

## Undefined-symbol contract

`nm -u bin/gpresult.x64.o` must show **only** `__imp_*` imports. Verified
clean after the `domain` addition — new imports vs the RSoP-only build:

- `wldap32.dll`: `ldap_initA`, `ldap_set_optionA`, `ldap_bind_sA`,
  `ldap_search_ext_sA`, `ldap_first_entry`, `ldap_next_entry`,
  `ldap_get_valuesA`, `ldap_value_freeA`, `ldap_get_values_lenA`,
  `ldap_value_free_len`, `ldap_get_dnA`, `ldap_memfreeA`, `ldap_err2stringA`,
  `ldap_msgfree`, `ldap_unbind`, `ldap_create_page_controlA`,
  `ldap_parse_page_controlA`, `ldap_parse_resultA`, `ldap_control_freeA`,
  `ldap_controls_freeA`, `ber_bvfree` (all confirmed present in
  mingw-w64's `libwldap32.a`, i.e. real `wldap32.dll` exports).
- `advapi32.dll`: `GetSecurityDescriptorDacl`, `GetAclInformation`, `GetAce`,
  `EqualSid`, `GetFileSecurityA`, `GetSidLengthRequired` (+ existing
  token/SID functions).
- `kernel32.dll`: `LocalAlloc`, `GetLastError` (+ existing).
- No CRT beyond `MSVCRT$sprintf/vsnprintf/calloc/free/memcpy` (all
  `__imp_`-declared). No `___chkstk_ms`.

WinLDAP note: `winldap.h` is deliberately NOT included — its plain
declarations would emit unresolvable `__imp_ldap_*` symbols. The LDAP ABI
subset (berval, LDAPControlA, struct layouts) is mirrored in
`include/ldap_helper.h`, verified against mingw-w64's winldap.h for x64.

## Notes / limitations

- RSoP logging-mode data only exists if Group Policy has been applied to the
  target in the beacon's session. If `RSOP_Session` is empty, the BOF reports
  it clearly.
- `gpresult domain` needs the beacon token to be a domain principal (user or
  machine account); otherwise the negotiate bind fails with an explicit line.
- SACLs are not read (needs `SeSecurityPrivilege`); DACLs only, per plan.
- Cross-forest, `-u <principal>`, and any write/abuse capability are
  non-goals — enumeration only (see `PLAN-DOMAIN.md` § Non-goals).
