# AclPwn

ACL / ACE abuse primitives for Havoc, dispatched as one BOF (`aclpwn.x64.o` /
`aclpwn.x86.o`) with a subcommand argument. The module owns *setup* and
*enumeration* only — roasting itself is done with existing tools
(`nanorobeus`, dedicated `kerberoast` / `asreproast` BOFs) against the SPN
or the AS-REP the AclPwn write enables.

## Layout

```
client/Modules/AclPwn/
├── makefile            x64+x86 build (-Wall -Wextra -fno-builtin)
├── include/
│   ├── beacon.h        BOF ABI (BeaconData*, BeaconOutput)
│   └── bofdefs.h       LIB$FUNC imports (msvcrt / advapi32 / netapi32 / wldap32)
├── src/entry.c         all subcommand implementations
├── bin/aclpwn.{x64,x86}.o
└── aclpwn.py           Havoc wrapper (registers `aclpwn` command)
```

Wire-up: registered in `client/config.toml [scripts].files`; top-level
`makefile` `bof-build` target rebuilds it on `make client-build`.

## Wire format

`aclpwn.py` packs args with `Packer` and sends via `demon.InlineExecute`.
Layout consumed by `go(char*, int)` in `entry.c`:

| Position | Type | Meaning |
|---|---|---|
| 0 | int   | mode id (see table below) |
| 1 | str   | target (DN or sAMAccountName; empty for list-* modes) |
| 2 | str   | value slot: `--spn` for set-spn, `--password` for reset-password |
| 3 | str   | domain (alt-creds; empty for default DC) |
| 4 | str   | user   (alt-creds) |
| 5 | str   | pass   (alt-creds) |
| 6 | int   | trailing: `noise` for list-* modes, `force` for set-spn, 0 otherwise |

## Subcommands

| Mode | Subcommand | Purpose |
|---:|---|---|
| 0 | `list-spn-writers`     | Domain-wide DACL inventory: who can write `servicePrincipalName` on which no-SPN user |
| 1 | `set-spn`              | Replace `servicePrincipalName` on a target |
| 2 | `clear-spn`            | Delete `servicePrincipalName` (cleanup) |
| 3 | `list-preauth-writers` | Domain-wide DACL inventory: who can flip `userAccountControl` on which preauth-required user |
| 4 | `set-nopreauth`        | Set the `DONT_REQ_PREAUTH` (0x400000) bit on a target |
| 5 | `unset-nopreauth`      | Clear `DONT_REQ_PREAUTH` (cleanup) |
| 6 | `list-pwreset-writers` | Domain-wide DACL inventory: who can reset each enabled user's password (`User-Force-Change-Password` extended right) |
| 7 | `reset-password`       | Reset `unicodePwd` on a target; `--password` or auto-generated |
| 8 | `list-writeowner-writers` | Domain-wide DACL inventory: who can take ownership of which user (`WriteOwner` / `GenericAll` / `WriteDACL` / `Owner`) |
| 9 | `take-ownership`       | Flip `nTSecurityDescriptor` OWNER to `--principal` (defaults to self) |
| 10 | `grant-genericall`    | Append `ACCESS_ALLOWED_ACE(GenericAll)` for `--principal` (defaults to self) on the target |
| 11 | `pwn-writeowner`      | `take-ownership` + `grant-genericall` in one shot |
| 12 | `restore-owner`       | Set OWNER back to `--owner` (cleanup helper) |

Global flags (both list-* and target-ops): `--domain`, `--user`, `--pass` for
alt-creds; `--noise` for list-* modes; `--force` for `set-spn`; `--password`
for `reset-password`; `--principal` for the WriteOwner ops; `--owner` for
`restore-owner`.

### Targeted kerberoast (`list-spn-writers` / `set-spn` / `clear-spn`)

Flow the module supports:

1. `aclpwn list-spn-writers` — pick a target you have a right on.
2. `aclpwn set-spn --target <sam> --spn HTTP/bogus.corp.local`
3. Roast with `nanorobeus` or a `kerberoast` BOF against `HTTP/bogus.corp.local`.
4. `aclpwn clear-spn --target <sam>` — cleanup.

`list-spn-writers` filter: `(&(sAMAccountType=805306368)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(!(servicePrincipalName=*)))` — enabled users with empty SPN, i.e. actionable candidates.

### Targeted AS-REP roast (`list-preauth-writers` / `set-nopreauth` / `unset-nopreauth`)

Flow:

1. `aclpwn list-preauth-writers` — pick a target you have a right on.
2. `aclpwn set-nopreauth --target <sam>` — flips UAC bit `0x400000` on.
3. AS-REP roast: send AS-REQ without preauth; the AS-REP is encrypted with
   the target's NTLM hash. Crack offline (hashcat mode 18200).
4. `aclpwn unset-nopreauth --target <sam>` — cleanup.

`list-preauth-writers` filter: `(&(sAMAccountType=805306368)(!(userAccountControl:...:=2))(!(userAccountControl:...:=4194304)))` — enabled users where the bit is **not** already set (already-set accounts are ordinary AS-REP-roastable targets and don't need the module).

### Password reset (`list-pwreset-writers` / `reset-password`)

Flow:

1. `aclpwn list-pwreset-writers` — pick a target where a non-default principal you control holds a reset right.
2. `aclpwn reset-password --target <sam>` — random password, printed to the beacon.
   Or `--password <pw>` for an operator-chosen value.
3. Log in as the target with the new credential (`runas /netonly`, `pass-the-hash` after
   `nanodump`, or S4U from a machine account you own).
4. There is no "unset" — the original password is gone. The target's user will notice on
   their next login and reset it. Blue teams alert on Event **4724** (password reset by
   another account, distinct from **4723** which is a self-change).

`list-pwreset-writers` uses the ControlAccess path in the DACL walker: it matches an ACE with
`ADS_RIGHT_DS_CONTROL_ACCESS` (0x100) whose `ObjectType` GUID equals the
`User-Force-Change-Password` rightsGuid `00299570-246d-11d0-a768-00aa006e0529`. `GenericAll`,
`WriteDACL`, `WriteOwner`, and object ownership also count. **`GenericWrite` does NOT grant
this right** — it only covers WriteProperty, and `unicodePwd` is guarded by a control-access
check, not a property-write check.

`reset-password` writes `unicodePwd` via `ldap_modify_s` with `LDAP_MOD_REPLACE | LDAP_MOD_BVALUES`.
The value is the new password wrapped in literal `"` and encoded as UTF-16LE (no BOM, no
trailing NUL). Requires sign+seal on the bind (already default) or LDAPS. Random passwords
come from `SystemFunction036` / `RtlGenRandom` and satisfy the default AD complexity policy
(upper/lower/digit/special, 16 chars).

### WriteOwner takeover (`list-writeowner-writers` / `take-ownership` / `grant-genericall` / `pwn-writeowner` / `restore-owner`)

Flow (two-step primitive — the whole point of the WriteOwner right):

1. `aclpwn list-writeowner-writers` — pick a target. **Note the current owner
   value** if you plan to restore it later; there is no auto-remember.
2. `aclpwn take-ownership --target <sam>` — writes `nTSecurityDescriptor` OWNER
   to your identity (or `--principal <SID|sAM>`). Owner has implicit `WriteDACL`.
3. `aclpwn grant-genericall --target <sam>` — appends an
   `ACCESS_ALLOWED_ACE(0x10000000)` for you (or `--principal`) to the target's
   DACL. Requires `WriteDACL`, which step 2 just gave us.
4. Cash in: `reset-password`, `set-spn`, `set-nopreauth`, add to a group,
   whatever the object type supports.
5. `aclpwn restore-owner --target <sam> --owner <original-SID>` — cleanup.
   The `GenericAll` ACE you appended stays until you also remove it (or wipe
   the DACL, which is destructive — future backlog).

`pwn-writeowner` is the one-shot: it does steps 2 and 3 in a single BOF call,
with a graceful bail-out message if step 2 succeeds but step 3 fails.

Under the hood:

- `WriteOwnerSid`: composes a minimal self-relative SD (revision 1, control
  `SE_SELF_RELATIVE` only, owner offset 20, other offsets zero, SID appended),
  writes it via `ldap_modify_ext_s` with the `LDAP_SERVER_SD_FLAGS` control
  value **`0x01`** (OWNER only). The DC replaces just the owner and preserves
  everything else.
- `AppendGenericAllAce`: reads the explicit SD, walks the DACL header, appends
  one `ACCESS_ALLOWED_ACE` (type 0, mask `0x10000000`, SID for the grantee),
  writes a minimal SD carrying only the amended DACL back with SD_FLAGS `0x04`
  (DACL only). Same pattern StandIn's `EscalateSelf` uses.
- Principal resolution (`--principal` / `--owner`): empty defaults to the
  current process identity (`GetUserNameA` + `LookupAccountNameA`); values
  starting with `S-` are parsed as SID strings; anything else is a
  `sAMAccountName` LDAP lookup.

Blue-team footprint:

- `take-ownership` fires Event **4670** (permissions on an object changed —
  owner change).
- `grant-genericall` fires another **4670** (DACL modification) plus
  potentially **5136** if DS Access auditing is on.
- `pwn-writeowner` fires both back-to-back — cleaner behavioral chain than
  the individual steps spaced out.

## DACL analysis

Both `list-*` subcommands share `CollectAttrWriters` in `entry.c`. For each
ACE in a target's `nTSecurityDescriptor` (read with `SD_FLAGS = OWNER|GROUP|DACL`),
the walker records every principal that holds any of the following rights and
which right(s) they hold:

| Bit | Right | What it enables |
|---|---|---|
| `R_GENERICALL`     | `GenericAll`               | Full control - one-step |
| `R_GENERICWRITE`   | `GenericWrite`             | Write any attribute except the ACL (WriteProperty modes only) |
| `R_WRITEPROP_ATTR` | `WriteProperty(<attr>)`    | Object-type ACE keyed to the specific attribute GUID |
| `R_WRITEPROP_ALL`  | `WriteProperty(*)`         | Unrestricted WriteProperty ACE |
| `R_EXTRIGHT_ATTR`  | `ExtendedRight(<right>)`   | ControlAccess ACE keyed to a specific rightsGuid |
| `R_EXTRIGHT_ALL`   | `ExtendedRight(*)`         | Unrestricted ControlAccess ACE |
| `R_WRITEDACL`      | `WriteDACL`                | Modify the DACL; grant self `GenericAll` then act |
| `R_WRITEOWNER`     | `WriteOwner`               | Take ownership (implicit `WriteDACL`), grant self, act |
| `R_OWNER`          | `Owner`                    | Already the owner - implicit `WriteDACL` |

`CollectAttrWriters` takes a `matchMode` argument that selects between the
two paths:

- `MATCH_WRITEPROP` (SPN, UAC): matches `ACE_WRITEPROPERTY` (0x20) ACEs
  against the attribute GUID. `GenericWrite` counts.
- `MATCH_EXTRIGHT`  (pwreset): matches `ACE_CONTROL_ACCESS` (0x100) ACEs
  against a rightsGuid. `GenericWrite` does NOT count.

Attribute / right GUIDs used for object-type ACE matching:

| Purpose | Kind | GUID | Constant in `entry.c` |
|---|---|---|---|
| `servicePrincipalName`         | schemaIDGUID | `f3a64788-5306-11d1-a9c5-0000f80367c1` | `SPN_ATTR_GUID`   |
| `userAccountControl`           | schemaIDGUID | `bf967a68-0de6-11d0-a285-00aa003049e2` | `UAC_ATTR_GUID`   |
| `User-Force-Change-Password`   | rightsGuid   | `00299570-246d-11d0-a768-00aa006e0529` | `FCPW_RIGHT_GUID` |

### "Boring" SID suppression

Every DACL on a user object grants `SYSTEM` and Domain / Enterprise / Schema
admin equivalents the rights we care about; those edges are structural, not
attacker paths. `IsBoringSid` in `entry.c` filters them out from list-*
output unless `--noise` is passed. The set:

- `S-1-1-0` Everyone
- `S-1-3-0` CREATOR OWNER, `S-1-3-1` CREATOR GROUP
- `S-1-5-9` Enterprise Domain Controllers
- `S-1-5-10` PRINCIPAL SELF
- `S-1-5-11` Authenticated Users
- `S-1-5-18` LOCAL SYSTEM
- `S-1-5-19` LocalService, `S-1-5-20` NetworkService
- `S-1-5-32-{544,548,549,550,551,552}` BUILTIN Administrators / Account / Server / Print / Backup / Replicator Operators
- Domain-scoped RIDs `500` (Administrator), `512` (Domain Admins), `516` (Domain Controllers), `518` (Schema Admins), `519` (Enterprise Admins), `520` (GPO Creator Owners)

## LDAP setup

- Bind: `LDAP_AUTH_NEGOTIATE`, sign + seal (`LDAP_OPT_SIGN`, `LDAP_OPT_ENCRYPT`).
- Referrals: **off** (`LDAP_OPT_REFERRALS = OFF`). Cross-domain referral chases
  during large sweeps are the most common BOF crash trigger.
- SD read: `ldap_search_ext_s` with `LDAP_SERVER_SD_FLAGS_OID`
  (`1.2.840.113556.1.4.801`) value `0x07` (owner + group + DACL).
- Modify: `ldap_modify_s` with `LDAP_MOD_REPLACE`; SPN cleanup uses REPLACE
  with an empty value list to delete every value.
- Target resolver: accepts both DN (contains `=`) and `sAMAccountName`.

## Cheatsheet

```
aclpwn list-spn-writers
aclpwn list-spn-writers --noise
aclpwn set-spn   --target jnovoa    --spn HTTP/bogus.corp.local
aclpwn set-spn   --target jnovoa    --spn HTTP/x.corp.local --force
aclpwn clear-spn --target jnovoa

aclpwn list-preauth-writers
aclpwn list-preauth-writers --noise
aclpwn set-nopreauth   --target rcastillo
aclpwn unset-nopreauth --target rcastillo

aclpwn list-pwreset-writers
aclpwn reset-password --target anovoa
aclpwn reset-password --target anovoa --password 'MyN3wP@ss!'

aclpwn list-writeowner-writers
aclpwn take-ownership --target rcastillo
aclpwn grant-genericall --target rcastillo
aclpwn pwn-writeowner --target rcastillo
aclpwn pwn-writeowner --target rcastillo --principal S-1-5-21-...-1104
aclpwn restore-owner --target rcastillo --owner S-1-5-21-...-1000

aclpwn list-spn-writers --domain corp --user rfludd --pass 'Cl4vi$Alchemi4e'
```

## Phase-4 backlog (planned, not shipped)

Same dispatcher pattern will host the next ACL primitives once needed:

- `list-writedacl-writers` — dedicated inventory for principals that hold
  `WriteDACL` directly (bypasses the take-ownership step).
- `add-member` — abuse `GenericWrite` / `WriteProperty(member)` on a group.
- Shadow-Credentials writes (`msDS-KeyCredentialLink`).
- AdminSDHolder ACE plant.
- DCSync grant (`GetChanges` + `GetChangesAll` on the domain object).

## Building

Standalone: `make -C client/Modules/AclPwn`
As part of the top-level rebuild: `make bof-build` at the repo root.

## Files touched by this module in the top-level tree

- `client/config.toml` — `aclpwn.py` registered under `[scripts].files`.
- `makefile` — `AclPwn` build block in the `bof-build` target.
