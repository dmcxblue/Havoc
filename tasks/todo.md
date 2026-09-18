# AclPwn — Phase 1 (targeted kerberoast enum + setup)

## Goal
New Havoc BOF module `AclPwn` with a subcommand dispatcher. Phase 1 exposes six subcommands covering the enumeration and setup steps of targeted kerberoasting only (no ticket requests / roasting — nanorobeus/kerberoast BOF already does that).

## Out of scope
- Ticket requests, S4U, roasting.
- Other ACL-abuse chains (WriteOwner, WriteDACL grant, AdminSDHolder, GPO ACL, Shadow-Cred, DCSync grant) — future phases plug into the same dispatcher.
- Cross-forest / referral chasing.

## Steps
1. `client/Modules/AclPwn/{makefile,include/{beacon.h,bofdefs.h},src/entry.c,aclpwn.py}` created. Check: `ls` shows all five files.
2. `bofdefs.h` declares the imports needed by phase 1 (msvcrt, kernel32, advapi32 including `OpenProcessToken`/`GetTokenInformation`, netapi32, wldap32). Check: `grep -c '\$' include/bofdefs.h` >= 30.
3. `entry.c` implements dispatcher + six ops (`find-writable-users`, `find-noSPN-users`, `check-rights`, `get-spn`, `set-spn`, `clear-spn`) reusing StandIn's LDAP helpers (bprintf, ResolveDomain, LdapConnect, GetBaseDn, ReadSdAttr, ParseDacl, FormatSid, LookupSidName, FindObjectDn). New helper: `TokenSidsGet()` returns array of SIDs from process token (self + all group memberships), and `DaclHoldsSpnWriteRights(sd, sdLen, sids[])` returns bitmask (GenericAll|GenericWrite|WriteProperty(SPN)|WriteDACL|WriteOwner) accounting for `ACCESS_ALLOWED_OBJECT_ACE` and the SPN schema GUID `f3a64788-5306-11d1-a9c5-0000f80367c1`. Check: `wc -l src/entry.c` shows the file is non-trivial (>600 lines).
4. `aclpwn.py` mirrors `standin.py`: `_parse_flags` reused, subcommand as first positional (`find-writable-users`, `find-noSPN-users`, `check-rights`, `get-spn`, `set-spn`, `clear-spn`), Packer sends `int mode, target, spn, domain, user, pass, force`. Registers `aclpwn` command. Check: `python3 -c "import ast; ast.parse(open('aclpwn.py').read())"` passes.
5. `makefile` builds x64 + x86 using the same pattern as StandIn (`-Os -Wall -Wextra -DBOF -I include -fno-builtin -mno-stack-arg-probe`, strip). Check: `make -C client/Modules/AclPwn all` produces `bin/aclpwn.x64.o` and `bin/aclpwn.x86.o`.
6. Top-level `makefile` gets an AclPwn block in `bof-build`, and `client/config.toml [scripts].files` gains `client/Modules/AclPwn/aclpwn.py`. Check: `grep AclPwn makefile` and `grep AclPwn client/config.toml` each match.
7. Local build succeeds: `make -C client/Modules/AclPwn` returns 0, files present, `x86_64-w64-mingw32-objdump -f bin/aclpwn.x64.o` shows a valid COFF. Check: file present + objdump exit 0.

## Review
- New module `client/Modules/AclPwn/` created: `makefile`, `include/{beacon.h,bofdefs.h}`, `src/entry.c` (~660 lines), `aclpwn.py`.
- Six subcommands: `find-writable-users`, `find-noSPN-users`, `check-rights`, `get-spn`, `set-spn`, `clear-spn`.
- Token-aware DACL walk: collects `TokenUser` + `TokenGroups` SIDs (skips deny/integrity), matches against ALLOW ACEs and ALLOW_OBJECT ACEs; matches the SPN schema GUID for `WriteProperty`; also flags implicit rights when we own the target.
- `set-spn` refuses to overwrite a non-empty attribute unless `--force`; `clear-spn` uses `LDAP_MOD_REPLACE` with empty vals.
- Wired into top-level `makefile` `bof-build` and `client/config.toml [scripts].files`.
- Verified: `make -C client/Modules/AclPwn` builds x64+x86 cleanly with `-Wall -Wextra`, outputs present in `bin/`.
- Not exercised against a live DC — no lab test in this session. Manual smoke test needed against the Halcyon sandbox before trusting the DACL analyzer on real ACEs.
- Deferred to phase 2: WriteOwner takeover, WriteDACL grant, AdminSDHolder, GPO ACL, DCSync grant, Shadow-Cred writes. Dispatcher is ready to receive new mode ids.
