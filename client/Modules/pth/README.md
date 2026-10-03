# pth — Pass-the-Hash BOF for Havoc

In-memory `sekurlsa::pth` port, using the **ORIGINAL mimikatz method**.
Spawns a sacrificial process with `CreateProcessWithLogonW(user, domain, "",
LOGON_NETCREDENTIALS_ONLY, CREATE_SUSPENDED)`, then patches that logon
session's MSV1_0 (NTLM) and Kerberos (AES) primary credentials inside LSASS
with the supplied hash/keys and resumes the process. All outbound network
auth from the spawned process (SMB, RPC, WMI, DCOM, LDAP, Kerberos pre-auth)
then uses the patched hash.

## Files

- `pth.py` — Havoc client wrapper, registers the `pth` command.
- `BOF/pth_bof.c` — BOF entry point (parses argv, enables SeDebugPrivilege,
  calls `kuhl_m_sekurlsa_pth`).
- `BOF/build.sh` — cross-compiles the BOF with MinGW.
- `bin/pth.x64.o` — pre-built BOF (self-contained, no runtime deps).

## Usage

```
Demon » pth /user:Administrator /domain:halcyon.local /ntlm:<hash>
Demon » pth /user:Administrator /domain:HALCYON /ntlm:<hash> /run:powershell.exe
Demon » pth /user:Administrator /domain:halcyon.local /ntlm:<hash> /aes256:<key>
Demon » pth /user:jadmin /domain:halcyon.local /ntlm:<hash> /impersonate
Demon » pth /luid:12345678 /ntlm:<hash>
```

Arguments: `/user`, `/domain`, `/ntlm` (alias `/rc4`), `/aes128`, `/aes256`,
`/run` (default `cmd.exe`), `/impersonate` (swap current thread token instead
of spawning), `/luid` (patch an existing session in place).

Requires an elevated Demon with SeDebugPrivilege. The BOF reads **and writes**
LSASS; EDR hooks on `OpenProcess` / `WriteProcessMemory` against `lsass.exe`
will see it, and RunAsPPL blocks it.

After the BOF returns, use the sacrificial process (PID is printed) or
`steal_token <pid>` to run subsequent commands under the patched session.
NTLM-only hashes cover NTLM auth; add `/aes256` for Kerberos pre-auth on
Win8.1+ targets.

## Rebuilding

```
cd BOF
bash build.sh
cp pth_bof.o ../bin/pth.x64.o
```

Requires `x86_64-w64-mingw32-gcc` (MinGW-w64). The tree under `inc/`,
`modules/` and `mimikatz/` is the vendored mimikatz source required by the
build; `BOF/casefix/` and the `.h` symlinks in `BOF/` resolve Windows/Linux
include-case and path differences (regenerate with `BOF/fixcase.sh`).
