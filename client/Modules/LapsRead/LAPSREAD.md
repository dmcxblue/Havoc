# LapsRead - Havoc LAPS Password Reader

Reads LAPS passwords from Active Directory via LDAP. Supports both
**Windows LAPS** (`msLAPS-Password`, Server 2022+) and **legacy LAPS**
(`ms-Mcs-AdmPwd`, AdmPwd.dll/MSI-based).

Reuses the `ldapsearch` BOF from the Delegation module (symlinked, no
new native code). The LDAP bind uses the Demon's current token context.

## Usage

```
laps-read                           # all computers, Windows LAPS
laps-read WKS01                     # specific computer, Windows LAPS
laps-read legacy                    # all computers, legacy LAPS
laps-read legacy WKS02              # specific computer, legacy LAPS
laps-read /dc:192.168.10.10        # target a specific DC
laps-read WKS01 /dc:DC01           # combine target + DC
```

## Prerequisites

Run the command as a user with LAPS read permissions on the target
computer objects. In the RTO lab that is **nwilson** (`T3chSup!2025`),
who has `Set-LapsADReadPasswordPermission` on `CN=Computers`.

If you get the Demon as another user, token-steal into nwilson first:
```
token steal <nwilson_pid>
laps-read WKS01
```

## Output format

**Windows LAPS** returns JSON per computer:
```
{"n":"Administrator","t":"2026-10-24T...","p":"<plaintext_password>"}
```

**Legacy LAPS** returns plaintext per computer (or empty if the
attribute is not populated / the AdmPwd agent is not installed).

## Empty results?

- The LAPS GPO has not been applied yet (run `gpupdate /force` on the
  workstation, then `Reset-LapsPassword`).
- The Demon's token does not have read ACL on the LAPS attribute.
- You targeted the DC itself (DCs do not have LAPS-managed local admins).

## Files

```
LapsRead/
  lapsread.py          # Python wrapper (command registration + arg packing)
  bin/ldapsearch.*.o   # symlinks to Delegation/bin/ (shared BOF)
  LAPSREAD.md          # this file
```
