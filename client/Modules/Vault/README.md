# Windows Vault credential recovery (separate module — WIP)

Extracted from the `browserdata-bof` project on 2026-09-30. Not yet integrated
into a build; kept here for the follow-up "Vault domain-password" effort.

## Files
- `bd_vault.c` — C implementation (offline Vault decryption). **Needs a fix**:
  `Policy.vpol` and `*.vcrd` are RAW `VAULT_POLICY`/`VAULT_CREDENTIAL` structs
  (NOT DPAPI); only the inner `KeyBlob` is DPAPI. The current code was still
  calling `CryptUnprotectData` on the outer files at the time it was cut over —
  the later revision already parsed them raw and added `[V]` debug lines. Verify
  against the algorithm below.
- `reference-mimikatz/` — authoritative mimikatz source (gentilkiwi), preserved:
  - `kull_m_cred.c/.h` — `VAULT_POLICY`, `VAULT_POLICY_KEY`, `MBDK`,
    `VAULT_CREDENTIAL`, attribute parsing (`kull_m_cred_vault_policy_key`,
    `kull_m_cred_vault_credential_create`, `kull_m_cred_vault_credential_create_attribute_from_data`)
  - `kull_m_dpapi.c/.h` — DPAPI master-key layer
  - `kuhl_m_vault.c/.h` — `vault::list` (VaultGetItem API path) + struct defs
  - `kull_m_crypto.h` — `KIWI_HARD_KEY`/`KIWI_BCRYPT_KEY`

## Algorithm (from mimikatz `dpapi::vault`, kuhl_m_dpapi_creds.c)
1. `Policy.vpol` (raw) → `VAULT_POLICY`: version(4)+GUID(16)+dwName(4)+Name(dwName)
   +unk0..2+dwKey(16) → `VAULT_POLICY_KEY` at `24+dwName+16`:
   GUID(16)+GUID(16)+dwKeyBlob(4)+KeyBlob(dwKeyBlob).
2. `KeyBlob` → `CryptUnprotectData` → `MBDK` (tag bytes "KDBM") → `aes256`
   (type==1, cbSecret==32, data at block+24).
3. Each `<guid>.vcrd` (raw) → `VAULT_CREDENTIAL`: dwFriendlyName@36,
   FriendlyName@40, dwAttributesMapSize@(40+dwFriendlyName), attributesMap@
   (44+dwFriendlyName) — entries `{id, offset, unk}` (12B each).
4. Each attribute at `rec+offset`: id@0, unk0@4, unk1@8, unk2@12,
   [+4 if id>=100], szData(stored=data+1), isIV(1B), [szIV+IV], data.
   **AES-256-CBC**(aes256, IV) for id>=100 (Resource=100, Identity=101,
   Authenticator=102); AES-128-CBC for 0<id<100.

## Status
- Algorithm + references are complete and correct.
- `bd_vault.c` needs the raw-parse fix confirmed + a build target.
