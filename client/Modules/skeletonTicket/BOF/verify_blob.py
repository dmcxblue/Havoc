#!/usr/bin/env python3
"""skeletonkey BOF post-build hygiene check.

The AES hooks are PRE-COMPILED position-independent blobs (standalone build,
.text-only extraction, verified there), embedded here as static const arrays
(aes_derive_blob.h / aes_decrypt2_blob.h). This TU runs in the beacon process —
it is never injected verbatim — so the old in-TU "blob order / data-relocation"
checks no longer apply. What still matters:

  1. the two blob arrays actually got embedded (canary),
  2. no ___chkstk_ms snuck in (breaks the freestanding BOF ABI),
  3. every unresolved symbol goes through __imp_LIB$FUNC / Beacon* / DFR aliases
     (a bare extern would silently become a NULL call at runtime).
"""
import subprocess
import sys

obj = sys.argv[1]
nm = subprocess.check_output(["x86_64-w64-mingw32-nm", obj], text=True)

# 1. blob canary — the derive + decrypt hook bytes must be present.
have_derive = any("aes_derive" in ln for ln in nm.splitlines())
have_decrypt = any("aes_decrypt2" in ln for ln in nm.splitlines())
if not (have_derive and have_decrypt):
    sys.exit("embedded blob arrays missing (aes_derive/aes_decrypt2)")

# 2. no chkstk
undef = subprocess.check_output(["x86_64-w64-mingw32-nm", "-u", obj], text=True)
if "chkstk" in undef.lower():
    sys.exit("___chkstk_ms present")

# 3. no bare externs (everything must resolve via the CoffeeLdr alias table)
bad_undef = [ln for ln in undef.splitlines()
             if "__imp_" not in ln and "Beacon" not in ln and "DFR" not in ln.upper()]
if bad_undef:
    sys.exit("bad undefined: " + "; ".join(bad_undef[:8]))

print("  [ok] blob canary + symbol hygiene (no chkstk, no bare externs)")
