#!/usr/bin/env bash
# build_bofs.sh — compile SSPMon BOFs (Havoc-compatible COFF) + embedded DLL.
# Usage: ./build_bofs.sh      (run from the SSPMon directory)
set -euo pipefail

M="x86_64-w64-mingw32"
CC="${M}-gcc"; LD="${M}-ld"; OC="${M}-objcopy"

ROOT="$(cd "$(dirname "$0")" && pwd)"
BOF="$ROOT/bof"; OBJ="$BOF/obj"; BIN="$ROOT/bin"
mkdir -p "$OBJ" "$BIN"

# Self-contained beacon.h (copied once from ../mimikatz/BOF if absent)
[ -f "$BOF/beacon.h" ] || cp ../mimikatz/BOF/beacon.h "$BOF/beacon.h"

CFLAGS=(
  -c -Os -fcommon -fno-stack-protector -fno-asynchronous-unwind-tables
  -mno-stack-arg-probe -ffreestanding -std=gnu17 -w
  -DUNICODE -D_UNICODE -D_WIN64 -D_WIN32_WINNT=0x0603
  -I"$BOF"
)

echo "== embedded DLL blob =="
cp "$ROOT/kit/sspmon2.dll" "$OBJ/sspmon2.dll"
# objcopy derives symbol names from the path AS GIVEN — use a bare relative
# filename so symbols are canonical (_binary_sspmon2_dll_start), then rename.
( cd "$OBJ" && "$OC" -I binary -O pe-x86-64 -B i386 sspmon2.dll ssp_dll_blob.o )
"$OC" "$OBJ/ssp_dll_blob.o" \
  --redefine-sym _binary_sspmon2_dll_start=ssp_dll_start \
  --redefine-sym _binary_sspmon2_dll_end=ssp_dll_end \
  --redefine-sym _binary_sspmon2_dll_size=ssp_dll_size
# HARD FAIL if the rename missed (objcopy --redefine-sym is silent on no-match)
if ! "$M"-nm "$OBJ/ssp_dll_blob.o" | grep -q ' D ssp_dll_start$'; then
  echo "FATAL: ssp_dll_start not defined in blob object — symbol rename failed" >&2
  "$M"-nm "$OBJ/ssp_dll_blob.o" >&2
  exit 1
fi
echo "  [objcopy] ssp_dll_blob.o (symbols verified)"

echo "== compile =="
for src in ssp_install ssp_remove ssp_status ssp_log; do
  "$CC" "${CFLAGS[@]}" -o "$OBJ/$src.o" "$BOF/$src.c" && echo "  [cc] $src.c"
done

echo "== link (ld -r) =="
"$LD" -r -o "$BIN/ssp_install.x64.o" "$OBJ/ssp_install.o" "$OBJ/ssp_dll_blob.o"
echo "  [ld] ssp_install.x64.o (with embedded DLL)"
for b in ssp_remove ssp_status ssp_log; do
  "$LD" -r -o "$BIN/$b.x64.o" "$OBJ/$b.o"
  echo "  [ld] $b.x64.o"
done
# strip debug only — keeps symbol table intact (see mimikatz BOF build.sh note)
for b in ssp_install ssp_remove ssp_status ssp_log; do
  "$OC" --strip-debug "$BIN/$b.x64.o" 2>/dev/null || true
done

echo "== done =="
ls -la "$BIN"
