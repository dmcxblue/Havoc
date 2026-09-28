#!/usr/bin/env bash
# batch_compile.sh — compile the whole sekurlsa TU set, report per-file first error.
set -u
M="x86_64-w64-mingw32"
MIK="/tmp/mimikatz"
OUT="$MIK/BOF/obj"
mkdir -p "$OUT"
FLAGS=(-c -Os -fcommon -fno-stack-protector -fno-asynchronous-unwind-tables
  -mno-stack-arg-probe -ffreestanding -w -std=gnu17
  -Wno-error=incompatible-pointer-types -Wno-error=int-conversion
  -Wno-error=implicit-function-declaration
  -DUNICODE -D_UNICODE -D_WIN64 -D_WIN32_WINNT=0x0603
  -include "$MIK/BOF/bof_compat.h"
  -I"$MIK/BOF/casefix" -I"$MIK/inc" -I"$MIK/modules" -I"$MIK/mimikatz/modules" -I"$MIK/BOF")

TUS=(
  modules/kull_m_process.c
  modules/kull_m_memory.c
  modules/kull_m_crypto.c
  modules/kull_m_patch.c
  modules/kull_m_file.c
  modules/kull_m_token.c
  modules/kull_m_net.c
  modules/kull_m_ldap.c
  modules/kull_m_handle.c
  modules/kull_m_registry.c
  modules/kull_m_service.c
  modules/kull_m_pipe.c
  modules/kull_m_remotelib.c
  modules/kull_m_asn1.c
  modules/kull_m_cred.c
  modules/kull_m_key.c
  modules/kull_m_dpapi.c
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
  modules/rpc/kull_m_rpc.c
  modules/rpc/kull_m_rpc_ms-credentialkeys.c
)

pass=0; fail=0
for tu in "${TUS[@]}"; do
  base="$(basename "$tu" .c)"
  err="$("$M-gcc" "${FLAGS[@]}" -o "$OUT/$base.o" "$MIK/$tu" 2>&1 | grep -m1 'error:')"
  if [ -z "$err" ]; then
    echo "OK   $tu"; pass=$((pass+1))
  else
    echo "FAIL $tu"; echo "       $err"; fail=$((fail+1))
  fi
done
echo "===== $pass OK, $fail FAIL ====="
