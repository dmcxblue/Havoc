/*
 * bof_globals.c — strong definitions for tentative header globals that would
 * otherwise become SHN_COMMON symbols (which BOF loaders handle poorly).
 * None of these are used by the logonpasswords code path, so zero-init is fine.
 */
#include "kuhl_m.h"
#include "kull_m_crypto_system.h"
#include "kull_m_crypto.h"
#include "rpc/kull_m_rpc_ms-drsr.h"
#include "sekurlsa/crypto/kuhl_m_sekurlsa_nt5.h"
#include "sekurlsa/crypto/kuhl_m_sekurlsa_nt6.h"
#include "crypto/kuhl_m_crypto_patch.h"

const KUHL_M kuhl_m_crypto  = {0};
const KUHL_M kuhl_m_dpapi   = {0};
const KUHL_M kuhl_m_kerberos = {0};
const KUHL_M kuhl_m_lsadump = {0};
const KUHL_M kuhl_m_process = {0};
const KUHL_M kuhl_m_token   = {0};

const wchar_t * KUHL_M_LSADUMP_UF_FLAG[32] = {0};
const SCHEMA_PREFIX_TABLE SCHEMA_DEFAULT_PREFIX_TABLE = {0};

const GUID BACKUPKEY_BACKUP_GUID = {0};
const GUID BACKUPKEY_RESTORE_GUID = {0};
const GUID BACKUPKEY_RESTORE_GUID_WIN2K = {0};
const GUID BACKUPKEY_RETRIEVE_BACKUP_KEY_GUID = {0};

BYTE g_Feedback[8] = {0};
BYTE g_pRandomKey[256] = {0};
BYTE gIumMkPerBoot[32] = {0};
BYTE InitializationVector[16] = {0};

KIWI_BCRYPT_GEN_KEY k3Des = {0};
KIWI_BCRYPT_GEN_KEY kAes = {0};
PCP_EXPORTKEY K_RSA_CPExportKey = {0};
PCP_EXPORTKEY K_DSS_CPExportKey = {0};
SYMCRYPT_NT5_DESX_EXPANDED_KEY g_pDESXKey = {0};
