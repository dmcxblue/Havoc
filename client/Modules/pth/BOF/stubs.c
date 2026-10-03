/*
 * stubs.c — no-op implementations for mimikatz functions that are referenced
 * by the compiled TUs but belong to commands we are NOT shipping (backupkeys,
 * dcshadow, lsadump-remote, etc.). They let the BOF link without pulling in
 * the huge lsadump/dcshadow/SAM/RPC dependency tree.
 */
#include "bofdefs.h"

/* kuhl_m_lsadump_analyzeKey — only used by sekurlsa::backupkeys (DPAPI backup
 * key export). logonpasswords does not call it. */
void kuhl_m_lsadump_analyzeKey(const void* guid, void* secret, unsigned long size, int isExport) {
    (void)guid; (void)secret; (void)size; (void)isExport;
}

/* kull_m_rpc_bkrp_Restore — DPAPI backup-key restore (dpapi::backupkeys). */
int kull_m_rpc_bkrp_Restore(const wchar_t* addr, void* in, unsigned long inlen, void** out, unsigned long* outlen) {
    (void)addr; (void)in; (void)inlen; (void)out; (void)outlen;
    return 0;
}
