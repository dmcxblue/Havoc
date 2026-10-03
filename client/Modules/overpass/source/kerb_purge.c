/*
 * kerb_purge.c — Purge Kerberos ticket cache for the current LUID.
 * Revert primitive paired with kerb_ptt.
 */

#include <windows.h>
#include <ntsecapi.h>

extern "C" {
#include "beacon.h"

void go(char* buff, int len);

DECLSPEC_IMPORT NTSTATUS NTAPI SECUR32$LsaConnectUntrusted(PHANDLE);
DECLSPEC_IMPORT NTSTATUS NTAPI SECUR32$LsaLookupAuthenticationPackage(HANDLE, PLSA_STRING, PULONG);
DECLSPEC_IMPORT NTSTATUS NTAPI SECUR32$LsaCallAuthenticationPackage(HANDLE, ULONG, PVOID, ULONG, PVOID*, PULONG, PNTSTATUS);
DECLSPEC_IMPORT NTSTATUS NTAPI SECUR32$LsaFreeReturnBuffer(PVOID);
DECLSPEC_IMPORT NTSTATUS NTAPI SECUR32$LsaDeregisterLogonProcess(HANDLE);
}

typedef struct _KERB_PURGE_TKT_CACHE_REQUEST_LITE {
    ULONG MessageType;      /* KerbPurgeTicketCacheMessage = 3 */
    LUID  LogonId;
    UNICODE_STRING ServerName;
    UNICODE_STRING RealmName;
} KERB_PURGE_TKT_CACHE_REQUEST_LITE;

#define KerbPurgeTicketCacheMessage_LITE 6

static BOOL make_lsa_string(LSA_STRING* out, const char* s)
{
    size_t n = 0;
    while (s[n]) n++;
    if (n > 0xFFFE) return FALSE;
    out->Length        = (USHORT)n;
    out->MaximumLength = (USHORT)(n + 1);
    out->Buffer        = (PCHAR)s;
    return TRUE;
}

void go(char* buff, int len)
{
    NTSTATUS status = 0, subStatus = 0;
    HANDLE   hLsa  = NULL;
    ULONG    authPkg = 0;
    LSA_STRING pkgName;
    KERB_PURGE_TKT_CACHE_REQUEST_LITE req;
    PVOID    outBuf = NULL;
    ULONG    outLen = 0;

    (void)buff; (void)len;

    status = SECUR32$LsaConnectUntrusted(&hLsa);
    if (status < 0 || !hLsa) {
        BeaconPrintf(CALLBACK_ERROR, "overpass/purge: LsaConnectUntrusted 0x%08lx", status);
        return;
    }

    if (!make_lsa_string(&pkgName, "Kerberos")) {
        BeaconPrintf(CALLBACK_ERROR, "overpass/purge: pkg name init failed");
        goto cleanup;
    }

    status = SECUR32$LsaLookupAuthenticationPackage(hLsa, &pkgName, &authPkg);
    if (status < 0) {
        BeaconPrintf(CALLBACK_ERROR, "overpass/purge: LsaLookupAuthenticationPackage 0x%08lx", status);
        goto cleanup;
    }

    req.MessageType       = KerbPurgeTicketCacheMessage_LITE;
    req.LogonId.LowPart   = 0;
    req.LogonId.HighPart  = 0;
    req.ServerName.Length = 0; req.ServerName.MaximumLength = 0; req.ServerName.Buffer = NULL;
    req.RealmName.Length  = 0; req.RealmName.MaximumLength  = 0; req.RealmName.Buffer  = NULL;

    status = SECUR32$LsaCallAuthenticationPackage(
        hLsa, authPkg, &req, sizeof(req), &outBuf, &outLen, &subStatus
    );

    if (status < 0 || subStatus < 0) {
        BeaconPrintf(CALLBACK_ERROR,
            "overpass/purge: LsaCallAuthenticationPackage status=0x%08lx sub=0x%08lx",
            status, subStatus);
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "overpass/purge: current LUID's Kerberos ticket cache cleared");
    }

    if (outBuf) SECUR32$LsaFreeReturnBuffer(outBuf);

cleanup:
    if (hLsa) SECUR32$LsaDeregisterLogonProcess(hLsa);
}
