#pragma once
#include "common.h"
#include "beacon.h"

static pCDLocateCSystem CDLocateCSystem = NULL;

BOOL LoadCryptDll() {
    HMODULE hCryptDll = KERNEL32$LoadLibraryA("cryptdll.dll");
    if (!hCryptDll) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to load cryptdll.dll");
        return FALSE;
    }

    CDLocateCSystem = (pCDLocateCSystem)KERNEL32$GetProcAddress(hCryptDll, "CDLocateCSystem");
    if (!CDLocateCSystem) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to resolve CDLocateCSystem");
        return FALSE;
    }

    return TRUE;
}

BOOL encrypt(BYTE* rawBytes, int rawSize, BYTE* key, DWORD eType, int keyUsage, BYTE** result, DWORD* size) {
    PKERB_ECRYPT pCSystem;
    PVOID pContext;
    BOOL status = TRUE;

    if (!NT_SUCCESS(CDLocateCSystem(eType, &pCSystem))) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to call CDLocateCSystem");
        return FALSE;
    }

    if (!NT_SUCCESS(pCSystem->Initialize(key, pCSystem->KeySize, keyUsage, &pContext))) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to initialize crypto system");
        return FALSE;
    }

    *size = rawSize;
    DWORD modulo = *size % pCSystem->BlockSize;
    if (modulo)
        *size += pCSystem->BlockSize - modulo;
    *size += pCSystem->HeaderSize;

    *result = MemAlloc(*size);
    if (*result) {
        if (!NT_SUCCESS(pCSystem->Encrypt(pContext, rawBytes, rawSize, *result, size))) {
            BeaconPrintf(CALLBACK_ERROR, "[-] Failed to encrypt data");
            status = FALSE;
        }
    } else {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed alloc memory");
        status = FALSE;
    }

    pCSystem->Finish(&pContext);
    return status;
}

BOOL decrypt(BYTE* key, DWORD eType, DWORD keyUsage, BYTE* data, int dataSize, BYTE** result, DWORD* size) {
    PKERB_ECRYPT pCSystem;
    PVOID pContext;
    NTSTATUS status;

    status = CDLocateCSystem(eType, &pCSystem);
    if (!NT_SUCCESS(status)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to call CDLocateCSystem");
        return FALSE;
    }

    status = pCSystem->Initialize(key, pCSystem->KeySize, keyUsage, &pContext);
    if (!NT_SUCCESS(status)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to initialize crypto system");
        return FALSE;
    }

    *result = MemAlloc(dataSize);
    if (!*result) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to allocate memory for decryption");
        pCSystem->Finish(&pContext);
        return FALSE;
    }
    *size = dataSize;
    status = pCSystem->Decrypt(pContext, data, dataSize, *result, size);
    pCSystem->Finish(&pContext);
    if (!NT_SUCCESS(status)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to decrypt data (0x%08x)", status);
        return FALSE;
    }
    return TRUE;
}