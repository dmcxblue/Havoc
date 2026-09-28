/*
 * bof_resolve.c — runtime resolution of CNG / cryptdll / rpcrt4 APIs.
 *
 * These DLLs (bcrypt, ncrypt, cryptdll, rpcrt4) are NOT in the BOF loader's
 * default import set, so mimikatz's calls to them are satisfied here via
 * GetModuleHandle/GetProcAddress at runtime. Each export is resolved once and
 * exposed through a thin wrapper whose signature matches the system headers.
 */
#include "bofdefs.h"
#include <bcrypt.h>
#include <ncrypt.h>
#include <rpcndr.h>

/* cryptdll (no system header; mimikatz declares these in kull_m_crypto_system.h) */
typedef NTSTATUS (WINAPI *PFN_CDGenerateRandomBits)(LPVOID pbBuffer, ULONG cbBuffer);
typedef NTSTATUS (WINAPI *PFN_CDLocateCheckSum)(ULONG Type, PVOID *ppCheckSum);
typedef NTSTATUS (WINAPI *PFN_CDLocateCSystem)(ULONG Type, PVOID *ppCSystem);

typedef NTSTATUS (WINAPI *PFN_BCryptOpenAlgorithmProvider)(BCRYPT_ALG_HANDLE*, LPCWSTR, LPCWSTR, ULONG);
typedef NTSTATUS (WINAPI *PFN_BCryptCloseAlgorithmProvider)(BCRYPT_ALG_HANDLE, ULONG);
typedef NTSTATUS (WINAPI *PFN_BCryptGenerateSymmetricKey)(BCRYPT_ALG_HANDLE, BCRYPT_KEY_HANDLE*, PUCHAR, ULONG, PUCHAR, ULONG, ULONG);
typedef NTSTATUS (WINAPI *PFN_BCryptCrypt)(BCRYPT_KEY_HANDLE, PUCHAR, ULONG, VOID*, PUCHAR, ULONG, PUCHAR, ULONG, ULONG*, ULONG);
typedef NTSTATUS (WINAPI *PFN_BCryptDestroyKey)(BCRYPT_KEY_HANDLE);
typedef NTSTATUS (WINAPI *PFN_BCryptGetProperty)(BCRYPT_HANDLE, LPCWSTR, PUCHAR, ULONG, ULONG*, ULONG);
typedef NTSTATUS (WINAPI *PFN_BCryptSetProperty)(BCRYPT_HANDLE, LPCWSTR, PUCHAR, ULONG, ULONG);
typedef NTSTATUS (WINAPI *PFN_BCryptKeyDerivation)(BCRYPT_KEY_HANDLE, BCryptBufferDesc*, PUCHAR, ULONG, ULONG*, ULONG);

typedef SECURITY_STATUS (WINAPI *PFN_NCryptOpenStorageProvider)(NCRYPT_PROV_HANDLE*, LPCWSTR, DWORD);
typedef SECURITY_STATUS (WINAPI *PFN_NCryptImportKey)(NCRYPT_PROV_HANDLE, NCRYPT_KEY_HANDLE, LPCWSTR, NCryptBufferDesc*, NCRYPT_KEY_HANDLE*, PBYTE, DWORD, DWORD);
typedef SECURITY_STATUS (WINAPI *PFN_NCryptGetProperty)(NCRYPT_HANDLE, LPCWSTR, PBYTE, DWORD, DWORD*, DWORD);
typedef SECURITY_STATUS (WINAPI *PFN_NCryptSetProperty)(NCRYPT_HANDLE, LPCWSTR, PBYTE, DWORD, DWORD);
typedef SECURITY_STATUS (WINAPI *PFN_NCryptFinalizeKey)(NCRYPT_KEY_HANDLE, DWORD);
typedef SECURITY_STATUS (WINAPI *PFN_NCryptFreeObject)(NCRYPT_HANDLE);

typedef RPC_STATUS (RPC_ENTRY *PFN_MesEncodeDecodeHandleCreate)(void*, void*);
typedef RPC_STATUS (RPC_ENTRY *PFN_MesIncrementalHandleReset)(handle_t, void*, void*, void*, void*, void*, void*);
typedef RPC_STATUS (RPC_ENTRY *PFN_MesHandleFree)(handle_t);
typedef void (RPC_ENTRY *PFN_NdrMesType)(handle_t, void*, void*, PFORMAT_STRING, void*);

static HMODULE g_bcrypt, g_ncrypt, g_cryptdll, g_rpcrt4;
static int g_resolved;

static PFN_BCryptOpenAlgorithmProvider     p_BCryptOpenAlgorithmProvider;
static PFN_BCryptCloseAlgorithmProvider    p_BCryptCloseAlgorithmProvider;
static PFN_BCryptGenerateSymmetricKey      p_BCryptGenerateSymmetricKey;
static PFN_BCryptCrypt                     p_BCryptEncrypt, p_BCryptDecrypt;
static PFN_BCryptDestroyKey                p_BCryptDestroyKey;
static PFN_BCryptGetProperty              p_BCryptGetProperty;
static PFN_BCryptSetProperty              p_BCryptSetProperty;
static PFN_BCryptKeyDerivation            p_BCryptKeyDerivation;
static PFN_NCryptOpenStorageProvider       p_NCryptOpenStorageProvider;
static PFN_NCryptImportKey                 p_NCryptImportKey;
static PFN_NCryptGetProperty              p_NCryptGetProperty;
static PFN_NCryptSetProperty              p_NCryptSetProperty;
static PFN_NCryptFinalizeKey              p_NCryptFinalizeKey;
static PFN_NCryptFreeObject               p_NCryptFreeObject;
static PFN_CDGenerateRandomBits           p_CDGenerateRandomBits;
static PFN_CDLocateCheckSum               p_CDLocateCheckSum;
static PFN_CDLocateCSystem                p_CDLocateCSystem;
static PFN_MesEncodeDecodeHandleCreate     p_MesEncodeIncrementalHandleCreate, p_MesDecodeIncrementalHandleCreate;
static PFN_MesIncrementalHandleReset       p_MesIncrementalHandleReset;
static PFN_MesHandleFree                   p_MesHandleFree;
static PFN_NdrMesType                      p_NdrMesTypeDecode2, p_NdrMesTypeFree2, p_NdrMesTypeEncode2, p_NdrMesTypeAlignSize2;

static void bof_resolve(void) {
    if (g_resolved) return;
    /* LoadLibraryA in case the beacon process hasn't already loaded the DLL
     * (a minimal agent won't have cryptdll.dll mapped, so GetModuleHandleA
     * returns NULL and every resolved export becomes a NULL-pointer call). */
    g_bcrypt   = GetModuleHandleA("bcrypt.dll");   if(!g_bcrypt)   g_bcrypt   = LoadLibraryA("bcrypt.dll");
    g_ncrypt   = GetModuleHandleA("ncrypt.dll");   if(!g_ncrypt)   g_ncrypt   = LoadLibraryA("ncrypt.dll");
    g_cryptdll = GetModuleHandleA("cryptdll.dll"); if(!g_cryptdll) g_cryptdll = LoadLibraryA("cryptdll.dll");
    g_rpcrt4   = GetModuleHandleA("rpcrt4.dll");   if(!g_rpcrt4)   g_rpcrt4   = LoadLibraryA("rpcrt4.dll");

    p_BCryptOpenAlgorithmProvider = (void*)GetProcAddress(g_bcrypt, "BCryptOpenAlgorithmProvider");
    p_BCryptCloseAlgorithmProvider = (void*)GetProcAddress(g_bcrypt, "BCryptCloseAlgorithmProvider");
    p_BCryptGenerateSymmetricKey = (void*)GetProcAddress(g_bcrypt, "BCryptGenerateSymmetricKey");
    p_BCryptEncrypt = (void*)GetProcAddress(g_bcrypt, "BCryptEncrypt");
    p_BCryptDecrypt = (void*)GetProcAddress(g_bcrypt, "BCryptDecrypt");
    p_BCryptDestroyKey = (void*)GetProcAddress(g_bcrypt, "BCryptDestroyKey");
    p_BCryptGetProperty = (void*)GetProcAddress(g_bcrypt, "BCryptGetProperty");
    p_BCryptSetProperty = (void*)GetProcAddress(g_bcrypt, "BCryptSetProperty");
    p_BCryptKeyDerivation = (void*)GetProcAddress(g_bcrypt, "BCryptKeyDerivation");

    p_NCryptOpenStorageProvider = (void*)GetProcAddress(g_ncrypt, "NCryptOpenStorageProvider");
    p_NCryptImportKey = (void*)GetProcAddress(g_ncrypt, "NCryptImportKey");
    p_NCryptGetProperty = (void*)GetProcAddress(g_ncrypt, "NCryptGetProperty");
    p_NCryptSetProperty = (void*)GetProcAddress(g_ncrypt, "NCryptSetProperty");
    p_NCryptFinalizeKey = (void*)GetProcAddress(g_ncrypt, "NCryptFinalizeKey");
    p_NCryptFreeObject = (void*)GetProcAddress(g_ncrypt, "NCryptFreeObject");

    p_CDGenerateRandomBits = (void*)GetProcAddress(g_cryptdll, "CDGenerateRandomBits");
    p_CDLocateCheckSum = (void*)GetProcAddress(g_cryptdll, "CDLocateCheckSum");
    p_CDLocateCSystem = (void*)GetProcAddress(g_cryptdll, "CDLocateCSystem");

    p_MesEncodeIncrementalHandleCreate = (void*)GetProcAddress(g_rpcrt4, "MesEncodeIncrementalHandleCreate");
    p_MesDecodeIncrementalHandleCreate = (void*)GetProcAddress(g_rpcrt4, "MesDecodeIncrementalHandleCreate");
    p_MesIncrementalHandleReset = (void*)GetProcAddress(g_rpcrt4, "MesIncrementalHandleReset");
    p_MesHandleFree = (void*)GetProcAddress(g_rpcrt4, "MesHandleFree");
    p_NdrMesTypeDecode2 = (void*)GetProcAddress(g_rpcrt4, "NdrMesTypeDecode2");
    p_NdrMesTypeFree2 = (void*)GetProcAddress(g_rpcrt4, "NdrMesTypeFree2");
    p_NdrMesTypeEncode2 = (void*)GetProcAddress(g_rpcrt4, "NdrMesTypeEncode2");
    p_NdrMesTypeAlignSize2 = (void*)GetProcAddress(g_rpcrt4, "NdrMesTypeAlignSize2");

    g_resolved = 1;
}

NTSTATUS WINAPI BCryptOpenAlgorithmProvider(BCRYPT_ALG_HANDLE* a, LPCWSTR b, LPCWSTR c, ULONG d) { bof_resolve(); return p_BCryptOpenAlgorithmProvider(a, b, c, d); }
NTSTATUS WINAPI BCryptCloseAlgorithmProvider(BCRYPT_ALG_HANDLE a, ULONG b) { bof_resolve(); return p_BCryptCloseAlgorithmProvider(a, b); }
NTSTATUS WINAPI BCryptGenerateSymmetricKey(BCRYPT_ALG_HANDLE a, BCRYPT_KEY_HANDLE* b, PUCHAR c, ULONG d, PUCHAR e, ULONG f, ULONG g) { bof_resolve(); return p_BCryptGenerateSymmetricKey(a, b, c, d, e, f, g); }
NTSTATUS WINAPI BCryptEncrypt(BCRYPT_KEY_HANDLE a, PUCHAR b, ULONG c, VOID* d, PUCHAR e, ULONG f, PUCHAR g, ULONG h, ULONG* i, ULONG j) { bof_resolve(); return p_BCryptEncrypt(a, b, c, d, e, f, g, h, i, j); }
NTSTATUS WINAPI BCryptDecrypt(BCRYPT_KEY_HANDLE a, PUCHAR b, ULONG c, VOID* d, PUCHAR e, ULONG f, PUCHAR g, ULONG h, ULONG* i, ULONG j) { bof_resolve(); return p_BCryptDecrypt(a, b, c, d, e, f, g, h, i, j); }
NTSTATUS WINAPI BCryptDestroyKey(BCRYPT_KEY_HANDLE a) { bof_resolve(); return p_BCryptDestroyKey(a); }
NTSTATUS WINAPI BCryptGetProperty(BCRYPT_HANDLE a, LPCWSTR b, PUCHAR c, ULONG d, ULONG* e, ULONG f) { bof_resolve(); return p_BCryptGetProperty(a, b, c, d, e, f); }
NTSTATUS WINAPI BCryptSetProperty(BCRYPT_HANDLE a, LPCWSTR b, PUCHAR c, ULONG d, ULONG e) { bof_resolve(); return p_BCryptSetProperty(a, b, c, d, e); }
NTSTATUS WINAPI BCryptKeyDerivation(BCRYPT_KEY_HANDLE a, BCryptBufferDesc* b, PUCHAR c, ULONG d, ULONG* e, ULONG f) { bof_resolve(); return p_BCryptKeyDerivation(a, b, c, d, e, f); }

SECURITY_STATUS WINAPI NCryptOpenStorageProvider(NCRYPT_PROV_HANDLE* a, LPCWSTR b, DWORD c) { bof_resolve(); return p_NCryptOpenStorageProvider(a, b, c); }
SECURITY_STATUS WINAPI NCryptImportKey(NCRYPT_PROV_HANDLE a, NCRYPT_KEY_HANDLE b, LPCWSTR c, NCryptBufferDesc* d, NCRYPT_KEY_HANDLE* e, PBYTE f, DWORD g, DWORD h) { bof_resolve(); return p_NCryptImportKey(a, b, c, d, e, f, g, h); }
SECURITY_STATUS WINAPI NCryptGetProperty(NCRYPT_HANDLE a, LPCWSTR b, PBYTE c, DWORD d, DWORD* e, DWORD f) { bof_resolve(); return p_NCryptGetProperty(a, b, c, d, e, f); }
SECURITY_STATUS WINAPI NCryptSetProperty(NCRYPT_HANDLE a, LPCWSTR b, PBYTE c, DWORD d, DWORD e) { bof_resolve(); return p_NCryptSetProperty(a, b, c, d, e); }
SECURITY_STATUS WINAPI NCryptFinalizeKey(NCRYPT_KEY_HANDLE a, DWORD b) { bof_resolve(); return p_NCryptFinalizeKey(a, b); }
SECURITY_STATUS WINAPI NCryptFreeObject(NCRYPT_HANDLE a) { bof_resolve(); return p_NCryptFreeObject(a); }

NTSTATUS WINAPI CDGenerateRandomBits(LPVOID a, ULONG b) { bof_resolve(); return p_CDGenerateRandomBits(a, b); }
NTSTATUS WINAPI CDLocateCheckSum(ULONG a, PVOID* b) { bof_resolve(); return p_CDLocateCheckSum(a, b); }
NTSTATUS WINAPI CDLocateCSystem(ULONG a, PVOID* b) { bof_resolve(); return p_CDLocateCSystem(a, b); }

RPC_STATUS RPC_ENTRY MesEncodeIncrementalHandleCreate(void* a, void* b) { bof_resolve(); return p_MesEncodeIncrementalHandleCreate(a, b); }
RPC_STATUS RPC_ENTRY MesDecodeIncrementalHandleCreate(void* a, void* b) { bof_resolve(); return p_MesDecodeIncrementalHandleCreate(a, b); }
RPC_STATUS RPC_ENTRY MesIncrementalHandleReset(handle_t a, void* b, void* c, void* d, void* e, void* f, void* g) { bof_resolve(); return p_MesIncrementalHandleReset(a, b, c, d, e, f, g); }
RPC_STATUS RPC_ENTRY MesHandleFree(handle_t a) { bof_resolve(); return p_MesHandleFree(a); }
void RPC_ENTRY NdrMesTypeDecode2(handle_t a, void* b, void* c, PFORMAT_STRING d, void* e) { bof_resolve(); p_NdrMesTypeDecode2(a, b, c, d, e); }
void RPC_ENTRY NdrMesTypeFree2(handle_t a, void* b, void* c, PFORMAT_STRING d, void* e) { bof_resolve(); p_NdrMesTypeFree2(a, b, c, d, e); }
void RPC_ENTRY NdrMesTypeEncode2(handle_t a, void* b, void* c, PFORMAT_STRING d, void* e) { bof_resolve(); p_NdrMesTypeEncode2(a, b, c, d, e); }
void RPC_ENTRY NdrMesTypeAlignSize2(handle_t a, void* b, void* c, PFORMAT_STRING d, void* e) { bof_resolve(); p_NdrMesTypeAlignSize2(a, b, c, d, e); }
