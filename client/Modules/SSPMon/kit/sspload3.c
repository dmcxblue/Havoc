// sspload3.c — control test: AddSecurityPackageW with an EXISTING package name.
// If the RPC opnum were merely gated for unknown DLLs, a known package would
// behave differently. RPC_S_PROCNUM_OUT_OF_RANGE here = the lsass-side proc
// is gone entirely on this build (runtime SSP loading removed).
// usage: sspload3.exe <package-name>   e.g. sspload3.exe wdigest

#include <windows.h>

typedef ULONG (NTAPI *PFN_AddSecurityPackageW)(LPWSTR PackageName, void *Reserved);

static void LogLine(const char *line)
{
	HANDLE f = CreateFileW(L"C:\\Windows\\Temp\\sspload_dbg.txt",
		FILE_APPEND_DATA | SYNCHRONIZE, FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if(f == INVALID_HANDLE_VALUE) return;
	SetFilePointer(f, 0, NULL, FILE_END);
	DWORD w = 0;
	WriteFile(f, line, lstrlenA(line), &w, NULL);
	WriteFile(f, "\r\n", 2, &w, NULL);
	CloseHandle(f);
}

static void LogFmt(const char *prefix, ULONG v)
{
	char buf[128];
	wsprintfA(buf, "%s 0x%08lx (%lu)", prefix, v, v);
	LogLine(buf);
}

int main(int argc, char **argv)
{
	DeleteFileW(L"C:\\Windows\\Temp\\sspload_dbg.txt");
	LogLine("== sspload3 (control) start ==");
	if(argc < 2) { LogLine("FAIL: need package name"); return 2; }
	LogLine(argv[1]);

	HMODULE h = LoadLibraryW(L"sspicli.dll");
	if(!h) { LogFmt("LoadLibraryW GLE =", GetLastError()); return 1; }
	PFN_AddSecurityPackageW p =
		(PFN_AddSecurityPackageW) GetProcAddress(h, "AddSecurityPackageW");
	if(!p) { LogFmt("GetProcAddress GLE =", GetLastError()); return 1; }

	wchar_t wname[256];
	MultiByteToWideChar(CP_ACP, 0, argv[1], -1, wname, 256);
	LogLine("calling AddSecurityPackageW(existing name) ...");
	ULONG st = p(wname, NULL);
	LogFmt("NTSTATUS =", st);
	LogFmt("GLE =", GetLastError());
	LogLine(st == 0 ? "== RESULT: SUCCESS ==" : "== RESULT: FAILED ==");
	return st == 0 ? 0 : 1;
}
