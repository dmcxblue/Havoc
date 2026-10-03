// sspload2.c — sspload with file-based diagnostics (no stdout dependency).
// Logs each step to C:\Windows\Temp\sspload_dbg.txt so failures are visible
// even when the RemCom/psexec pipe swallows console output.
// usage: sspload2.exe C:\Windows\Temp\sspmon.dll   (run as SYSTEM)

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
	LogLine("== sspload2 start ==");
	LogFmt("argc =", (ULONG) argc);
	if(argc < 2) { LogLine("FAIL: no argument"); return 2; }
	LogLine(argv[1]);

	HMODULE h = GetModuleHandleW(L"sspicli.dll");
	if(h) LogLine("GetModuleHandleW(sspicli.dll): OK");
	else {
		LogFmt("GetModuleHandleW failed GLE =", GetLastError());
		h = LoadLibraryW(L"sspicli.dll");
		if(h) LogLine("LoadLibraryW(sspicli.dll): OK");
		else LogFmt("LoadLibraryW failed GLE =", GetLastError());
	}
	if(!h) { LogLine("FAIL: no sspicli"); return 1; }

	PFN_AddSecurityPackageW p =
		(PFN_AddSecurityPackageW) GetProcAddress(h, "AddSecurityPackageW");
	if(p) LogLine("GetProcAddress(AddSecurityPackageW): OK");
	else { LogFmt("GetProcAddress failed GLE =", GetLastError()); return 1; }

	wchar_t wpath[512];
	MultiByteToWideChar(CP_ACP, 0, argv[1], -1, wpath, 512);
	LogLine("calling AddSecurityPackageW ...");
	ULONG st = p(wpath, NULL);
	LogFmt("AddSecurityPackageW NTSTATUS =", st);
	LogLine(st == 0 ? "== RESULT: SUCCESS ==" : "== RESULT: FAILED ==");
	return st == 0 ? 0 : 1;
}
