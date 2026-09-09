/*
 * Gpresult BOF — applied Group Policy reporter.
 *
 * Reimplements the useful core of `gpresult /R` without spawning gpresult.exe.
 *
 * Primary data source (elevated / high-integrity token):
 *   The RSoP WMI provider (root\rsop\user / root\rsop\computer). This is the
 *   authoritative source `gpresult /R` reads and it exposes the applied GPOs,
 *   "last applied" timestamp, and security groups. NOTE: these namespaces have
 *   a restricted DACL — a medium-integrity token gets WBEM_E_ACCESS_DENIED
 *   (0x80041003), so an elevated beacon is required.
 *
 * Fallback (medium-integrity token, RSoP denied):
 *   - Applied GPOs: Group Policy\History registry (baseline only — domain GPOs
 *     are NOT reliably present here).
 *   - Security groups: the current token's groups.
 *
 * Modes (dispatched from gpresult.py):
 *   0 = all, 1 = user, 2 = computer
 *
 * OUTPUT CONTRACT: buffered via bprintf(), flushed in ONE BeaconOutput.
 * BSTR discipline: every WMI string is SysAllocString/SysFreeString.
 */

#define SECURITY_WIN32
#include <windows.h>
#include <secext.h>
#include <dsgetdc.h>
#include <lm.h>
#include <objbase.h>
#include <oleauto.h>
#include <wbemcli.h>
#include <combaseapi.h>
#include <stdarg.h>

extern "C" {
#include "beacon.h"

    void go(char* buff, int len);

    /* OLE32 / COM */
    DECLSPEC_IMPORT HRESULT WINAPI OLE32$CLSIDFromString(wchar_t* lpsz, LPCLSID pclsid);
    DECLSPEC_IMPORT HRESULT WINAPI OLE32$IIDFromString(wchar_t* lpsz, LPIID lpiid);
    DECLSPEC_IMPORT HRESULT WINAPI OLE32$CoCreateInstance(REFCLSID rclsid, LPUNKNOWN pUnkOuter, DWORD dwClsContext, REFIID riid, LPVOID* ppv);
    DECLSPEC_IMPORT HRESULT WINAPI OLE32$CoInitializeEx(LPVOID, DWORD);
    DECLSPEC_IMPORT VOID    WINAPI OLE32$CoUninitialize();
    DECLSPEC_IMPORT HRESULT WINAPI OLE32$CoInitializeSecurity(PSECURITY_DESCRIPTOR pSecDesc, LONG cAuthSvc, SOLE_AUTHENTICATION_SERVICE* asAuthSvc, void* pReserved1, DWORD dwAuthnLevel, DWORD dwImpLevel, void* pAuthList, DWORD dwCapabilities, void* pReserved3);
    DECLSPEC_IMPORT HRESULT WINAPI OLE32$CoSetProxyBlanket(IUnknown* pProxy, DWORD dwAuthnSvc, DWORD dwAuthzSvc, OLECHAR* pServerPrincName, DWORD dwAuthnLevel, DWORD dwImpLevel, RPC_AUTH_IDENTITY_HANDLE pAuthInfo, DWORD dwCapabilities);

    /* OLEAUT32 */
    DECLSPEC_IMPORT VOID    WINAPI OLEAUT32$VariantInit(VARIANTARG* pvarg);
    DECLSPEC_IMPORT HRESULT WINAPI OLEAUT32$VariantClear(VARIANTARG* pvarg);
    DECLSPEC_IMPORT BSTR    WINAPI OLEAUT32$SysAllocString(const OLECHAR* psz);
    DECLSPEC_IMPORT void    WINAPI OLEAUT32$SysFreeString(BSTR bstrString);
    DECLSPEC_IMPORT HRESULT WINAPI OLEAUT32$SafeArrayGetLBound(SAFEARRAY* psa, UINT nDim, LONG* plLbound);
    DECLSPEC_IMPORT HRESULT WINAPI OLEAUT32$SafeArrayGetUBound(SAFEARRAY* psa, UINT nDim, LONG* plUbound);
    DECLSPEC_IMPORT HRESULT WINAPI OLEAUT32$SafeArrayGetElement(SAFEARRAY* psa, LONG* rgIndices, void* pv);

    /* KERNEL32 */
    DECLSPEC_IMPORT int     WINAPI KERNEL32$WideCharToMultiByte(UINT CodePage, DWORD dwFlags, const wchar_t* lpWideCharStr, int cchWideChar, char* lpMultiByteStr, int cbMultiByte, const char* lpDefaultChar, BOOL* lpUsedDefaultChar);
    DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$GetComputerNameExA(COMPUTER_NAME_FORMAT NameType, LPSTR lpBuffer, LPDWORD nSize);
    DECLSPEC_IMPORT DWORD   WINAPI KERNEL32$ExpandEnvironmentStringsA(LPCSTR lpSrc, LPSTR lpDst, DWORD nSize);
    DECLSPEC_IMPORT HMODULE WINAPI KERNEL32$LoadLibraryA(LPCSTR lpLibFileName);
    DECLSPEC_IMPORT FARPROC WINAPI KERNEL32$GetProcAddress(HMODULE hModule, LPCSTR lpProcName);
    DECLSPEC_IMPORT HANDLE  WINAPI KERNEL32$GetCurrentProcess(VOID);
    DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$CloseHandle(HANDLE hObject);
    DECLSPEC_IMPORT HLOCAL  WINAPI KERNEL32$LocalFree(HLOCAL hMem);

    /* ADVAPI32 */
    DECLSPEC_IMPORT LONG   WINAPI ADVAPI32$RegOpenKeyExA(HKEY, LPCSTR, DWORD, REGSAM, PHKEY);
    DECLSPEC_IMPORT LONG   WINAPI ADVAPI32$RegQueryValueExA(HKEY, LPCSTR, LPDWORD, LPDWORD, LPBYTE, LPDWORD);
    DECLSPEC_IMPORT LONG   WINAPI ADVAPI32$RegEnumKeyExA(HKEY, DWORD, LPSTR, LPDWORD, LPDWORD, LPSTR, LPDWORD, PFILETIME);
    DECLSPEC_IMPORT LONG   WINAPI ADVAPI32$RegCloseKey(HKEY);
    DECLSPEC_IMPORT BOOL   WINAPI ADVAPI32$LookupAccountSidA(LPCSTR lpSystemName, PSID Sid, LPSTR Name, LPDWORD cchName, LPSTR ReferencedDomainName, LPDWORD cchReferencedDomainName, PSID_NAME_USE peUse);
    DECLSPEC_IMPORT BOOL   WINAPI ADVAPI32$ConvertSidToStringSidA(PSID Sid, LPSTR* StringSid);
    DECLSPEC_IMPORT BOOL   WINAPI ADVAPI32$ConvertStringSidToSidA(LPCSTR StringSid, PSID* Sid);
    DECLSPEC_IMPORT BOOL   WINAPI ADVAPI32$OpenProcessToken(HANDLE ProcessHandle, DWORD DesiredAccess, PHANDLE TokenHandle);
    DECLSPEC_IMPORT BOOL   WINAPI ADVAPI32$GetTokenInformation(HANDLE TokenHandle, TOKEN_INFORMATION_CLASS TokenInformationClass, LPVOID TokenInformation, DWORD TokenInformationLength, PDWORD ReturnLength);

    /* SECUR32 */
    DECLSPEC_IMPORT BOOLEAN WINAPI SECUR32$GetUserNameExA(EXTENDED_NAME_FORMAT NameFormat, LPSTR lpNameBuffer, PULONG nSize);

    /* NETAPI32 */
    DECLSPEC_IMPORT DWORD WINAPI NETAPI32$DsGetDcNameA(LPCSTR ComputerName, LPCSTR DomainName, GUID* DomainGuid, LPCSTR SiteName, ULONG Flags, PDOMAIN_CONTROLLER_INFOA* DomainControllerInfo);
    DECLSPEC_IMPORT NET_API_STATUS WINAPI NETAPI32$NetApiBufferFree(LPVOID Buffer);

    /* MSVCRT */
    DECLSPEC_IMPORT int    __cdecl MSVCRT$sprintf(char* d, const char* fmt, ...);
    DECLSPEC_IMPORT int    __cdecl MSVCRT$vsnprintf(char* d, size_t n, const char* fmt, va_list arg);
    DECLSPEC_IMPORT void*  __cdecl MSVCRT$calloc(size_t n, size_t s);
    DECLSPEC_IMPORT void   __cdecl MSVCRT$free(void* p);
    DECLSPEC_IMPORT void*  __cdecl MSVCRT$memcpy(void* d, const void* s, size_t n);
    DECLSPEC_IMPORT size_t __cdecl MSVCRT$strlen(const char* s);
}

#define OUTBUFSIZE 65536

/* ---- buffered output ---- */
static char* g_out    = (char*)1;
static int   g_outLen = 1;

static void bflush(void)
{
    if (g_out != NULL && g_out != (char*)1 && g_outLen > 0)
        BeaconOutput(CALLBACK_OUTPUT, g_out, g_outLen);
    g_outLen = 0;
    if (g_out != NULL && g_out != (char*)1)
        g_out[0] = '\0';
}

static void bprintf(const char* fmt, ...)
{
    va_list ap;
    char    tmp[2048];
    int     n, remaining, toCopy;
    if (g_out == NULL || g_out == (char*)1) return;
    va_start(ap, fmt);
    n = MSVCRT$vsnprintf(tmp, sizeof(tmp), fmt, ap);
    va_end(ap);
    if (n <= 0) return;
    if (n >= (int)sizeof(tmp)) n = (int)sizeof(tmp) - 1;
    if (g_outLen + n >= OUTBUFSIZE) bflush();
    remaining = OUTBUFSIZE - g_outLen - 1;
    toCopy    = (n < remaining) ? n : remaining;
    MSVCRT$memcpy(g_out + g_outLen, tmp, (size_t)toCopy);
    g_outLen += toCopy;
    g_out[g_outLen] = '\0';
}

/* ---- header globals ---- */
static char g_computer[256];
static char g_domain[256];
static char g_netbios[256];
static char g_dc[256];
static char g_osver[64];
static char g_osconfig[64];
static char g_userdn[512];
static char g_profile[512];

static char* wtoa(const wchar_t* w)
{
    int n;
    char* out;
    if (!w) return NULL;
    n = KERNEL32$WideCharToMultiByte(CP_UTF8, 0, w, -1, NULL, 0, NULL, NULL);
    if (n <= 0) return NULL;
    out = (char*)MSVCRT$calloc((size_t)n, 1);
    if (!out) return NULL;
    KERNEL32$WideCharToMultiByte(CP_UTF8, 0, w, -1, out, n, NULL, NULL);
    return out;
}

static void FormatDmtf(BSTR b, char* out, int cap)
{
    const wchar_t* s = b;
    int year, mon, day, hr, mn, sec, h12;
    const char* ap;
    if (s == NULL || s[0] == L'\0' || s[13] == L'\0') { out[0] = '\0'; return; }
    year = (s[0]-L'0')*1000 + (s[1]-L'0')*100 + (s[2]-L'0')*10 + (s[3]-L'0');
    mon  = (s[4]-L'0')*10 + (s[5]-L'0');
    day  = (s[6]-L'0')*10 + (s[7]-L'0');
    hr   = (s[8]-L'0')*10 + (s[9]-L'0');
    mn   = (s[10]-L'0')*10 + (s[11]-L'0');
    sec  = (s[12]-L'0')*10 + (s[13]-L'0');
    ap   = (hr >= 12) ? "PM" : "AM";
    h12  = hr % 12;
    if (h12 == 0) h12 = 12;
    MSVCRT$sprintf(out, "%d/%d/%d at %d:%02d:%02d %s", mon, day, year, h12, mn, sec, ap);
}

static BOOL GetStr(IWbemClassObject* obj, const wchar_t* name, char** out)
{
    VARIANT v;
    HRESULT hr;
    *out = NULL;
    OLEAUT32$VariantInit(&v);
    hr = obj->Get(name, 0, &v, NULL, NULL);
    if (SUCCEEDED(hr) && v.vt == VT_BSTR && v.bstrVal) *out = wtoa(v.bstrVal);
    OLEAUT32$VariantClear(&v);
    return (*out != NULL);
}

static BOOL GetBool(IWbemClassObject* obj, const wchar_t* name, BOOL* out)
{
    VARIANT v;
    HRESULT hr;
    *out = FALSE;
    OLEAUT32$VariantInit(&v);
    hr = obj->Get(name, 0, &v, NULL, NULL);
    if (SUCCEEDED(hr) && v.vt == VT_BOOL) *out = (v.boolVal == VARIANT_TRUE);
    OLEAUT32$VariantClear(&v);
    return TRUE;
}

static void GetDateTimeStr(IWbemClassObject* obj, const wchar_t* name, char* out, int cap)
{
    VARIANT v;
    HRESULT hr;
    out[0] = '\0';
    OLEAUT32$VariantInit(&v);
    hr = obj->Get(name, 0, &v, NULL, NULL);
    if (SUCCEEDED(hr) && v.vt == VT_BSTR) FormatDmtf(v.bstrVal, out, cap);
    OLEAUT32$VariantClear(&v);
}

/* ---- WMI helpers ---- */
static HRESULT WmiExecQuery(IWbemServices* psvc, const wchar_t* query, IEnumWbemClassObject** out)
{
    BSTR lang = OLEAUT32$SysAllocString(L"WQL");
    BSTR q    = OLEAUT32$SysAllocString(query);
    HRESULT hr;
    if (!lang || !q) {
        if (lang) OLEAUT32$SysFreeString(lang);
        if (q)    OLEAUT32$SysFreeString(q);
        return E_OUTOFMEMORY;
    }
    hr = psvc->ExecQuery(lang, q, WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, NULL, out);
    OLEAUT32$SysFreeString(lang);
    OLEAUT32$SysFreeString(q);
    return hr;
}

static IWbemServices* ConnectNamespace(const wchar_t* ns)
{
    IWbemLocator* ploc = NULL;
    IWbemServices* psvc = NULL;
    HRESULT hr;

    wchar_t* Iwbmstr = (wchar_t*)L"{dc12a687-737f-11cf-884d-00aa004b2e24}";
    wchar_t* Cwbmstr = (wchar_t*)L"{4590f811-1d3a-11d0-891f-00aa004b2e24}";
    IID  Iwbm;
    CLSID Cwbm;
    OLE32$CLSIDFromString(Cwbmstr, &Cwbm);
    OLE32$IIDFromString(Iwbmstr, &Iwbm);

    hr = OLE32$CoCreateInstance(Cwbm, 0, CLSCTX_INPROC_SERVER, Iwbm, (LPVOID*)&ploc);
    if (FAILED(hr) || !ploc) return NULL;

    {
        BSTR bns = OLEAUT32$SysAllocString(ns);
        if (bns) {
            hr = ploc->ConnectServer(bns, NULL, NULL, 0, WBEM_FLAG_CONNECT_USE_MAX_WAIT, 0, 0, &psvc);
            OLEAUT32$SysFreeString(bns);
        } else hr = E_OUTOFMEMORY;
    }
    if (FAILED(hr) || !psvc) { ploc->Release(); return NULL; }

    OLE32$CoSetProxyBlanket(psvc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL,
                            RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE);
    ploc->Release();
    return psvc;
}

static IWbemClassObject* GetFirstObject(IWbemServices* psvc, const wchar_t* query)
{
    IEnumWbemClassObject* en = NULL;
    IWbemClassObject* obj = NULL;
    ULONG count = 0;
    if (FAILED(WmiExecQuery(psvc, query, &en)) || !en) return NULL;
    if (en->Next(WBEM_INFINITE, 1, &obj, &count) != S_OK || count != 1) { en->Release(); return NULL; }
    en->Release();
    return obj;
}

/* ---- header gathering ---- */
static void GatherHeader(void)
{
    DWORD n;
    g_computer[0] = g_domain[0] = g_netbios[0] = g_dc[0] = g_osver[0] = g_osconfig[0] = g_userdn[0] = g_profile[0] = '\0';

    n = sizeof(g_computer);
    KERNEL32$GetComputerNameExA(ComputerNameDnsHostname, g_computer, &n);
    n = sizeof(g_domain);
    KERNEL32$GetComputerNameExA(ComputerNameDnsDomain, g_domain, &n);

    PDOMAIN_CONTROLLER_INFOA pdc = NULL;
    if (NETAPI32$DsGetDcNameA(NULL, NULL, NULL, NULL, DS_RETURN_FLAT_NAME, &pdc) == ERROR_SUCCESS && pdc) {
        const char* name = pdc->DomainControllerName;
        if (name && name[0] == '\\' && name[1] == '\\') name += 2;
        int i = 0;
        for (; name && name[i] && i < (int)sizeof(g_dc) - 1; i++) g_dc[i] = name[i];
        g_dc[i] = '\0';
        const char* nb = pdc->DomainName;
        i = 0;
        for (; nb && nb[i] && i < (int)sizeof(g_netbios) - 1; i++) g_netbios[i] = nb[i];
        g_netbios[i] = '\0';
        NETAPI32$NetApiBufferFree(pdc);
    }

    {
        typedef LONG (WINAPI *pRtlGetVersion)(PRTL_OSVERSIONINFOW);
        HMODULE hNtdll = KERNEL32$LoadLibraryA("ntdll.dll");
        if (hNtdll) {
            pRtlGetVersion fn = (pRtlGetVersion)KERNEL32$GetProcAddress(hNtdll, "RtlGetVersion");
            if (fn) {
                RTL_OSVERSIONINFOW vi = {0};
                vi.dwOSVersionInfoSize = sizeof(vi);
                if (fn(&vi) == 0)
                    MSVCRT$sprintf(g_osver, "%lu.%lu.%lu", vi.dwMajorVersion, vi.dwMinorVersion, vi.dwBuildNumber);
            }
        }
    }

    {
        HKEY hKey = NULL;
        DWORD type = 0, size = sizeof(g_osconfig);
        if (ADVAPI32$RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\ProductOptions", 0, KEY_QUERY_VALUE, &hKey) == ERROR_SUCCESS) {
            if (ADVAPI32$RegQueryValueExA(hKey, "ProductType", NULL, &type, (LPBYTE)g_osconfig, &size) == ERROR_SUCCESS)
                g_osconfig[size] = '\0';
            ADVAPI32$RegCloseKey(hKey);
        }
    }

    {
        ULONG n2 = sizeof(g_userdn);
        SECUR32$GetUserNameExA(NameFullyQualifiedDN, g_userdn, &n2);
    }

    {
        DWORD r = KERNEL32$ExpandEnvironmentStringsA("%USERPROFILE%", g_profile, sizeof(g_profile));
        if (r == 0 || r > sizeof(g_profile)) g_profile[0] = '\0';
    }
}

static const char* OsConfigFriendly(void)
{
    if (g_osconfig[0] == '\0') return "N/A";
    if (g_osconfig[0]=='W' && g_osconfig[1]=='i' && g_osconfig[2]=='n' && g_osconfig[3]=='N' && g_osconfig[4]=='T')
        return "Member Workstation";
    if (g_osconfig[0]=='L' && g_osconfig[1]=='a' && g_osconfig[2]=='n' && g_osconfig[3]=='m' && g_osconfig[4]=='a' && g_osconfig[5]=='n' && g_osconfig[6]=='N' && g_osconfig[7]=='T')
        return "Domain Controller";
    return "Member Server";
}

/* ---- RSoP WMI reporting (authoritative, needs elevated token) ---- */
static BOOL DoRsopWmi(const wchar_t* ns, const char* title, BOOL isUser)
{
    IWbemServices* psvc = ConnectNamespace(ns);
    if (!psvc) return FALSE;

    IWbemClassObject* session = GetFirstObject(psvc, L"SELECT * FROM RSOP_Session");
    if (!session) { psvc->Release(); return FALSE; }

    char* target = NULL;
    char  lastApplied[64];
    GetStr(session, L"targetName", &target);
    GetDateTimeStr(session, L"creationTime", lastApplied, sizeof(lastApplied));

    bprintf("\n%s\n", title);
    bprintf("--------------\n");
    if (target) {
        bprintf("    %s\n", target);
        MSVCRT$free(target);
    }
    bprintf("    Last time Group Policy was applied: %s\n", lastApplied[0] ? lastApplied : "N/A");
    bprintf("    Group Policy was applied from:      %s\n", g_dc[0] ? g_dc : "N/A");
    bprintf("    Group Policy slow link threshold:   500 kbps\n");
    bprintf("    Domain Name:                        %s\n", g_netbios[0] ? g_netbios : "N/A");
    bprintf("    Domain Type:                        Windows 2008 or later\n");

    /* Applied GPOs */
    bprintf("\n    Applied Group Policy Objects\n");
    bprintf("    -----------------------------\n");
    {
        IEnumWbemClassObject* en = NULL;
        IWbemClassObject* obj = NULL;
        ULONG count = 0;
        int   applied = 0;
        if (SUCCEEDED(WmiExecQuery(psvc, L"SELECT * FROM RSOP_GPO", &en)) && en) {
            while (en->Next(WBEM_INFINITE, 1, &obj, &count) == S_OK && count == 1) {
                char* name = NULL;
                BOOL  enabled = TRUE, filterAllowed = TRUE, accessDenied = FALSE;
                GetBool(obj, L"enabled", &enabled);
                GetBool(obj, L"filterAllowed", &filterAllowed);
                GetBool(obj, L"accessDenied", &accessDenied);
                GetStr(obj, L"name", &name);
                if (enabled && filterAllowed && !accessDenied) {
                    bprintf("        %s\n", name ? name : "(unnamed)");
                    applied++;
                }
                if (name) MSVCRT$free(name);
                obj->Release();
                obj = NULL;
            }
            en->Release();
        }
        if (applied == 0)
            bprintf("        Local Group Policy\n");
    }

    /* Filtered GPOs */
    bprintf("\n    The following GPOs were not applied because they were filtered out\n");
    bprintf("    ------------------------------------------------------------------\n");
    {
        IEnumWbemClassObject* en = NULL;
        IWbemClassObject* obj = NULL;
        ULONG count = 0;
        int   filtered = 0;
        if (SUCCEEDED(WmiExecQuery(psvc, L"SELECT * FROM RSOP_GPO", &en)) && en) {
            while (en->Next(WBEM_INFINITE, 1, &obj, &count) == S_OK && count == 1) {
                char* name = NULL;
                BOOL  enabled = TRUE, filterAllowed = TRUE, accessDenied = FALSE;
                GetBool(obj, L"enabled", &enabled);
                GetBool(obj, L"filterAllowed", &filterAllowed);
                GetBool(obj, L"accessDenied", &accessDenied);
                GetStr(obj, L"name", &name);
                if (!enabled || !filterAllowed || accessDenied) {
                    bprintf("        %s%s%s%s\n", name ? name : "(unnamed)",
                            !enabled ? " (disabled)" : "",
                            !filterAllowed ? " (filter not allowed)" : "",
                            accessDenied ? " (access denied)" : "");
                    filtered++;
                }
                if (name) MSVCRT$free(name);
                obj->Release();
                obj = NULL;
            }
            en->Release();
        }
        if (filtered == 0)
            bprintf("        (none)\n");
    }

    /* Security groups */
    if (isUser) {
        bprintf("\n    The user is a part of the following security groups\n");
        bprintf("    ---------------------------------------------------\n");
        VARIANT v;
        OLEAUT32$VariantInit(&v);
        if (SUCCEEDED(session->Get(L"SecurityGroups", 0, &v, NULL, NULL))
            && (v.vt & VT_ARRAY) && (v.vt & VT_BSTR) && v.parray) {
            SAFEARRAY* sa = v.parray;
            LONG lb = 0, ub = 0;
            OLEAUT32$SafeArrayGetLBound(sa, 1, &lb);
            OLEAUT32$SafeArrayGetUBound(sa, 1, &ub);
            for (LONG i = lb; i <= ub; i++) {
                BSTR sidStr = NULL;
                if (SUCCEEDED(OLEAUT32$SafeArrayGetElement(sa, &i, &sidStr)) && sidStr) {
                    char* sidN = wtoa(sidStr);
                    if (sidN) {
                        PSID psid = NULL;
                        char name[256], dom[256];
                        DWORD nsz = sizeof(name), dsz = sizeof(dom);
                        SID_NAME_USE use;
                        BOOL ok = FALSE;
                        if (ADVAPI32$ConvertStringSidToSidA(sidN, &psid)) {
                            ok = ADVAPI32$LookupAccountSidA(NULL, psid, name, &nsz, dom, &dsz, &use);
                            if (ok) bprintf("        %s%s%s\n", dom[0] ? dom : "", dom[0] ? "\\" : "", name);
                            KERNEL32$LocalFree(psid);
                        }
                        if (!ok) bprintf("        %s\n", sidN);
                        MSVCRT$free(sidN);
                    }
                }
            }
        } else {
            bprintf("        (unavailable)\n");
        }
        OLEAUT32$VariantClear(&v);
    } else {
        bprintf("\n    The computer is a part of the following security groups\n");
        bprintf("    --------------------------------------------------------\n");
        VARIANT v;
        OLEAUT32$VariantInit(&v);
        if (SUCCEEDED(session->Get(L"SecurityGroups", 0, &v, NULL, NULL))
            && (v.vt & VT_ARRAY) && (v.vt & VT_BSTR) && v.parray) {
            SAFEARRAY* sa = v.parray;
            LONG lb = 0, ub = 0;
            OLEAUT32$SafeArrayGetLBound(sa, 1, &lb);
            OLEAUT32$SafeArrayGetUBound(sa, 1, &ub);
            for (LONG i = lb; i <= ub; i++) {
                BSTR sidStr = NULL;
                if (SUCCEEDED(OLEAUT32$SafeArrayGetElement(sa, &i, &sidStr)) && sidStr) {
                    char* sidN = wtoa(sidStr);
                    if (sidN) {
                        PSID psid = NULL;
                        char name[256], dom[256];
                        DWORD nsz = sizeof(name), dsz = sizeof(dom);
                        SID_NAME_USE use;
                        BOOL ok = FALSE;
                        if (ADVAPI32$ConvertStringSidToSidA(sidN, &psid)) {
                            ok = ADVAPI32$LookupAccountSidA(NULL, psid, name, &nsz, dom, &dsz, &use);
                            if (ok) bprintf("        %s%s%s\n", dom[0] ? dom : "", dom[0] ? "\\" : "", name);
                            KERNEL32$LocalFree(psid);
                        }
                        if (!ok) bprintf("        %s\n", sidN);
                        MSVCRT$free(sidN);
                    }
                }
            }
        } else {
            bprintf("        (unavailable)\n");
        }
        OLEAUT32$VariantClear(&v);
    }

    session->Release();
    psvc->Release();
    return TRUE;
}

/* ---- registry + token fallback (medium integrity) ---- */
static void PrintGpoHistory(HKEY hRoot, const char* subkeyPath)
{
    HKEY hKey = NULL;
    if (ADVAPI32$RegOpenKeyExA(hRoot, subkeyPath, 0, KEY_READ, &hKey) != ERROR_SUCCESS) return;
    DWORD idx = 0;
    while (1) {
        char guid[128];
        DWORD guidSize = sizeof(guid);
        if (ADVAPI32$RegEnumKeyExA(hKey, idx++, guid, &guidSize, NULL, NULL, NULL, NULL) != ERROR_SUCCESS) break;
        char full[256];
        MSVCRT$sprintf(full, "%s\\%s", subkeyPath, guid);
        HKEY hGpo = NULL;
        if (ADVAPI32$RegOpenKeyExA(hRoot, full, 0, KEY_READ, &hGpo) == ERROR_SUCCESS) {
            char name[512];
            DWORD nameSize = sizeof(name);
            DWORD type = 0;
            if (ADVAPI32$RegQueryValueExA(hGpo, "DisplayName", NULL, &type, (LPBYTE)name, &nameSize) == ERROR_SUCCESS && nameSize > 1)
                bprintf("        %s\n", name);
            ADVAPI32$RegCloseKey(hGpo);
        }
    }
    ADVAPI32$RegCloseKey(hKey);
}

static void PrintTokenGroups(void)
{
    HANDLE hToken = NULL;
    if (!ADVAPI32$OpenProcessToken(KERNEL32$GetCurrentProcess(), TOKEN_QUERY, &hToken)) return;
    DWORD need = 0;
    ADVAPI32$GetTokenInformation(hToken, TokenGroups, NULL, 0, &need);
    if (need == 0) { KERNEL32$CloseHandle(hToken); return; }
    TOKEN_GROUPS* groups = (TOKEN_GROUPS*)MSVCRT$calloc(need, 1);
    if (!groups) { KERNEL32$CloseHandle(hToken); return; }
    if (!ADVAPI32$GetTokenInformation(hToken, TokenGroups, groups, need, &need)) {
        MSVCRT$free(groups); KERNEL32$CloseHandle(hToken); return;
    }
    for (DWORD i = 0; i < groups->GroupCount; i++) {
        PSID sid = groups->Groups[i].Sid;
        char name[256], dom[256];
        DWORD nsz = sizeof(name), dsz = sizeof(dom);
        SID_NAME_USE use;
        if (ADVAPI32$LookupAccountSidA(NULL, sid, name, &nsz, dom, &dsz, &use))
            bprintf("        %s%s%s\n", dom[0] ? dom : "", dom[0] ? "\\" : "", name);
        else {
            LPSTR sidStr = NULL;
            if (ADVAPI32$ConvertSidToStringSidA(sid, &sidStr)) {
                bprintf("        %s\n", sidStr);
                KERNEL32$LocalFree(sidStr);
            }
        }
    }
    MSVCRT$free(groups);
    KERNEL32$CloseHandle(hToken);
}

static void DoUserFallback(void)
{
    bprintf("\nUSER SETTINGS\n--------------\n");
    bprintf("    %s\n", g_userdn[0] ? g_userdn : "N/A");
    bprintf("    Last time Group Policy was applied: N/A\n");
    bprintf("    Group Policy was applied from:      %s\n", g_dc[0] ? g_dc : "N/A");
    bprintf("    Group Policy slow link threshold:   500 kbps\n");
    bprintf("    Domain Name:                        %s\n", g_netbios[0] ? g_netbios : "N/A");
    bprintf("    Domain Type:                        Windows 2008 or later\n");
    bprintf("\n    Applied Group Policy Objects\n    -----------------------------\n");
    bprintf("        Local Group Policy\n");
    PrintGpoHistory(HKEY_CURRENT_USER, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Group Policy\\History");
    bprintf("\n    The user is a part of the following security groups\n    ---------------------------------------------------\n");
    PrintTokenGroups();
}

static void DoComputerFallback(void)
{
    bprintf("\nCOMPUTER SETTINGS\n------------------\n");
    bprintf("    %s\n", g_computer[0] ? g_computer : "N/A");
    bprintf("    Last time Group Policy was applied: N/A\n");
    bprintf("    Group Policy was applied from:      %s\n", g_dc[0] ? g_dc : "N/A");
    bprintf("    Group Policy slow link threshold:   500 kbps\n");
    bprintf("    Domain Name:                        %s\n", g_netbios[0] ? g_netbios : "N/A");
    bprintf("    Domain Type:                        Windows 2008 or later\n");
    bprintf("\n    Applied Group Policy Objects\n    -----------------------------\n");
    bprintf("        Local Group Policy\n");
    PrintGpoHistory(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Group Policy\\History");
}

/* ---- entrypoint ---- */
void go(char* buff, int len)
{
    datap parser;
    int   mode;

    g_out    = (char*)MSVCRT$calloc(OUTBUFSIZE, 1);
    g_outLen = 0;
    if (g_out) g_out[0] = '\0';

    BeaconDataParse(&parser, buff, len);
    mode = BeaconDataInt(&parser);

    HRESULT hr = OLE32$CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    if (FAILED(hr)) {
        bprintf("[!] CoInitializeEx failed: 0x%08x\n", (unsigned)hr);
        goto done;
    }
    OLE32$CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
                               RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE, NULL);

    GatherHeader();

    bprintf("=== Group Policy Result ===\n");
    bprintf("RSOP data for %s on %s : Logging Mode\n",
            g_userdn[0] ? g_userdn : "?", g_computer[0] ? g_computer : "?");
    bprintf("-------------------------------------------------------\n\n");
    bprintf("OS Configuration:            %s\n", OsConfigFriendly());
    bprintf("OS Version:                  %s\n", g_osver[0] ? g_osver : "N/A");
    bprintf("Site Name:                   N/A\n");
    bprintf("Roaming Profile:             N/A\n");
    bprintf("Local Profile:               %s\n", g_profile[0] ? g_profile : "N/A");
    bprintf("Connected over a slow link?: No\n");

    if (mode == 0 || mode == 1) {
        if (!DoRsopWmi(L"root\\rsop\\user", "USER SETTINGS", TRUE))
            DoUserFallback();
    }
    if (mode == 0 || mode == 2) {
        if (!DoRsopWmi(L"root\\rsop\\computer", "COMPUTER SETTINGS", FALSE))
            DoComputerFallback();
    }

    bprintf("\n[*] Done.\n");

    OLE32$CoUninitialize();

done:
    bflush();
    if (g_out && g_out != (char*)1)
        MSVCRT$free(g_out);
    g_out    = (char*)1;
    g_outLen = 1;
}
