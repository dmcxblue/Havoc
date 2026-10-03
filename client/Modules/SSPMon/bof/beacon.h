/*
 * beacon.h — Cobalt Strike Beacon API declarations (BOF entry).
 * These symbols are resolved by the BOF loader at runtime.
 */
#ifndef BEACON_H
#define BEACON_H

#include <windows.h>

/* callback types */
#define CALLBACK_OUTPUT      0x0
#define CALLBACK_OUTPUT_OEM  0x1e
#define CALLBACK_OUTPUT_UTF8 0x20
#define CALLBACK_ERROR       0x0d

/* argument parser (BeaconData*) */
typedef struct {
    char* original; /* the original buffer */
    char* buffer;   /* current pointer into the buffer */
    int   length;   /* remaining bytes */
    int   size;     /* total size of the buffer */
} datap;

DECLSPEC_IMPORT void   BeaconDataParse(datap* parser, char* buffer, int size);
DECLSPEC_IMPORT char*  BeaconDataPtr(datap* parser, int size);
DECLSPEC_IMPORT int    BeaconDataInt(datap* parser);
DECLSPEC_IMPORT short  BeaconDataShort(datap* parser);
DECLSPEC_IMPORT int    BeaconDataLength(datap* parser);
DECLSPEC_IMPORT char*  BeaconDataExtract(datap* parser, int* size);

/* output */
DECLSPEC_IMPORT void   BeaconPrintf(int type, char* fmt, ...);
DECLSPEC_IMPORT void   BeaconOutput(int type, char* data, int len);

/* token impersonation (needed for dcsync in a privileged token) */
DECLSPEC_IMPORT void   BeaconUseToken(HANDLE token);
DECLSPEC_IMPORT void   BeaconRevertToken(void);
DECLSPEC_IMPORT void   BeaconIsAdmin(void);

/* process spawning / injection */
DECLSPEC_IMPORT BOOL   BeaconSpawnTemporaryProcess(BOOL x86, BOOL ignoreToken,
                                                  STARTUPINFO* si, PROCESS_INFORMATION* pi);
DECLSPEC_IMPORT void   BeaconInjectProcess(HANDLE hProc, int pid, char* payload, int p_len,
                                           int p_offset, char* arg, int a_len);
DECLSPEC_IMPORT void   BeaconInjectTemporaryProcess(PROCESS_INFORMATION* pInfo, char* payload,
                                                    int p_len, int p_offset, char* arg, int a_len);
DECLSPEC_IMPORT void   BeaconCleanupProcess(PROCESS_INFORMATION* pInfo);
DECLSPEC_IMPORT void   BeaconGetSpawnTo(BOOL x86, char* buffer, int length);

/* key/value store */
DECLSPEC_IMPORT void   BeaconAddValue(const char* key, char* value);
DECLSPEC_IMPORT void   BeaconRemoveValue(const char* key);

#endif /* BEACON_H */
