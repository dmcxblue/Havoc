/* beacon.h - COFF BOF (Beacon Object File) API declarations.
 *
 * Havoc's CoffeeLdr resolves __imp_BeaconFUNCNAME against its BeaconApi[]
 * table (it hashes the name after stripping "__imp_"), so every Beacon API
 * function MUST be declared __declspec(dllimport) — a bare extern produces a
 * bare `BeaconOutput` symbol the loader cannot resolve ("Symbol not found").
 *
 * The formatp (datap) struct must match Havoc's ObjectApi.h exactly: 4 fields
 * {original, buffer, length, size}. BeaconDataParse writes ALL of them, so a
 * smaller struct corrupts the caller's stack.
 */
#ifndef BD_BEACON_H
#define BD_BEACON_H

#include <windows.h>

/* output types (match Havoc payloads/Demon/include/core/ObjectApi.h) */
#define CALLBACK_OUTPUT      0x0
#define CALLBACK_OUTPUT_OEM  0x1e
#define CALLBACK_OUTPUT_UTF8 0x20
#define CALLBACK_ERROR       0x0d

/* layout MUST match Havoc's `datap` */
typedef struct formatp {
    char *original;  /* the original buffer [so we can free it] */
    char *buffer;    /* current pointer into our buffer */
    int   length;    /* remaining length of data */
    int   size;      /* total size of this buffer */
} formatp;

__declspec(dllimport) void   BeaconDataParse(formatp *format, char *buffer, int size);
__declspec(dllimport) int    BeaconDataInt(formatp *format);
__declspec(dllimport) short  BeaconDataShort(formatp *format);
__declspec(dllimport) int    BeaconDataLength(formatp *format);
__declspec(dllimport) char  *BeaconDataExtract(formatp *format, int *size);

__declspec(dllimport) char  *BeaconGetSpawnTo(BOOL x86, char *buffer, int length);

__declspec(dllimport) void   BeaconPrintf(int type, char *fmt, ...);
__declspec(dllimport) void   BeaconOutput(int type, char *data, int len);

#endif /* BD_BEACON_H */
