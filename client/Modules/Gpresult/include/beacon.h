/*
 * Beacon Object File (BOF) API — Havoc-compatible subset.
 *
 * Mirrors the WmiSubscriptions include/beacon.h. This module links against
 * the same DFR symbols (BeaconDataParse / BeaconOutput) that the Havoc demon
 * provides to inline-executed BOFs.
 */

/* data API */
typedef struct {
	char * original;
	char * buffer;
	int    length;
	int    size;
} datap;

DECLSPEC_IMPORT void    BeaconDataParse(datap * parser, char * buffer, int size);
DECLSPEC_IMPORT int     BeaconDataInt(datap * parser);
DECLSPEC_IMPORT char *  BeaconDataExtract(datap * parser, int * size);

/* Output Functions */
#define CALLBACK_OUTPUT      0x0
#define CALLBACK_OUTPUT_OEM  0x1e
#define CALLBACK_ERROR       0x0d
#define CALLBACK_OUTPUT_UTF8 0x20

DECLSPEC_IMPORT void   BeaconPrintf(int type, char * fmt, ...);
DECLSPEC_IMPORT void   BeaconOutput(int type, char * data, int len);
