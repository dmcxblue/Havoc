#ifndef DEMON_BASE64_H
#define DEMON_BASE64_H

#include <windows.h>

// Standard base64 encode. Caller frees with LocalFree.
PCHAR Base64Encode( PBYTE Data, SIZE_T DataLen, PSIZE_T OutLen );

// Standard base64 decode. Caller frees with LocalFree.
PBYTE Base64Decode( PCHAR Encoded, SIZE_T EncodedLen, PSIZE_T OutLen );

// URL-safe base64 encode (no padding). Caller frees with LocalFree.
PCHAR Base64UrlEncode( PBYTE Data, SIZE_T DataLen, PSIZE_T OutLen );

// URL-safe base64 decode. Caller frees with LocalFree.
PBYTE Base64UrlDecode( PCHAR Encoded, SIZE_T EncodedLen, PSIZE_T OutLen );

#endif
