#pragma once

#include <windows.h>
#include "common.h"
#include "base64.h"

#define _KerbSubmitTicketMessage 21

/* KERB_CRYPTO_KEY32 / KERB_SUBMIT_TKT_REQUEST are now provided by mingw-w64's
   ntsecapi.h (byte-compatible with the old local definitions). Defining them
   again here collides with ntsecapi.h under modern toolchains. */

void execute_ptt(WCHAR** dispatch, HANDLE hToken, char* ticket, LUID luid, BOOL currentLuid);