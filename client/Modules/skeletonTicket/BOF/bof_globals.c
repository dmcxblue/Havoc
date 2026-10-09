/*
 * bof_globals.c — strong definitions for tentative header globals that would
 * otherwise become SHN_COMMON symbols (which BOF loaders handle poorly).
 * MIMIKATZ_NT_* / logfile / outputBuffer are already owned by bof_output.c.
 */
#include "kull_m_crypto.h"
#include "kull_m_crypto_system.h"
