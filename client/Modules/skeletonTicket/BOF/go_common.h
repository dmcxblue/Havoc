/*
 * go_common.h — shared helpers for the BOF go() entries.
 */
#ifndef GO_COMMON_H
#define GO_COMMON_H

#include "bofdefs.h"

/* Convert a UTF-8 arg blob into a wide argv[] (mimics CommandLineToArgvW:
 * space/tab separated, double-quote grouping). Returns NULL on failure. */
wchar_t** bof_argv_from_utf8(const char* utf8, int len, int* argc_out);
void      bof_argv_free(wchar_t** argv);

/* Set MIMIKATZ_NT_* from ntdll (needed before sekurlsa/lsadump logic). */
void      bof_get_nt_version(void);

#endif /* GO_COMMON_H */
