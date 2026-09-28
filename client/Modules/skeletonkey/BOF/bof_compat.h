/*
 * bof_compat.h — MSVC-isms that mingw does not provide.
 *
 * mimikatz is written for MSVC. When cross-compiling with mingw we must supply:
 *   1. The legacy SAL1 annotations (double-underscore) used by mimikatz's bundled
 *      Windows SDK headers (inc/wincred.h and friends). mingw only ships SAL2
 *      (single-underscore, trailing underscore) via <sal.h>.
 *
 * Force-include this file with:  -include /path/to/bof_compat.h
 * It must be processed BEFORE mimikatz's inc/wincred.h (included via globals.h).
 */
#ifndef BOF_COMPAT_H
#define BOF_COMPAT_H

/*
 * Neutralize mingw's CRT import macros so all CRT functions become plain
 * external references that WE satisfy in crt_shim.c (no dependency on the BOF
 * loader resolving msvcrt symbols).
 */
#define _CRTIMP
#define _SECIMP

/* MSVC SEH (__try/__except) — a BOF runs in the beacon thread without a
 * registered SEH handler, so mimikatz's __try/__except crash-guards (used to
 * catch ERROR_DLL_NOT_FOUND from delay-loaded bcrypt/ncrypt) are compiled to
 * no-ops: the try body runs normally, the except block becomes dead code. */
#define __try
#define __except(x) if(0)
#define __finally

/* ---- SAL1 parameter annotations (swallowed as empty) ------------------- */
#define __in
#define __in_opt
#define __in_bcount(...)
#define __in_bcount_opt(...)
#define __in_ecount(...)
#define __in_ecount_opt(...)
#define __in_range(...)
#define __in_z
#define __in_z_opt

#define __out
#define __out_opt
#define __out_bcount(...)
#define __out_bcount_full_opt(...)
#define __out_bcount_opt(...)
#define __out_bcount_part(...)
#define __out_bcount_part_opt(...)
#define __out_ecount(...)
#define __out_ecount_opt(...)
#define __out_xcount(...)
#define __out_xcount_opt(...)
#define __out_z

#define __inout
#define __inout_opt
#define __inout_bcount(...)
#define __inout_bcount_opt(...)
#define __inout_ecount(...)
#define __inout_ecount_opt(...)
#define __inout_z

#define __deref
#define __deref_out
#define __deref_out_opt
#define __deref_opt_out
#define __deref_opt_out_opt
#define __deref_opt_out_bcount(...)
#define __deref_out_bcount(...)
#define __deref_out_bcount_full(...)
#define __deref_out_bcount_opt(...)
#define __deref_out_ecount(...)
#define __deref_out_ecount_full_opt(...)
#define __deref_in
#define __deref_in_opt
#define __deref_in_bcount(...)
#define __deref_in_bcount_opt(...)
#define __deref_in_ecount(...)
#define __deref_inout
#define __deref_inout_opt

#define __field_bcount(...)
#define __field_ecount(...)
#define __field_ecount_opt(...)
#define __field_xcount(...)

#define __bcount(...)
#define __ecount(...)
#define __count(...)
#define __xcount(...)
#define __size_is(...)

#define __reserved
#define __notnull
#define __maybenull
#define __nullterminated
#define __readonly
#define __valid
#define __range(...)
#define __success(...)
#define __checkReturn
#define __analysis_noreturn

#endif /* BOF_COMPAT_H */
