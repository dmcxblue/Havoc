/*
 * bofdefs.h — BOF foundation: Beacon API + the few non-<windows.h> imports.
 *
 * Conventions (matching how Cobalt Strike / COFFLoader BOFs work):
 *   - Win32 APIs are already declared by <windows.h> with dllimport; the loader
 *     resolves them by name — we do NOT redeclare them.
 *   - Standard CRT symbols (memcpy, memset, strlen, sprintf, malloc, ...) are
 *     emitted as plain references and resolved by the loader from msvcrt.
 *   - We only declare the msvcrt printf variants we use directly, so the
 *     compiler emits the correct __imp_* references.
 */
#ifndef BOFDEFS_H
#define BOFDEFS_H

#include <windows.h>
#include "beacon.h"

#ifndef DECLSPEC_IMPORT
#define DECLSPEC_IMPORT __declspec(dllimport)
#endif
#ifndef DECLSPEC_EXPORT
#define DECLSPEC_EXPORT __declspec(dllexport)
#endif

/* ------------------------------------------------------------------ */
/* MSVCRT printf-family — provided by crt_shim.c as PLAIN externs      */
/* (not dllimport), so we never depend on the loader resolving msvcrt. */
/* ------------------------------------------------------------------ */
int __cdecl _vsnprintf(char* buffer, size_t n, const char* format, va_list argptr);
int __cdecl _snprintf(char* buffer, size_t n, const char* format, ...);
int __cdecl _vsnwprintf(wchar_t* buffer, size_t n, const wchar_t* format, va_list argptr);
int __cdecl _vscwprintf(const wchar_t* format, va_list argptr);

/* ------------------------------------------------------------------ */
/* formatted output through Beacon                                     */
/* ------------------------------------------------------------------ */
#define internal_printf(...)  do { char _b[0x2000]; int _n = _snprintf(_b, sizeof(_b), __VA_ARGS__); \
                                   if (_n > 0) { if ((size_t)_n >= sizeof(_b)) _n = (int)sizeof(_b) - 1; \
                                   BeaconOutput(CALLBACK_OUTPUT, _b, _n); } } while(0)

#endif /* BOFDEFS_H */
