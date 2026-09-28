/*
 * stubs.c — stub functions skeletonkey pulls in transitively but never calls
 * (minidump path of kull_m_memory.c; skeletonkey uses live process memory only).
 */
#include "kull_m_minidump.h"

BOOL kull_m_minidump_open(HANDLE hFile, PKULL_M_MINIDUMP_HANDLE *hMinidump) { (void)hFile; (void)hMinidump; return FALSE; }
BOOL kull_m_minidump_close(PKULL_M_MINIDUMP_HANDLE hMinidump) { (void)hMinidump; return FALSE; }
BOOL kull_m_minidump_copy(PKULL_M_MINIDUMP_HANDLE hMinidump, VOID *Destination, VOID *Source, SIZE_T Length) { (void)hMinidump; (void)Destination; (void)Source; (void)Length; return FALSE; }
LPVOID kull_m_minidump_RVAtoPTR(PKULL_M_MINIDUMP_HANDLE hMinidump, RVA64 rva) { (void)hMinidump; (void)rva; return NULL; }
LPVOID kull_m_minidump_stream(PKULL_M_MINIDUMP_HANDLE hMinidump, MINIDUMP_STREAM_TYPE type, DWORD *pSize) { (void)hMinidump; (void)type; (void)pSize; return NULL; }
LPVOID kull_m_minidump_remapVirtualMemory64(PKULL_M_MINIDUMP_HANDLE hMinidump, VOID *Source, SIZE_T Length) { (void)hMinidump; (void)Source; (void)Length; return NULL; }
