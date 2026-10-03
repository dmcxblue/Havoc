/*
 * dump_asreq.c — deterministic harness for the asreproast BOF.
 *
 * Compiles WITHOUT -DBOF (so bofdefs.h maps to the real CRT/Win32 names) and
 * links against -lwldap32 / -lnetapi32 / -lws2_32. Its only job is to emit the
 * exact AS-REQ bytes that build_asreq() produces, as hex on stdout, so the
 * wire format can be diffed against impacket's canonical encoder on the Linux
 * side. No network, no Windows — runs fine under wine.
 *
 * Build (from the module dir):
 *   x86_64-w64-mingw32-gcc tools/dump_asreq.c -o tools/dump_asreq.exe \
 *       -I include -w -lwldap32 -lnetapi32 -lws2_32
 * Run:
 *   wine tools/dump_asreq.exe 'user' 'CORP.LOCAL'
 */
#include <windows.h>
#include <ntsecapi.h>
#include <stdio.h>
#include <stdlib.h>

/* beacon.h defines datap / CALLBACK_OUTPUT only under -DBOF, and this harness
   deliberately compiles WITHOUT -DBOF so bofdefs.h maps to the real CRT names.
   Include it anyway so entry.c's glue sees the same definitions it would
   in-tree, then supply the couple of BOF-only names it expects. */
#include "beacon.h"

#ifndef BOF
typedef struct {
    char* original;
    char* buffer;
    int   length;
    int   size;
} datap;

#define CALLBACK_OUTPUT      0x0
#define CALLBACK_OUTPUT_UTF8 0x20
#endif

/* bofdefs.h (with -DBOF) declares every runtime call as __declspec(dllimport)
   under its Beacon-style name MSVCRT$memcpy etc. Off-implant those import
   pointers don't exist, so bind each one to the real CRT/Win32 function. */
void* __imp_MSVCRT$strlen    = (void*)strlen;
void* __imp_MSVCRT$calloc    = (void*)calloc;
void* __imp_MSVCRT$free      = (void*)free;
void* __imp_MSVCRT$memcpy    = (void*)memcpy;
void* __imp_MSVCRT$memset    = (void*)memset;
void* __imp_MSVCRT$vsnprintf = (void*)vsnprintf;
void* __imp_KERNEL32$GetTickCount = (void*)GetTickCount;

void* __imp_WS2_32$WSAStartup  = (void*)WSAStartup;
void* __imp_WS2_32$WSACleanup  = (void*)WSACleanup;
void* __imp_WS2_32$socket      = (void*)socket;
void* __imp_WS2_32$connect     = (void*)connect;
void* __imp_WS2_32$send        = (void*)send;
void* __imp_WS2_32$recv        = (void*)recv;
void* __imp_WS2_32$closesocket = (void*)closesocket;

/* Not declared by this mingw's winldap.h/winnt.h -> resolve at runtime. */
static void ho_bind(void** slot, const char* dll, const char* fn)
{
    HMODULE h = LoadLibraryA(dll);
    *slot = h ? (void*)GetProcAddress(h, fn) : NULL;
}

void* __imp_WLDAP32$ldap_init         = NULL;
void* __imp_WLDAP32$ldap_set_option   = NULL;
void* __imp_WLDAP32$ldap_bind_s       = NULL;
void* __imp_WLDAP32$ldap_search_s     = NULL;
void* __imp_WLDAP32$ldap_first_entry  = NULL;
void* __imp_WLDAP32$ldap_next_entry   = NULL;
void* __imp_WLDAP32$ldap_get_values   = NULL;
void* __imp_WLDAP32$ldap_value_free   = NULL;
void* __imp_WLDAP32$ldap_msgfree      = NULL;
void* __imp_WLDAP32$ldap_unbind       = NULL;

void* __imp_NETAPI32$DsGetDcNameA     = NULL;
void* __imp_NETAPI32$NetApiBufferFree = NULL;

static void bind_imports(void)
{
    ho_bind(&__imp_WLDAP32$ldap_init,        "wldap32.dll", "ldap_init");
    ho_bind(&__imp_WLDAP32$ldap_set_option,  "wldap32.dll", "ldap_set_option");
    ho_bind(&__imp_WLDAP32$ldap_bind_s,      "wldap32.dll", "ldap_bind_s");
    ho_bind(&__imp_WLDAP32$ldap_search_s,    "wldap32.dll", "ldap_search_s");
    ho_bind(&__imp_WLDAP32$ldap_first_entry, "wldap32.dll", "ldap_first_entry");
    ho_bind(&__imp_WLDAP32$ldap_next_entry,  "wldap32.dll", "ldap_next_entry");
    ho_bind(&__imp_WLDAP32$ldap_get_values,  "wldap32.dll", "ldap_get_values");
    ho_bind(&__imp_WLDAP32$ldap_value_free,  "wldap32.dll", "ldap_value_free");
    ho_bind(&__imp_WLDAP32$ldap_msgfree,     "wldap32.dll", "ldap_msgfree");
    ho_bind(&__imp_WLDAP32$ldap_unbind,      "wldap32.dll", "ldap_unbind");
    ho_bind(&__imp_NETAPI32$DsGetDcNameA,     "netapi32.dll", "DsGetDcNameA");
    ho_bind(&__imp_NETAPI32$NetApiBufferFree, "netapi32.dll", "NetApiBufferFree");
}

/* Beacon runtime stubs: compiled with -DBOF so bofdefs.h declares the real
   Win32 imports, but the Beacon API itself is unavailable off-implant. */
void BeaconOutput(int type, char* data, int len)
{
    (void)type;
    if (data && len > 0) fwrite(data, 1, (size_t)len, stderr);
}
void BeaconDataParse(datap* parser, char* buffer, int size)
{
    (void)parser; (void)buffer; (void)size;
}
char* BeaconDataExtract(datap* parser, int* size)
{
    (void)parser;
    if (size) *size = 0;
    return NULL;
}

/* Pull in the REAL encoder under test. */
#define main asreproast_unused_main
#include "../src/entry.c"
#undef main

int main(int argc, char* argv[])
{
    const char* user  = (argc >= 2) ? argv[1] : "user";
    const char* realm = (argc >= 3) ? argv[2] : "CORP.LOCAL";

    BYTE* out = NULL;
    int   len = 0;
    bind_imports();
    if (!build_asreq(user, realm, &out, &len)) {
        fprintf(stderr, "build_asreq failed\n");
        return 1;
    }
    for (int i = 0; i < len; i++) printf("%02x", out[i]);
    printf("\n");
    free(out);
    return 0;
}
