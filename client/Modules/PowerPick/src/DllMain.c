/**
 * KaynLdr
 * Author: Paul Ungur (@C5pider)
 */

#include <KaynLdr.h>
#include <stdio.h>
#include <InvokeAssembly.h>

HINSTANCE   hAppInstance = NULL;
INSTANCE    Instance     = { 0 };

BOOL WINAPI DllMain( HINSTANCE hInstDLL, DWORD dwReason, LPVOID lpReserved )
{
    BOOL bReturnValue = TRUE;

    switch( dwReason )
    {
        case DLL_QUERY_HMODULE:
            if( lpReserved != NULL )
                *( HMODULE* ) lpReserved = hAppInstance;
            break;

		case DLL_PROCESS_ATTACH:
		{
			hAppInstance = hInstDLL;

            ModuleInit();
            ModuleMain( lpReserved );

			fflush( stdout );
			ExitProcess( 0 );
		}

        case DLL_PROCESS_DETACH:
        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
            break;
    }
    return bReturnValue;
}

VOID ModuleInit()
{
    Instance.Modules.Msvcrt = LoadLibraryA( "Msvcrt" );
    if ( Instance.Modules.Msvcrt )
    {
        Instance.Win32.printf = (void*)GetProcAddress( Instance.Modules.Msvcrt, "printf" );
    }

    Instance.Modules.Mscoree = LoadLibraryA( "Mscoree" );
    if ( Instance.Modules.Msvcrt )
    {
        Instance.Win32.CLRCreateInstance = (void*)GetProcAddress( Instance.Modules.Mscoree, "CLRCreateInstance" );
    }
}

VOID ModuleMain( PVOID Params )
{
    HANDLE hOrigStdout = GetStdHandle( STD_OUTPUT_HANDLE );
    HANDLE hOrigStderr = GetStdHandle( STD_ERROR_HANDLE );
    HANDLE hPipeRead   = NULL;
    HANDLE hPipeWrite  = NULL;

    SECURITY_ATTRIBUTES sa = { sizeof( SECURITY_ATTRIBUTES ), NULL, TRUE };

    if ( CreatePipe( &hPipeRead, &hPipeWrite, &sa, 0 ) )
    {
        SetStdHandle( STD_OUTPUT_HANDLE, hPipeWrite );
        SetStdHandle( STD_ERROR_HANDLE,  hPipeWrite );
    }

    PARSER Parser = { 0 };
    ParserNew( &Parser, Params );
    InvokeAssembly( &Parser );

    if ( hPipeRead )
    {
        CloseHandle( hPipeWrite );

        UCHAR buf[ 1024 ];
        DWORD dwRead    = 0;
        DWORD dwWritten = 0;

        while ( ReadFile( hPipeRead, buf, sizeof( buf ), &dwRead, NULL ) && dwRead > 0 )
        {
            WriteFile( hOrigStdout, buf, dwRead, &dwWritten, NULL );
            dwRead = 0;
        }

        CloseHandle( hPipeRead );
    }

    SetStdHandle( STD_OUTPUT_HANDLE, hOrigStdout );
    SetStdHandle( STD_ERROR_HANDLE,  hOrigStderr );
}