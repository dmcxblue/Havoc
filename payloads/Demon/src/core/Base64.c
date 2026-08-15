#include <Demon.h>
#include <core/Base64.h>
#include <core/MiniStd.h>

static const CHAR B64Table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static const CHAR B64UrlTable[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

static PCHAR B64EncodeInternal( PBYTE Data, SIZE_T DataLen, PSIZE_T OutLen, const CHAR* Table, BOOL Pad )
{
    SIZE_T EncLen = 0;
    PCHAR  Output = NULL;
    SIZE_T i      = 0;
    SIZE_T j      = 0;

    if ( Pad )
        EncLen = 4 * ( ( DataLen + 2 ) / 3 );
    else
        EncLen = 4 * ( DataLen / 3 ) + ( DataLen % 3 == 0 ? 0 : DataLen % 3 + 1 );

    Output = Instance->Win32.LocalAlloc( LPTR, EncLen + 1 );
    if ( ! Output )
        return NULL;

    for ( i = 0, j = 0; i < DataLen; )
    {
        UINT32 a = i < DataLen ? Data[ i++ ] : 0;
        UINT32 b = i < DataLen ? Data[ i++ ] : 0;
        UINT32 c = i < DataLen ? Data[ i++ ] : 0;

        UINT32 triple = ( a << 16 ) | ( b << 8 ) | c;

        Output[ j++ ] = Table[ ( triple >> 18 ) & 0x3F ];
        Output[ j++ ] = Table[ ( triple >> 12 ) & 0x3F ];
        Output[ j++ ] = Table[ ( triple >> 6  ) & 0x3F ];
        Output[ j++ ] = Table[   triple         & 0x3F ];
    }

    if ( Pad )
    {
        SIZE_T mod = DataLen % 3;
        if ( mod == 1 )
        {
            Output[ EncLen - 1 ] = '=';
            Output[ EncLen - 2 ] = '=';
        }
        else if ( mod == 2 )
        {
            Output[ EncLen - 1 ] = '=';
        }
    }
    else
    {
        j = EncLen;
    }

    Output[ EncLen ] = '\0';

    if ( OutLen )
        *OutLen = EncLen;

    return Output;
}

static BYTE B64DecodeChar( CHAR c, BOOL UrlSafe )
{
    if ( c >= 'A' && c <= 'Z' ) return c - 'A';
    if ( c >= 'a' && c <= 'z' ) return c - 'a' + 26;
    if ( c >= '0' && c <= '9' ) return c - '0' + 52;
    if ( UrlSafe )
    {
        if ( c == '-' ) return 62;
        if ( c == '_' ) return 63;
    }
    else
    {
        if ( c == '+' ) return 62;
        if ( c == '/' ) return 63;
    }
    return 0;
}

static PBYTE B64DecodeInternal( PCHAR Encoded, SIZE_T EncodedLen, PSIZE_T OutLen, BOOL UrlSafe )
{
    SIZE_T DecLen = 0;
    PBYTE  Output = NULL;
    SIZE_T i      = 0;
    SIZE_T j      = 0;
    SIZE_T Pad    = 0;

    if ( EncodedLen == 0 )
        return NULL;

    // strip padding
    while ( EncodedLen > 0 && Encoded[ EncodedLen - 1 ] == '=' )
    {
        Pad++;
        EncodedLen--;
    }

    DecLen = ( EncodedLen * 3 ) / 4;

    Output = Instance->Win32.LocalAlloc( LPTR, DecLen + 1 );
    if ( ! Output )
        return NULL;

    for ( i = 0, j = 0; i < EncodedLen; )
    {
        UINT32 a = i < EncodedLen ? B64DecodeChar( Encoded[ i++ ], UrlSafe ) : 0;
        UINT32 b = i < EncodedLen ? B64DecodeChar( Encoded[ i++ ], UrlSafe ) : 0;
        UINT32 c = i < EncodedLen ? B64DecodeChar( Encoded[ i++ ], UrlSafe ) : 0;
        UINT32 d = i < EncodedLen ? B64DecodeChar( Encoded[ i++ ], UrlSafe ) : 0;

        UINT32 triple = ( a << 18 ) | ( b << 12 ) | ( c << 6 ) | d;

        if ( j < DecLen ) Output[ j++ ] = ( triple >> 16 ) & 0xFF;
        if ( j < DecLen ) Output[ j++ ] = ( triple >> 8  ) & 0xFF;
        if ( j < DecLen ) Output[ j++ ] =   triple         & 0xFF;
    }

    if ( OutLen )
        *OutLen = j;

    return Output;
}

PCHAR Base64Encode( PBYTE Data, SIZE_T DataLen, PSIZE_T OutLen )
{
    return B64EncodeInternal( Data, DataLen, OutLen, B64Table, TRUE );
}

PBYTE Base64Decode( PCHAR Encoded, SIZE_T EncodedLen, PSIZE_T OutLen )
{
    return B64DecodeInternal( Encoded, EncodedLen, OutLen, FALSE );
}

PCHAR Base64UrlEncode( PBYTE Data, SIZE_T DataLen, PSIZE_T OutLen )
{
    return B64EncodeInternal( Data, DataLen, OutLen, B64UrlTable, FALSE );
}

PBYTE Base64UrlDecode( PCHAR Encoded, SIZE_T EncodedLen, PSIZE_T OutLen )
{
    return B64DecodeInternal( Encoded, EncodedLen, OutLen, TRUE );
}
