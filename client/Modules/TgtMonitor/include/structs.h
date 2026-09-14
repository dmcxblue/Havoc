#pragma once

// Kerberos ASN.1 structs
typedef struct AsnElt {
    unsigned char* objBuf;
    int objBufSize;
    int objOff;
    int objLen;
    int valOff;
    int valLen;
    int hasEncodedHeader;
    int tagClass;
    int tagValue;
    struct AsnElt* sub;
    int subCount;
} AsnElt;

typedef struct {
    BOOL isSet;
    int year;
    int month;
    int day;
    int hour;
    int minute;
    int second;
    int millisecond;
} DateTime;

typedef struct _Checksum {
    int   cksumtype;
    int   checksum_length;
    unsigned char* checksum;
} Checksum;

typedef struct _HostAddress {
    long  addr_type;
    char* addr_string;
} HostAddress;

typedef struct _EncryptedData {
    int          etype;
    unsigned int kvno;
    unsigned int cipher_size;
    unsigned char*        cipher;
} EncryptedData;

typedef struct _PrincipalName {
    long         name_type;
    unsigned int name_count;
    char**       name_string;
} PrincipalName;

typedef struct _Ticket {
    int           tkt_vno;
    char*         realm;
    PrincipalName sname;
    EncryptedData enc_part;
} Ticket;

typedef struct _EncryptionKey {
    int   key_type;
    unsigned int  key_size;
    unsigned char* key_value;
} EncryptionKey;

typedef struct _KDCReqBody {
    unsigned int          kdc_options;
    PrincipalName cname;
    PrincipalName sname;
    char*         realm;
    unsigned int          till;
    unsigned int          rtime;
    unsigned int          nonce;
    unsigned int          addresses_count;
    HostAddress*  addresses;
    unsigned int          additional_tickets_count;
    Ticket*       additional_tickets;
    unsigned int          etypes_count;
    int*          etypes;
    EncryptedData enc_authorization_data;
} KDCReqBody;

typedef struct _KERB_PA_PAC_REQUEST {
    BOOL include_pac;
} KERB_PA_PAC_REQUEST;

typedef struct _PA_PAC_OPTIONS {
    unsigned char kerberosFlags[4];
} PA_PAC_OPTIONS;

typedef struct _ETYPE_INFO2_ENTRY {
    int   etype;
    char* salt;
} ETYPE_INFO2_ENTRY;

typedef struct _PA_DATA {
    unsigned int  type;
    void* value;
} PA_DATA;

typedef struct _LastReq {
    int      lr_type;
    DateTime lr_value;
} LastReq;

typedef struct _EncryptedPAData {
    int           keytype;
    int           keysize;
    unsigned char*         keyvalue;
    EncryptionKey encryptionKey;
} EncryptedPAData;

typedef struct _EncKDCRepPart {
    EncryptionKey   key;
    LastReq         lastReq;
    unsigned int            nonce;
    DateTime        key_expiration;
    unsigned int            flags;
    DateTime        authtime;
    DateTime        starttime;
    DateTime        endtime;
    DateTime        renew_till;
    char*           realm;
    PrincipalName   sname;
    EncryptedPAData encryptedPaData;
} EncKDCRepPart;

typedef struct _KrbCredInfo {
    EncryptionKey key;
    char*         prealm;
    PrincipalName pname;
    unsigned int          flags;
    DateTime      authtime;
    DateTime      starttime;
    DateTime      endtime;
    DateTime      renew_till;
    char*         srealm;
    PrincipalName sname;
} KrbCredInfo;

typedef struct _EncKrbCredPart {
    unsigned int         ticket_count;
    KrbCredInfo* ticket_info;
} EncKrbCredPart;

typedef struct _KRB_CRED {
    long           pvno;
    long           msg_type;
    unsigned int           ticket_count;
    Ticket*        tickets;
    EncKrbCredPart enc_part;
} KRB_CRED;

typedef struct _Authenticator {
    long          authenticator_vno;
    char*         crealm;
    Checksum      cksum;
    PrincipalName cname;
    long          cusec;
    DateTime      ctime;
    EncryptionKey subkey;
    unsigned int          seq_number;
} Authenticator;

typedef struct _AS_REQ {
    long       pvno;
    long       msg_type;
    unsigned int       pa_data_count;
    PA_DATA*   pa_data;
    KDCReqBody req_body;
} AS_REQ;

typedef struct _AP_REQ {
    long          pvno;
    long          msg_type;
    unsigned int          ap_options;
    Ticket        ticket;
    Authenticator authenticator;
    EncryptionKey key;
    int           keyUsage;
} AP_REQ;

typedef struct _TGS_REP {
    long          pvno;
    long          msg_type;
    PA_DATA       padata;
    char*         crealm;
    PrincipalName cname;
    Ticket        ticket;
    EncryptedData enc_part;
} TGS_REP;

// CRYPTDLL typedefs
typedef CONST UNICODE_STRING* PCUNICODE_STRING;

typedef NTSTATUS(WINAPI* PKERB_ECRYPT_INITIALIZE)(LPCVOID pbKey, ULONG KeySize, ULONG MessageType, PVOID* pContext);
typedef NTSTATUS(WINAPI* PKERB_ECRYPT_ENCRYPT)(PVOID pContext, LPCVOID pbInput, ULONG cbInput, PVOID pbOutput, ULONG* cbOutput);
typedef NTSTATUS(WINAPI* PKERB_ECRYPT_DECRYPT)(PVOID pContext, LPCVOID pbInput, ULONG cbInput, PVOID pbOutput, ULONG* cbOutput);
typedef NTSTATUS(WINAPI* PKERB_ECRYPT_FINISH)(PVOID* pContext);
typedef NTSTATUS(WINAPI* PKERB_ECRYPT_HASHPASSWORD_NT5)(PCUNICODE_STRING Password, PVOID pbKey);
typedef NTSTATUS(WINAPI* PKERB_ECRYPT_HASHPASSWORD_NT6)(PCUNICODE_STRING Password, PCUNICODE_STRING Salt, ULONG Count, PVOID pbKey);
typedef NTSTATUS(WINAPI* PKERB_ECRYPT_RANDOMKEY)(LPCVOID Seed, ULONG SeedLength, PVOID pbKey);
typedef NTSTATUS(WINAPI* PKERB_ECRYPT_CONTROL)(ULONG Function, PVOID pContext, PUCHAR InputBuffer, ULONG InputBufferSize);

typedef struct _KERB_ECRYPT {
    ULONG EncryptionType;
    ULONG BlockSize;
    ULONG ExportableEncryptionType;
    ULONG KeySize;
    ULONG HeaderSize;
    ULONG PreferredCheckSum;
    ULONG Attributes;
    PCWSTR Name;
    PKERB_ECRYPT_INITIALIZE Initialize;
    PKERB_ECRYPT_ENCRYPT Encrypt;
    PKERB_ECRYPT_DECRYPT Decrypt;
    PKERB_ECRYPT_FINISH Finish;
    union {
        PKERB_ECRYPT_HASHPASSWORD_NT5 HashPassword_NT5;
        PKERB_ECRYPT_HASHPASSWORD_NT6 HashPassword_NT6;
    };
    PKERB_ECRYPT_RANDOMKEY RandomKey;
    PKERB_ECRYPT_CONTROL Control;
    PVOID unk0_null;
    PVOID unk1_null;
    PVOID unk2_null;
} KERB_ECRYPT, *PKERB_ECRYPT;

typedef NTSTATUS(WINAPI* pCDLocateCSystem)(ULONG Type, PKERB_ECRYPT* ppCSystem);

#ifndef KerbSubmitTicketMessage
#define KerbSubmitTicketMessage 21
#endif

// Enums
enum TICKET_FLAGS {
    reserved         = 2147483648,
    forwardable      = 0x40000000,
    forwarded        = 0x20000000,
    proxiable        = 0x10000000,
    proxy            = 0x08000000,
    may_postdate     = 0x04000000,
    postdated        = 0x02000000,
    invalid          = 0x01000000,
    renewable        = 0x00800000,
    initial          = 0x00400000,
    pre_authent      = 0x00200000,
    hw_authent       = 0x00100000,
    ok_as_delegate   = 0x00040000,
    anonymous        = 0x00020000,
    name_canonicalize= 0x00010000,
    enc_pa_rep       = 0x00010000,
    reserved1        = 0x00000001,
};

enum KERB_ETYPE {
    des_cbc_crc                  = 1,
    des_cbc_md4                  = 2,
    des_cbc_md5                  = 3,
    des3_cbc_md5                 = 5,
    des3_cbc_sha1                = 7,
    dsaWithSHA1_CmsOID           = 9,
    md5WithRSAEncryption_CmsOID  = 10,
    sha1WithRSAEncryption_CmsOID = 11,
    rc2CBC_EnvOID                = 12,
    rsaEncryption_EnvOID         = 13,
    rsaES_OAEP_ENV_OID           = 14,
    des_ede3_cbc_Env_OID         = 15,
    des3_cbc_sha1_kd             = 16,
    aes128_cts_hmac_sha1         = 17,
    aes256_cts_hmac_sha1         = 18,
    rc4_hmac                     = 23,
    rc4_hmac_exp                 = 24,
    subkey_keymaterial           = 65,
    old_exp                      = -135,
};

enum KRB_KEY_USAGE {
    KRB_KEY_USAGE_AS_REQ_PA_ENC_TIMESTAMP         = 1,
    KRB_KEY_USAGE_AS_REP_TGS_REP                  = 2,
    KRB_KEY_USAGE_AS_REP_EP_SESSION_KEY            = 3,
    KRB_KEY_USAGE_TGS_REQ_ENC_AUTHOIRZATION_DATA  = 4,
    KRB_KEY_USAGE_TGS_REQ_PA_AUTHENTICATOR         = 7,
    KRB_KEY_USAGE_TGS_REP_EP_SESSION_KEY           = 8,
    KRB_KEY_USAGE_AP_REQ_AUTHENTICATOR             = 11,
    KRB_KEY_USAGE_KRB_PRIV_ENCRYPTED_PART          = 13,
    KRB_KEY_USAGE_KRB_CRED_ENCRYPTED_PART          = 14,
    KRB_KEY_USAGE_KRB_NON_KERB_SALT                = 16,
    KRB_KEY_USAGE_KRB_NON_KERB_CKSUM_SALT          = 17,
    KRB_KEY_USAGE_PA_S4U_X509_USER                 = 26,
};


enum KERB_MESSAGE_TYPE {
    KERB_AS_REQ   = 10,
    KERB_AS_REP   = 11,
    KERB_TGS_REQ  = 12,
    KERB_TGS_REP  = 13,
    KERB_AP_REQ   = 14,
    KERB_AP_REP   = 15,
    KERB_TGT_REQ  = 16,
    KERB_TGT_REP  = 17,
    KERB_SAFE     = 20,
    KERB_PRIV     = 21,
    KERB_CRED_MSG = 22,
    KERB_ERROR    = 30,
};

enum PADATA_TYPE {
    PADATA_NONE                     = 0,
    PADATA_TGS_REQ                  = 1,
    PADATA_AP_REQ                   = 1,
    PADATA_ENC_TIMESTAMP            = 2,
    PADATA_PW_SALT                  = 3,
    PADATA_ENC_UNIX_TIME            = 5,
    PADATA_SANDIA_SECUREID          = 6,
    PADATA_SESAME                   = 7,
    PADATA_OSF_DCE                  = 8,
    PADATA_CYBERSAFE_SECUREID       = 9,
    PADATA_AFS3_SALT                = 10,
    PADATA_ETYPE_INFO               = 11,
    PADATA_SAM_CHALLENGE            = 12,
    PADATA_SAM_RESPONSE             = 13,
    PADATA_PK_AS_REQ_19             = 14,
    PADATA_PK_AS_REP_19             = 15,
    PADATA_PK_AS_REQ_WIN            = 15,
    PADATA_PK_AS_REQ                = 16,
    PADATA_PK_AS_REP                = 17,
    PADATA_PA_PK_OCSP_RESPONSE      = 18,
    PADATA_ETYPE_INFO2              = 19,
    PADATA_USE_SPECIFIED_KVNO       = 20,
    PADATA_SVR_REFERRAL_INFO        = 20,
    PADATA_SAM_REDIRECT             = 21,
    PADATA_GET_FROM_TYPED_DATA      = 22,
    PADATA_SAM_ETYPE_INFO           = 23,
    PADATA_SERVER_REFERRAL          = 25,
    PADATA_TD_KRB_PRINCIPAL         = 102,
    PADATA_PK_TD_TRUSTED_CERTIFIERS = 104,
    PADATA_PK_TD_CERTIFICATE_INDEX  = 105,
    PADATA_TD_APP_DEFINED_ERROR     = 106,
    PADATA_TD_REQ_NONCE             = 107,
    PADATA_TD_REQ_SEQ               = 108,
    PADATA_PA_PAC_REQUEST           = 128,
    PADATA_S4U2SELF                 = 129,
    PADATA_PA_S4U_X509_USER         = 130,
    PADATA_PA_PAC_OPTIONS           = 167,
    PADATA_PK_AS_09_BINDING         = 132,
    PADATA_CLIENT_CANONICALIZED     = 133,
    PADATA_KEY_LIST_REQ             = 161,
    PADATA_KEY_LIST_REP             = 162,
};

enum KdcOptions {
    VALIDATE               = 0x00000001,
    RENEW                  = 0x00000002,
    UNUSED29               = 0x00000004,
    ENCTKTINSKEY           = 0x00000008,
    RENEWABLEOK            = 0x00000010,
    DISABLETRANSITEDCHECK  = 0x00000020,
    UNUSED16               = 0x0000FFC0,
    CONSTRAINED_DELEGATION = 0x00020000,
    CANONICALIZE           = 0x00010000,
    CNAMEINADDLTKT         = 0x00004000,
    OK_AS_DELEGATE         = 0x00040000,
    REQUEST_ANONYMOUS      = 0x00008000,
    UNUSED12               = 0x00080000,
    OPTHARDWAREAUTH        = 0x00100000,
    PREAUTHENT             = 0x00200000,
    INITIAL                = 0x00400000,
    RENEWABLE              = 0x00800000,
    UNUSED7                = 0x01000000,
    POSTDATED              = 0x02000000,
    ALLOWPOSTDATE          = 0x04000000,
    PROXY                  = 0x08000000,
    PROXIABLE              = 0x10000000,
    FORWARDED              = 0x20000000,
    FORWARDABLE            = 0x40000000,
    RESERVED               = 0x80000000,
};

enum PRINCIPAL_TYPE {
    PRINCIPAL_NT_UNKNOWN        = 0,
    PRINCIPAL_NT_PRINCIPAL      = 1,
    PRINCIPAL_NT_SRV_INST       = 2,
    PRINCIPAL_NT_SRV_HST        = 3,
    PRINCIPAL_NT_SRV_XHST       = 4,
    PRINCIPAL_NT_UID            = 5,
    PRINCIPAL_NT_X500_PRINCIPAL = 6,
    PRINCIPAL_NT_SMTP_NAME      = 7,
    PRINCIPAL_NT_ENTERPRISE     = 10,
};

enum ASN_TYPES {
    ASN_UNIVERSAL       = 0,
    ASN_BOOLEAN         = 1,
    ASN_APPLICATION     = 1,
    ASN_CONTEXT         = 2,
    ASN_INTEGER         = 2,
    ASN_BIT_STRING      = 3,
    ASN_OCTET_STRING    = 4,
    ASN_UTF8String      = 12,
    ASN_SEQUENCE        = 16,
    ASN_NumericString   = 18,
    ASN_PrintableString = 19,
    ASN_TeletexString   = 20,
    ASN_IA5String       = 22,
    ASN_UTCTime         = 23,
    ASN_GeneralizedTime = 24,
    ASN_GeneralString   = 27,
    ASN_UniversalString = 28,
    ASN_BMPString       = 30,
    ASN_LIST            = 0xa0,
};
