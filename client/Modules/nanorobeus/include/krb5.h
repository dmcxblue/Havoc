#pragma once

#include "msasn1.h"

// Copyright (c) Microsoft Corporation

#define KRB_KEY_USAGE_AP_REQ_AUTHENTICATOR 11
#define KRB_KEY_USAGE_KRB_CRED_ENCRYPTED_PART 14

#define version_present 0x80
#define ticket_extensions_present 0x80
#define checksum_present 0x80
#define KERB_AUTHENTICATOR_subkey_present 0x40
#define KERB_AUTHENTICATOR_sequence_number_present 0x20
#define KERB_AUTHENTICATOR_authorization_data_present 0x10
#define subject_public_key_present 0x80

#define KERB_ENCRYPTED_DATA_PDU 6
#define KERB_ENCRYPTION_KEY_PDU 7
#define KERB_CHECKSUM_PDU 8
#define KERB_REPLY_KEY_PACKAGE2_PDU 15
#define KERB_TICKET_PDU 28
#define KERB_AUTHENTICATOR_PDU 30
#define KERB_AP_REQUEST_PDU 31
#define KERB_CRED_PDU 36
/* AS-REQ / AS-REP (RFC 4120 KDC-REQ / KDC-REP). New PDUs appended after the
   existing 49 so the table indices stay self-contained. */
#define KERB_PA_DATA_PDU      49
#define KERB_KDC_REQ_BODY_PDU 50
#define KERB_KDC_REQ_PDU      51
#define KERB_KDC_REP_PDU      52
#define KERB_ERROR_PDU        53

#define SIZE_KRB5_Module_PDU_6 sizeof(KERB_ENCRYPTED_DATA)
#define SIZE_KRB5_Module_PDU_7 sizeof(KERB_ENCRYPTION_KEY)
#define SIZE_KRB5_Module_PDU_8 sizeof(KERB_CHECKSUM)
#define SIZE_KRB5_Module_PDU_15 sizeof(KERB_REPLY_KEY_PACKAGE2)
#define SIZE_KRB5_Module_PDU_28 sizeof(KERB_TICKET)
#define SIZE_KRB5_Module_PDU_30 sizeof(KERB_AUTHENTICATOR)
#define SIZE_KRB5_Module_PDU_31 sizeof(KERB_AP_REQUEST)
#define SIZE_KRB5_Module_PDU_36 sizeof(KERB_CRED)
#define SIZE_KRB5_Module_PDU_49 sizeof(KERB_PA_DATA)
#define SIZE_KRB5_Module_PDU_50 sizeof(KERB_KDC_REQ_BODY)
#define SIZE_KRB5_Module_PDU_51 sizeof(KERB_KDC_REQ)
#define SIZE_KRB5_Module_PDU_52 sizeof(KERB_KDC_REP)
#define SIZE_KRB5_Module_PDU_53 sizeof(KERB_ERROR)

typedef LONG KERBERR, *PKERBERR;
#define KDC_ERR_NONE ((KERBERR)0x0)
#define KRB_ERR_GENERIC ((KERBERR)0x3C)
#define KDC_ERR_MORE_DATA ((KERBERR)0x80000001)
#define KERB_SUCCESS(_kerberr_) ((KERBERR)(_kerberr_) == KDC_ERR_NONE)

typedef struct _KERB_GSS_CHECKSUM {
    ULONG BindLength;
    ULONG BindHash[4];
    ULONG GssFlags;
    USHORT Delegation;
    USHORT DelegationLength;
    UCHAR DelegationInfo[ANYSIZE_ARRAY];
} KERB_GSS_CHECKSUM, *PKERB_GSS_CHECKSUM;

typedef ASN1ztcharstring_t KERB_PRINCIPAL_NAME_name_string_Seq;
typedef struct KERB_PRINCIPAL_NAME_name_string_s* PKERB_PRINCIPAL_NAME_name_string;
typedef struct KERB_PRINCIPAL_NAME_name_string_s {
    PKERB_PRINCIPAL_NAME_name_string next;
    KERB_PRINCIPAL_NAME_name_string_Seq value;
} KERB_PRINCIPAL_NAME_name_string_Element, *KERB_PRINCIPAL_NAME_name_string;

typedef struct PKERB_TICKET_EXTENSIONS_s* PPKERB_TICKET_EXTENSIONS;
typedef struct PKERB_TICKET_EXTENSIONS_Seq {
    ASN1int32_t te_type;
    ASN1octetstring_t te_data;
} PKERB_TICKET_EXTENSIONS_Seq;
typedef struct PKERB_TICKET_EXTENSIONS_s {
    PPKERB_TICKET_EXTENSIONS next;
    PKERB_TICKET_EXTENSIONS_Seq value;
} PKERB_TICKET_EXTENSIONS_Element, *PKERB_TICKET_EXTENSIONS;

typedef ASN1bitstring_t KERB_AP_OPTIONS;
typedef ASN1ztcharstring_t KERB_REALM;
typedef ASN1generalizedtime_t KERB_TIME;
typedef ASN1intx_t KERB_SEQUENCE_NUMBER_LARGE;

typedef struct PKERB_AUTHORIZATION_DATA_Seq {
    ASN1int32_t auth_data_type;
    ASN1octetstring_t auth_data;
} PKERB_AUTHORIZATION_DATA_Seq;

typedef struct PKERB_AUTHORIZATION_DATA_s* PPKERB_AUTHORIZATION_DATA;
typedef struct PKERB_AUTHORIZATION_DATA_s {
    PPKERB_AUTHORIZATION_DATA next;
    PKERB_AUTHORIZATION_DATA_Seq value;
} PKERB_AUTHORIZATION_DATA_Element, *PKERB_AUTHORIZATION_DATA;

typedef struct KERB_PRINCIPAL_NAME {
    ASN1int32_t name_type;
    PKERB_PRINCIPAL_NAME_name_string name_string;
} KERB_PRINCIPAL_NAME;

typedef struct KERB_ENCRYPTED_DATA {
    union {
        ASN1uint16_t bit_mask;
        ASN1octet_t o[1];
    };
    ASN1int32_t encryption_type;
    ASN1int32_t version;
    ASN1octetstring_t cipher_text;
} KERB_ENCRYPTED_DATA;

typedef struct KERB_ENCRYPTION_KEY {
    ASN1int32_t keytype;
    ASN1octetstring_t keyvalue;
} KERB_ENCRYPTION_KEY;

typedef struct KERB_CHECKSUM {
    ASN1int32_t checksum_type;
    ASN1octetstring_t checksum;
} KERB_CHECKSUM;

typedef struct KERB_REPLY_KEY_PACKAGE2 {
    union {
        ASN1uint16_t bit_mask;
        ASN1octet_t o[1];
    };
    KERB_ENCRYPTION_KEY reply_key;
    ASN1int32_t nonce;
    ASN1bitstring_t subject_public_key;
} KERB_REPLY_KEY_PACKAGE2;

typedef struct KERB_TICKET {
    union {
        ASN1uint16_t bit_mask;
        ASN1octet_t o[1];
    };
    ASN1int32_t ticket_version;
    KERB_REALM realm;
    KERB_PRINCIPAL_NAME server_name;
    KERB_ENCRYPTED_DATA encrypted_part;
    PPKERB_TICKET_EXTENSIONS ticket_extensions;
} KERB_TICKET;

typedef struct KERB_AUTHENTICATOR {
    union {
        ASN1uint16_t bit_mask;
        ASN1octet_t o[1];
    };
    ASN1int32_t authenticator_version;
    KERB_REALM client_realm;
    KERB_PRINCIPAL_NAME client_name;
    KERB_CHECKSUM checksum;
    ASN1int32_t client_usec;
    KERB_TIME client_time;
    KERB_ENCRYPTION_KEY subkey;
    KERB_SEQUENCE_NUMBER_LARGE sequence_number;
    PPKERB_AUTHORIZATION_DATA authorization_data;
} KERB_AUTHENTICATOR;

typedef struct KERB_AP_REQUEST {
    ASN1int32_t version;
    ASN1int32_t message_type;
    KERB_AP_OPTIONS ap_options;
    KERB_TICKET ticket;
    KERB_ENCRYPTED_DATA authenticator;
} KERB_AP_REQUEST, *PKERB_AP_REQUEST;

typedef struct KERB_CRED_tickets_s* PKERB_CRED_tickets;
typedef struct KERB_CRED_tickets_s {
    PKERB_CRED_tickets next;
    KERB_TICKET value;
} KERB_CRED_tickets_Element, *KERB_CRED_tickets;
typedef struct KERB_CRED {
    ASN1int32_t version;
    ASN1int32_t message_type;
    PKERB_CRED_tickets tickets;
    KERB_ENCRYPTED_DATA encrypted_part;
} KERB_CRED;

/* ---- AS-REQ / AS-REP (RFC 4120) ---- */

/* SEQUENCE OF Int32 (etype list in KDC-REQ-BODY) */
typedef struct PKERB_INT32_list_s* PPKERB_INT32_list;
typedef struct PKERB_INT32_list_s {
    PPKERB_INT32_list next;
    ASN1int32_t value;
} PKERB_INT32_list_Element, *PKERB_INT32_list;

/* PA-DATA ::= SEQUENCE { padata-type [1] Int32, padata-value [2] OCTET STRING } */
typedef struct KERB_PA_DATA {
    ASN1int32_t type;
    ASN1octetstring_t value;
} KERB_PA_DATA;

/* SEQUENCE OF PA-DATA */
typedef struct PKERB_PA_DATA_list_s* PPKERB_PA_DATA_list;
typedef struct PKERB_PA_DATA_list_s {
    PPKERB_PA_DATA_list next;
    KERB_PA_DATA value;
} PKERB_PA_DATA_list_Element, *PKERB_PA_DATA_list;

/* KDC-REQ-BODY. Optional fields use the o[0] bit mask (same pattern as
   KERB_TICKET); bits set in kdc_req_body_present_* define which are encoded. */
#define kdc_req_body_cname_present      0x01
#define kdc_req_body_sname_present      0x02
#define kdc_req_body_from_present       0x04
#define kdc_req_body_rtime_present      0x08
#define kdc_req_body_addresses_present  0x10
#define kdc_req_body_encauthdata_present 0x20
#define kdc_req_body_addtickets_present 0x40

typedef struct KERB_KDC_REQ_BODY {
    union {
        ASN1uint16_t bit_mask;
        ASN1octet_t o[1];
    };
    ASN1bitstring_t kdc_options;
    KERB_PRINCIPAL_NAME cname;      /* [1] optional */
    KERB_REALM realm;
    KERB_PRINCIPAL_NAME sname;      /* [3] optional */
    KERB_TIME from;                 /* [4] optional */
    KERB_TIME till;                 /* [5] */
    KERB_TIME rtime;                /* [6] optional */
    ASN1int32_t nonce;              /* [7] */
    PKERB_INT32_list etype;         /* [8] SEQUENCE OF Int32 */
} KERB_KDC_REQ_BODY;

/* KDC-REQ ::= SEQUENCE { pvno [1], msg-type [2], padata [3] OPT, req-body [4] } */
typedef struct KERB_KDC_REQ {
    ASN1int32_t pvno;               /* 5 */
    ASN1int32_t msg_type;           /* 10 = AS-REQ, 12 = TGS-REQ */
    PKERB_PA_DATA_list padata;      /* [3] optional */
    KERB_KDC_REQ_BODY req_body;     /* [4] */
} KERB_KDC_REQ, *PKERB_KDC_REQ;

/* KDC-REP ::= SEQUENCE { pvno [0], msg-type [1], padata [2] OPT,
   crealm [3], cname [4], ticket [5], enc-part [6] } */
typedef struct KERB_KDC_REP {
    ASN1int32_t pvno;               /* 5 */
    ASN1int32_t msg_type;           /* 11 = AS-REP, 13 = TGS-REP */
    PKERB_PA_DATA_list padata;      /* [2] optional */
    KERB_REALM crealm;              /* [3] */
    KERB_PRINCIPAL_NAME cname;      /* [4] */
    KERB_TICKET ticket;             /* [5] */
    KERB_ENCRYPTED_DATA enc_part;   /* [6] */
} KERB_KDC_REP, *PKERB_KDC_REP;

/* KRB-ERROR ::= [APPLICATION 30] (RFC 4120). Only the fields needed for
   ASREPRoast error reporting are retained; optionals are decoded-and-skipped. */
#define kerb_error_etext_present 0x01

typedef struct KERB_ERROR {
    union {
        ASN1uint16_t bit_mask;
        ASN1octet_t o[1];
    };
    ASN1int32_t pvno;
    ASN1int32_t msg_type;
    ASN1int32_t error_code;
    KERB_REALM realm;               /* [9] */
    KERB_PRINCIPAL_NAME sname;      /* [10] */
    KERB_REALM e_text;              /* [11] optional */
} KERB_ERROR, *PKERB_ERROR;

ASN1module_t ASN1CALL KRB5_Module_Startup(void);
void ASN1CALL KRB5_Module_Cleanup(ASN1module_t module);
KERBERR KerbInitAsn(ASN1module_t module, ASN1encoding_t* pEnc, ASN1decoding_t* pDec);
void KerbTermAsn(ASN1encoding_t pEnc, ASN1decoding_t pDec);
KERBERR NTAPI KerbUnpackData(ASN1module_t module, PUCHAR Data, ULONG DataSize, ULONG PduValue, PVOID* DecodedData);
KERBERR NTAPI KerbPackData(ASN1module_t module, PVOID Data, ULONG PduValue, PULONG DataSize, PUCHAR* EncodedData);
void KerbFreeData(ASN1module_t module, ULONG PduValue, PVOID Data);