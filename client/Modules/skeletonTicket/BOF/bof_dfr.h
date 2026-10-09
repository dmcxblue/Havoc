/*
 * bof_dfr.h — Dynamic Function Resolution shim for the mimikatz BOF.
 *
 * Havoc's CoffeeLdr resolves imports of the form __imp_LIB$FUNC via
 * LoadLibrary("LIB")+GetProcAddress. Unqualified __imp_FUNC only resolves
 * against a 7-entry built-in table (LocalAlloc/LocalFree/LoadLibraryA/
 * GetModuleHandle/GetProcAddress/FreeLibrary/toWideChar); bare non-__imp_
 * externs do not resolve at all.
 *
 * We fix that by pre-aliasing every Win32/Nt/Crypt/Rpc/Ldap symbol used by
 * mimikatz to its LIB$FUNC form BEFORE any SDK header runs. The SDK then
 * declares the qualified name and the compiler emits __imp_LIB$FUNC when
 * the original declaration was dllimport.
 *
 * For a set of ntdll/advapi32/netapi32 symbols that mimikatz's own headers
 * (or mingw's ntsecapi.h) declare without dllimport, we also publish
 * DECLSPEC_IMPORT prototypes of the qualified name with unspecified args:
 * this establishes the dllimport attribute on the identifier first, and a
 * later specific-arg declaration is compatible and inherits the attribute.
 * Force-include this file AFTER bof_compat.h and before any SDK include.
 */
#ifndef BOF_DFR_H
#define BOF_DFR_H

/* ============ KERNEL32 ============ */
#define CloseHandle                          KERNEL32$CloseHandle
#define ConnectNamedPipe                     KERNEL32$ConnectNamedPipe
#define CreateFileMappingW                   KERNEL32$CreateFileMappingW
#define CreateFileW                          KERNEL32$CreateFileW
#define CreateNamedPipeW                     KERNEL32$CreateNamedPipeW
#define CreateProcessW                       KERNEL32$CreateProcessW
#define CreateRemoteThread                   KERNEL32$CreateRemoteThread
#define DeviceIoControl                      KERNEL32$DeviceIoControl
#define DisconnectNamedPipe                  KERNEL32$DisconnectNamedPipe
#define DuplicateHandle                      KERNEL32$DuplicateHandle
#define ExpandEnvironmentStringsW            KERNEL32$ExpandEnvironmentStringsW
#define FileTimeToLocalFileTime              KERNEL32$FileTimeToLocalFileTime
#define FileTimeToSystemTime                 KERNEL32$FileTimeToSystemTime
#define FindClose                            KERNEL32$FindClose
#define FindFirstFileW                       KERNEL32$FindFirstFileW
#define FindNextFileW                        KERNEL32$FindNextFileW
#define FlushFileBuffers                     KERNEL32$FlushFileBuffers
#define GetComputerNameExW                   KERNEL32$GetComputerNameExW
#define GetCurrentDirectoryW                 KERNEL32$GetCurrentDirectoryW
#define GetCurrentProcess                    KERNEL32$GetCurrentProcess
#define GetDateFormatW                       KERNEL32$GetDateFormatW
#define GetFileAttributesW                   KERNEL32$GetFileAttributesW
#define GetFileSizeEx                        KERNEL32$GetFileSizeEx
#define GetLastError                         KERNEL32$GetLastError
#define GetModuleHandleA                     KERNEL32$GetModuleHandleA
#define LoadLibraryA                         KERNEL32$LoadLibraryA
#define GetProcAddress                       KERNEL32$GetProcAddress
#define FreeLibrary                          KERNEL32$FreeLibrary
#define LocalAlloc                           KERNEL32$LocalAlloc
#define LocalFree                            KERNEL32$LocalFree
#define GetNamedPipeInfo                     KERNEL32$GetNamedPipeInfo
#define GetProcessId                         KERNEL32$GetProcessId
#define GetSystemTimeAsFileTime              KERNEL32$GetSystemTimeAsFileTime
#define GetTimeFormatW                       KERNEL32$GetTimeFormatW
#define IsTextUnicode                        ADVAPI32$IsTextUnicode
#define MapViewOfFile                        KERNEL32$MapViewOfFile
#define MultiByteToWideChar                  KERNEL32$MultiByteToWideChar
#define OpenProcess                          KERNEL32$OpenProcess
#define ReadFile                             KERNEL32$ReadFile
#define ReadProcessMemory                    KERNEL32$ReadProcessMemory
#define SetFilePointer                       KERNEL32$SetFilePointer
#define SetFilePointerEx                     KERNEL32$SetFilePointerEx
#define SetLastError                         KERNEL32$SetLastError
#define SetNamedPipeHandleState              KERNEL32$SetNamedPipeHandleState
#define SystemTimeToFileTime                 KERNEL32$SystemTimeToFileTime
#define UnmapViewOfFile                      KERNEL32$UnmapViewOfFile
#define VirtualAlloc                         KERNEL32$VirtualAlloc
#define VirtualAllocEx                       KERNEL32$VirtualAllocEx
#define VirtualFree                          KERNEL32$VirtualFree
#define VirtualFreeEx                        KERNEL32$VirtualFreeEx
#define VirtualProtect                       KERNEL32$VirtualProtect
#define VirtualProtectEx                     KERNEL32$VirtualProtectEx
#define VirtualQuery                         KERNEL32$VirtualQuery
#define VirtualQueryEx                       KERNEL32$VirtualQueryEx
#define WaitForSingleObject                  KERNEL32$WaitForSingleObject
#define WaitNamedPipeW                       KERNEL32$WaitNamedPipeW
#define WideCharToMultiByte                  KERNEL32$WideCharToMultiByte
#define WriteFile                            KERNEL32$WriteFile
#define WriteProcessMemory                   KERNEL32$WriteProcessMemory
#define lstrlenA                             KERNEL32$lstrlenA
#define lstrlenW                             KERNEL32$lstrlenW

/* ============ ADVAPI32 ============ */
#define AdjustTokenPrivileges                ADVAPI32$AdjustTokenPrivileges
#define AllocateAndInitializeSid             ADVAPI32$AllocateAndInitializeSid
#define BuildSecurityDescriptorW             ADVAPI32$BuildSecurityDescriptorW
#define CheckTokenMembership                 ADVAPI32$CheckTokenMembership
#define CloseServiceHandle                   ADVAPI32$CloseServiceHandle
#define ControlService                       ADVAPI32$ControlService
#define ConvertSidToStringSidW               ADVAPI32$ConvertSidToStringSidW
#define ConvertStringSidToSidW               ADVAPI32$ConvertStringSidToSidW
#define CopySid                              ADVAPI32$CopySid
#define CreateProcessAsUserW                 ADVAPI32$CreateProcessAsUserW
#define CreateProcessWithLogonW              ADVAPI32$CreateProcessWithLogonW
#define CreateServiceW                       ADVAPI32$CreateServiceW
#define CreateWellKnownSid                   ADVAPI32$CreateWellKnownSid
#define CredIsMarshaledCredentialW           ADVAPI32$CredIsMarshaledCredentialW
#define CredUnmarshalCredentialW             ADVAPI32$CredUnmarshalCredentialW
#define CredFree                             ADVAPI32$CredFree
#define CryptAcquireContextA                 ADVAPI32$CryptAcquireContextA
#define CryptAcquireContextW                 ADVAPI32$CryptAcquireContextW
#define CryptCreateHash                      ADVAPI32$CryptCreateHash
#define CryptDecrypt                         ADVAPI32$CryptDecrypt
#define CryptDestroyHash                     ADVAPI32$CryptDestroyHash
#define CryptDestroyKey                      ADVAPI32$CryptDestroyKey
#define CryptDuplicateKey                    ADVAPI32$CryptDuplicateKey
#define CryptEncrypt                         ADVAPI32$CryptEncrypt
#define CryptExportKey                       ADVAPI32$CryptExportKey
#define CryptGenKey                          ADVAPI32$CryptGenKey
#define CryptGetHashParam                    ADVAPI32$CryptGetHashParam
#define CryptGetKeyParam                     ADVAPI32$CryptGetKeyParam
#define CryptGetProvParam                    ADVAPI32$CryptGetProvParam
#define CryptHashData                        ADVAPI32$CryptHashData
#define CryptImportKey                       ADVAPI32$CryptImportKey
#define CryptReleaseContext                  ADVAPI32$CryptReleaseContext
#define CryptSetHashParam                    ADVAPI32$CryptSetHashParam
#define CryptSetKeyParam                     ADVAPI32$CryptSetKeyParam
#define DeleteService                        ADVAPI32$DeleteService
#define DuplicateTokenEx                     ADVAPI32$DuplicateTokenEx
#define FreeSid                              ADVAPI32$FreeSid
#define GetLengthSid                         ADVAPI32$GetLengthSid
#define GetSidSubAuthority                   ADVAPI32$GetSidSubAuthority
#define GetSidSubAuthorityCount              ADVAPI32$GetSidSubAuthorityCount
#define GetTokenInformation                  ADVAPI32$GetTokenInformation
#define IsValidSid                           ADVAPI32$IsValidSid
#define LookupAccountNameW                   ADVAPI32$LookupAccountNameW
#define LookupAccountSidW                    ADVAPI32$LookupAccountSidW
#define LookupPrivilegeValueA                ADVAPI32$LookupPrivilegeValueA
#define OpenProcessToken                     ADVAPI32$OpenProcessToken
#define OpenSCManagerW                       ADVAPI32$OpenSCManagerW
#define OpenServiceW                         ADVAPI32$OpenServiceW
#define QueryServiceObjectSecurity           ADVAPI32$QueryServiceObjectSecurity
#define QueryServiceStatusEx                 ADVAPI32$QueryServiceStatusEx
#define RegCloseKey                          ADVAPI32$RegCloseKey
#define RegEnumKeyExW                        ADVAPI32$RegEnumKeyExW
#define RegEnumValueW                        ADVAPI32$RegEnumValueW
#define RegOpenKeyExW                        ADVAPI32$RegOpenKeyExW
#define RegQueryInfoKeyW                     ADVAPI32$RegQueryInfoKeyW
#define RegQueryValueExW                     ADVAPI32$RegQueryValueExW
#define RegSetValueExW                       ADVAPI32$RegSetValueExW
#define RegCreateKeyExW                      ADVAPI32$RegCreateKeyExW
#define SetServiceObjectSecurity             ADVAPI32$SetServiceObjectSecurity
#define SetThreadToken                       ADVAPI32$SetThreadToken
#define StartServiceW                        ADVAPI32$StartServiceW

/* ============ CRYPT32 ============ */
#define CertAddEncodedCertificateToStore     CRYPT32$CertAddEncodedCertificateToStore
#define CertCloseStore                       CRYPT32$CertCloseStore
#define CertFreeCertificateContext           CRYPT32$CertFreeCertificateContext
#define CertOpenStore                        CRYPT32$CertOpenStore
#define CertSetCertificateContextProperty    CRYPT32$CertSetCertificateContextProperty
#define CryptBinaryToStringA                 CRYPT32$CryptBinaryToStringA
#define CryptBinaryToStringW                 CRYPT32$CryptBinaryToStringW
#define CryptStringToBinaryA                 CRYPT32$CryptStringToBinaryA
#define CryptStringToBinaryW                 CRYPT32$CryptStringToBinaryW
#define CryptUnprotectData                   CRYPT32$CryptUnprotectData
#define PFXExportCertStoreEx                 CRYPT32$PFXExportCertStoreEx

/* ============ NTDLL ============ */
#define RtlCompressBuffer                    NTDLL$RtlCompressBuffer
#define RtlDecompressBuffer                  NTDLL$RtlDecompressBuffer
#define RtlGetCompressionWorkSpaceSize       NTDLL$RtlGetCompressionWorkSpaceSize
#define RtlGetNtVersionNumbers               NTDLL$RtlGetNtVersionNumbers
#define RtlEqualUnicodeString                NTDLL$RtlEqualUnicodeString
#define RtlEqualString                       NTDLL$RtlEqualString
#define RtlDowncaseUnicodeString             NTDLL$RtlDowncaseUnicodeString
#define RtlFreeAnsiString                    NTDLL$RtlFreeAnsiString
#define RtlFreeUnicodeString                 NTDLL$RtlFreeUnicodeString
#define RtlGetCurrentPeb                     NTDLL$RtlGetCurrentPeb
#define RtlGUIDFromString                    NTDLL$RtlGUIDFromString
#define RtlInitUnicodeString                 NTDLL$RtlInitUnicodeString
#define RtlStringFromGUID                    NTDLL$RtlStringFromGUID
#define RtlUnicodeStringToAnsiString         NTDLL$RtlUnicodeStringToAnsiString
#define RtlCreateUserThread                  NTDLL$RtlCreateUserThread
#define NtCompareTokens                      NTDLL$NtCompareTokens
#define NtQueryInformationProcess            NTDLL$NtQueryInformationProcess
#define NtQueryObject                        NTDLL$NtQueryObject
#define NtQuerySystemInformation             NTDLL$NtQuerySystemInformation
#define NtResumeProcess                      NTDLL$NtResumeProcess
#define NtTerminateProcess                   NTDLL$NtTerminateProcess

/* ============ ADVAPI32 (bare non-imp mimikatz decls) ============ */
#define A_SHAFinal                           ADVAPI32$A_SHAFinal
#define A_SHAInit                            ADVAPI32$A_SHAInit
#define A_SHAUpdate                          ADVAPI32$A_SHAUpdate
#define LsaClose                             ADVAPI32$LsaClose
#define LsaOpenPolicy                        ADVAPI32$LsaOpenPolicy
#define LsaQueryInformationPolicy            ADVAPI32$LsaQueryInformationPolicy
#define SystemFunction007                    ADVAPI32$SystemFunction007

/* ============ NETAPI32 ============ */
#define DsGetDcNameW                         NETAPI32$DsGetDcNameW
#define NetApiBufferFree                     NETAPI32$NetApiBufferFree

/* ============ MSASN1 ============ */
#define ASN1BERDotVal2Eoid                   MSASN1$ASN1BERDotVal2Eoid
#define ASN1BEREoid2DotVal                   MSASN1$ASN1BEREoid2DotVal
#define ASN1_CloseDecoder                    MSASN1$ASN1_CloseDecoder
#define ASN1_CloseEncoder                    MSASN1$ASN1_CloseEncoder
#define ASN1_CloseModule                     MSASN1$ASN1_CloseModule
#define ASN1_CreateDecoder                   MSASN1$ASN1_CreateDecoder
#define ASN1_CreateEncoder                   MSASN1$ASN1_CreateEncoder
#define ASN1_CreateModule                    MSASN1$ASN1_CreateModule
#define ASN1Free                             MSASN1$ASN1Free
#define ASN1_FreeEncoded                     MSASN1$ASN1_FreeEncoded

/* ============ WLDAP32 ============ */
#define ldap_bind_sW                         WLDAP32$ldap_bind_sW
#define ldap_count_entries                   WLDAP32$ldap_count_entries
#define ldap_count_values_len                WLDAP32$ldap_count_values_len
#define ldap_get_values_lenW                 WLDAP32$ldap_get_values_lenW
#define ldap_initW                           WLDAP32$ldap_initW
#define ldap_msgfree                         WLDAP32$ldap_msgfree
#define ldap_search_sW                       WLDAP32$ldap_search_sW
#define ldap_unbind                          WLDAP32$ldap_unbind
#define ldap_modify_sW                       WLDAP32$ldap_modify_sW
#define ldap_set_optionW                     WLDAP32$ldap_set_optionW
#define ldap_value_free_len                  WLDAP32$ldap_value_free_len
#define ber_alloc_t                          WLDAP32$ber_alloc_t
#define ber_bvfree                           WLDAP32$ber_bvfree
#define ber_flatten                          WLDAP32$ber_flatten
#define ber_free                             WLDAP32$ber_free
#define ber_printf                           WLDAP32$ber_printf

/* ============ RPCRT4 ============ */
#define RpcBindingFree                       RPCRT4$RpcBindingFree
#define RpcBindingFromStringBindingW         RPCRT4$RpcBindingFromStringBindingW
#define RpcBindingInqAuthClientW             RPCRT4$RpcBindingInqAuthClientW
#define RpcBindingSetAuthInfoExW             RPCRT4$RpcBindingSetAuthInfoExW
#define RpcBindingSetOption                  RPCRT4$RpcBindingSetOption
#define RpcImpersonateClient                 RPCRT4$RpcImpersonateClient
#define RpcRevertToSelf                      RPCRT4$RpcRevertToSelf
#define RpcStringBindingComposeW             RPCRT4$RpcStringBindingComposeW
#define RpcStringFreeW                       RPCRT4$RpcStringFreeW
#define UuidCreate                           RPCRT4$UuidCreate

/* ============ SHLWAPI ============ */
#define PathCanonicalizeW                    SHLWAPI$PathCanonicalizeW
#define PathCombineW                         SHLWAPI$PathCombineW
#define PathIsRelativeW                      SHLWAPI$PathIsRelativeW

/* ============ USER32 ============ */
#define IsCharAlphaNumericW                  USER32$IsCharAlphaNumericW
#define GetUserObjectInformationW            USER32$GetUserObjectInformationW

/* -------------------------------------------------------------------------
 * Bring the SDK types in with the aliases ABOVE active, so windows.h /
 * ntsecapi.h declare the qualified names. For symbols with dllimport in the
 * SDK (~130), that's enough — the aliased declaration inherits dllimport.
 * The four LSA/SystemFunction007 symbols come from mingw's ntsecapi.h as
 * bare externs (no dllimport), so we add explicit dllimport prototypes here
 * with the SDK's exact types now that they're available. gcc upgrades a
 * previously-bare declaration to dllimport when a later decl adds it.
 * Symbols mimikatz declares in its OWN modules/*.h headers get dllimport
 * via the DECLSPEC_IMPORT prefix added there directly.
 * ------------------------------------------------------------------------- */
/* Temporarily suppress the LSA/NETAPI aliases so system headers declare the
 * original names as usual (bare externs). We then restore the aliases and
 * publish dllimport prototypes for the qualified names. */
#pragma push_macro("LsaClose")
#pragma push_macro("LsaOpenPolicy")
#pragma push_macro("LsaQueryInformationPolicy")
#undef LsaClose
#undef LsaOpenPolicy
#undef LsaQueryInformationPolicy

#include <windows.h>
#include <ntsecapi.h>

#pragma pop_macro("LsaQueryInformationPolicy")
#pragma pop_macro("LsaOpenPolicy")
#pragma pop_macro("LsaClose")

extern __attribute__((dllimport)) NTSTATUS NTAPI ADVAPI32$LsaClose(LSA_HANDLE);
extern __attribute__((dllimport)) NTSTATUS NTAPI ADVAPI32$LsaOpenPolicy(PLSA_UNICODE_STRING, PLSA_OBJECT_ATTRIBUTES, ACCESS_MASK, PLSA_HANDLE);
extern __attribute__((dllimport)) NTSTATUS NTAPI ADVAPI32$LsaQueryInformationPolicy(LSA_HANDLE, POLICY_INFORMATION_CLASS, PVOID*);

#endif /* BOF_DFR_H */
