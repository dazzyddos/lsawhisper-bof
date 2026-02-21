/*
 * lsa_structs.h - Documented and undocumented LSA structures
 * 
 * Based on reverse engineering from LSA Whisperer (MIT License)
 * by Evan McBroom / SpecterOps
 *
 * These structures define the message protocols for communicating
 * with Authentication Packages via LsaCallAuthenticationPackage.
 */
#pragma once

#include <windows.h>

/* ============================================================
 * Forward type definitions (must come before any struct usage)
 * ============================================================ */

/* LSA_UNICODE_STRING - reuse UNICODE_STRING from winternl.h if available */
#ifndef _LSA_UNICODE_STRING_DEFINED
#define _LSA_UNICODE_STRING_DEFINED
typedef UNICODE_STRING LSA_UNICODE_STRING, *PLSA_UNICODE_STRING;
#endif

/* SecHandle for Kerberos retrieve request */
#ifndef _SEC_HANDLE_DEFINED
#define _SEC_HANDLE_DEFINED
typedef struct _SecHandle {
    ULONG_PTR dwLower;
    ULONG_PTR dwUpper;
} SecHandle, *PSecHandle;
#endif

/* LSA_LAST_INTER_LOGON_INFO for session data */
#ifndef _LSA_LAST_INTER_LOGON_INFO_DEFINED
#define _LSA_LAST_INTER_LOGON_INFO_DEFINED
typedef struct _LSA_LAST_INTER_LOGON_INFO {
    LARGE_INTEGER LastSuccessfulLogon;
    LARGE_INTEGER LastFailedLogon;
    ULONG FailedAttemptCountSinceLastSuccessfulLogon;
} LSA_LAST_INTER_LOGON_INFO, *PLSA_LAST_INTER_LOGON_INFO;
#endif

/* ============================================================
 * Common LSA Types (from ntsecapi.h, redefined for BOF)
 * ============================================================ */

#ifndef _LSA_STRING_DEFINED
#define _LSA_STRING_DEFINED
typedef struct _LSA_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PCHAR  Buffer;
} LSA_STRING, *PLSA_STRING;
#endif

typedef ULONG LSA_OPERATIONAL_MODE;

/* Known package names */
#define MSV1_0_PACKAGE_NAME     "MICROSOFT_AUTHENTICATION_PACKAGE_V1_0"
#define KERBEROS_PACKAGE_NAME   "Kerberos"
#define NEGOTIATE_PACKAGE_NAME  "Negotiate"
#define CLOUDAP_PACKAGE_NAME    "CloudAP"
#define SCHANNEL_PACKAGE_NAME   "Schannel"
#define PKU2U_PACKAGE_NAME      "pku2u"
#define NEGOEXTS_PACKAGE_NAME   "NegoExtender"
#define LIVESSP_PACKAGE_NAME    "LiveSSP"

/* ============================================================
 * MSV1_0 - Microsoft Authentication Package V1.0
 * ============================================================ */

/*
 * MSV1_0 Protocol Message Types (ntsecapi.h + undocumented extensions)
 */
typedef enum _MSV1_0_PROTOCOL_MESSAGE_TYPE {
    MsV1_0Lm20ChallengeRequest = 0,
    MsV1_0Lm20GetChallengeResponse,        // 1
    MsV1_0EnumerateUsers,                   // 2
    MsV1_0GetUserInfo,                      // 3
    MsV1_0ReLogonUsers,                     // 4
    MsV1_0ChangePassword,                   // 5
    MsV1_0ChangeCachedPassword,             // 6
    MsV1_0GenericPassthrough,               // 7
    MsV1_0CacheLogon,                       // 8
    MsV1_0SubAuth,                          // 9
    MsV1_0DeriveCredential,                 // 10
    MsV1_0CacheLookup,                      // 11
    MsV1_0SetProcessOption,                 // 12
    MsV1_0ConfigLocalAliases,               // 13
    MsV1_0ClearCachedCredentials,           // 14
    MsV1_0LookupToken,                      // 15
    MsV1_0ValidateAuth,                     // 16
    MsV1_0CacheLookupEx,                    // 17
    MsV1_0GetCredentialKey,                 // 18  <-- DPAPI cred key recovery
    MsV1_0SetThreadOption,                  // 19
    MsV1_0DecryptDpapiMasterKey,            // 20
    MsV1_0GetStrongCredentialKey,           // 21  <-- Strong DPAPI cred key
    MsV1_0TransferCred,                     // 22
    MsV1_0ProvisionTbal,                    // 23
    MsV1_0DeleteTbalSecret,                 // 24
} MSV1_0_PROTOCOL_MESSAGE_TYPE, *PMSV1_0_PROTOCOL_MESSAGE_TYPE;

/*
 * MSV1_0 GetCredentialKey Request
 * Recovers the DPAPI credential key for a logon session.
 * Compatible with Credential Guard.
 */
typedef struct _MSV1_0_GETCREDENTIALKEY_REQUEST {
    MSV1_0_PROTOCOL_MESSAGE_TYPE MessageType;  // = MsV1_0GetCredentialKey (18)
    LUID LogonId;
    UCHAR Reserved[16];                         // Must be zeroed
} MSV1_0_GETCREDENTIALKEY_REQUEST, *PMSV1_0_GETCREDENTIALKEY_REQUEST;

/*
 * MSV1_0 GetCredentialKey Response
 * Returns credential key data. Structure from LSA Whisperer:
 *   - MessageType (4 bytes)
 *   - Reserved (16 bytes)
 *   - CredSize (4 bytes) = 0x28
 *   - ShaPassword (20 bytes) - SHA OWF / Local CredKey
 *   - Key2 (20 bytes) - Domain CredKey (NT OWF or "Secure" DPAPI key)
 *   - 8 bytes padding
 */
#define MSV1_0_SHA_PASSWORD_LENGTH    20
#define MSV1_0_OWF_PASSWORD_LENGTH    16
#define MSV1_0_CREDENTIAL_KEY_LENGTH  20

typedef struct _MSV1_0_GETCREDENTIALKEY_RESPONSE {
    MSV1_0_PROTOCOL_MESSAGE_TYPE MessageType;
    UCHAR Reserved[16];
    DWORD CredSize;                              // Typically 0x28
    UCHAR ShaPassword[MSV1_0_SHA_PASSWORD_LENGTH]; // Local CredKey (SHA OWF)
    UCHAR Key2[20];                              // Domain CredKey
    // 8 bytes of trailing padding
} MSV1_0_GETCREDENTIALKEY_RESPONSE, *PMSV1_0_GETCREDENTIALKEY_RESPONSE;

/*
 * MSV1_0 GetStrongCredentialKey Request/Response
 * From LSA Whisperer source - more complex struct with version field.
 * Version 0: uses Reserved + LogonId
 * Version 1: uses KeyType, Key, Sid fields
 */
typedef struct _MSV1_0_GETSTRONGCREDENTIALKEY_REQUEST {
    MSV1_0_PROTOCOL_MESSAGE_TYPE MessageType;  // = MsV1_0GetStrongCredentialKey (21)
    DWORD Version;                              // 0 for basic mode
    DWORD Reserved[8];                          // Ignored in version 0
    LUID LogonId;
    DWORD KeyType;                              // Used in version 1
    DWORD KeyLength;                            // Used in version 1
    PVOID Key;                                  // Used in version 1
    DWORD SidLength;                            // Used in version 1
    PVOID Sid;                                  // Used in version 1
    DWORD IsProtectedUser;                      // From lsasrv!LsapGetStrongCredentialKeyFromMSV
} MSV1_0_GETSTRONGCREDENTIALKEY_REQUEST, *PMSV1_0_GETSTRONGCREDENTIALKEY_REQUEST;

/*
 * MSV1_0 Lm20GetChallengeResponse
 * Generate an NTLMv1 response using a chosen server challenge.
 * Bypasses LmCompatibilityLevel. Blocked by Credential Guard.
 */

/* Parameter control flags for Lm20GetChallengeResponse */
#define MSV1_0_RETURN_PASSWORD_EXPIRY     0x00000040
#define MSV1_0_USE_CLIENT_CHALLENGE       0x00000080
#define MSV1_0_RETURN_PROFILE_PATH        0x00000200
#define MSV1_0_DISABLE_PERSONAL_FALLBACK  0x00001000

/* Re-define the documented structure for clarity */
typedef struct _MSV1_0_LM20_CHALLENGE_REQUEST {
    MSV1_0_PROTOCOL_MESSAGE_TYPE MessageType;  // = MsV1_0Lm20ChallengeRequest (0)
} MSV1_0_LM20_CHALLENGE_REQUEST;

typedef struct _MSV1_0_LM20_CHALLENGE_RESPONSE_REQ {
    MSV1_0_PROTOCOL_MESSAGE_TYPE MessageType;  // = MsV1_0Lm20GetChallengeResponse (1)
    ULONG ParameterControl;
    LUID LogonId;
    UNICODE_STRING Password;                    // Empty (Length=0, Buffer=NULL) to use stored cred
    UCHAR ChallengeToClient[8];                 // 8-byte server challenge
    // Optional NTLMv2 fields (only if GCR_NTLM3_PARMS = 0x20):
    // UNICODE_STRING UserName;
    // UNICODE_STRING LogonDomainName;
    // UNICODE_STRING ServerName;
} MSV1_0_LM20_CHALLENGE_RESPONSE_REQ;

/* Response structure */
typedef struct _STRING32 {
    USHORT Length;
    USHORT MaximumLength;
    ULONG  Buffer;          // Offset relative to response base
} STRING32;

typedef struct _MSV1_0_LM20_CHALLENGE_RESPONSE_RESP {
    MSV1_0_PROTOCOL_MESSAGE_TYPE MessageType;
    STRING32 CaseSensitiveChallengeResponse;   // NTLM response
    STRING32 CaseInsensitiveChallengeResponse; // LM response
    UNICODE_STRING UserName;
    UNICODE_STRING LogonDomainName;
    UNICODE_STRING UserParameters;
} MSV1_0_LM20_CHALLENGE_RESPONSE_RESP;

/* ============================================================
 * KERBEROS - Kerberos Authentication Package
 * ============================================================ */

/*
 * Kerberos Protocol Message Types
 * Documented + undocumented extensions from LSA Whisperer
 */
typedef enum _KERB_PROTOCOL_MESSAGE_TYPE {
    KerbDebugRequestMessage = 0,
    KerbQueryTicketCacheMessage,                // 1
    KerbChangeMachinePasswordMessage,           // 2
    KerbVerifyPacMessage,                       // 3
    KerbRetrieveTicketMessage,                  // 4
    KerbUpdateAddressesMessage,                 // 5
    KerbPurgeTicketCacheMessage,                // 6
    KerbChangePasswordMessage,                  // 7
    KerbRetrieveEncodedTicketMessage,           // 8
    KerbDecryptDataMessage,                     // 9
    KerbAddBindingCacheEntryMessage,            // 10
    KerbSetPasswordMessage,                     // 11
    KerbSetPasswordExMessage,                   // 12
    KerbVerifyCredentialsMessage,               // 13  (not implemented)
    KerbQueryTicketCacheExMessage,              // 14
    KerbPurgeTicketCacheExMessage,              // 15
    KerbRefreshSmartcardCredentialsMessage,     // 16
    KerbAddExtraCredentialsMessage,             // 17
    KerbQuerySupplementalCredentialsMessage,    // 18
    KerbTransferCredentialsMessage,             // 19
    KerbQueryTicketCacheEx2Message,             // 20  <-- Extended cache query
    KerbSubmitTicketMessage,                    // 21  <-- PTT
    KerbAddExtraCredentialsExMessage,           // 22
    KerbQueryKdcProxyCacheMessage,              // 23
    KerbPurgeKdcProxyCacheMessage,              // 24
    KerbQueryTicketCacheEx3Message,             // 25
    KerbCleanupMachinePkinitCredsMessage,       // 26
    KerbAddBindingCacheEntryExMessage,          // 27  <-- Domain binding (Golden Ticket)
    KerbQueryBindingCacheMessage,               // 28
    KerbPurgeBindingCacheMessage,               // 29
    KerbPinKdcMessage,                          // 30  <-- KDC pinning (LPE)
    KerbUnpinAllKdcsMessage,                    // 31
    KerbQueryDomainExtendedPoliciesMessage,     // 32  <-- FAST, etc.
    KerbQueryS4U2ProxyCacheMessage,             // 33
    KerbRetrieveKeyTabMessage,                  // 34
    KerbRefreshPolicyMessage,                   // 35
    KerbPrintCloudKerberosDebugMessage,         // 36
} KERB_PROTOCOL_MESSAGE_TYPE, *PKERB_PROTOCOL_MESSAGE_TYPE;

/* Kerberos encryption types */
#define KERB_ETYPE_DES_CBC_CRC          0x0001
#define KERB_ETYPE_DES_CBC_MD5          0x0003
#define KERB_ETYPE_AES128_CTS_HMAC_SHA1 0x0011
#define KERB_ETYPE_AES256_CTS_HMAC_SHA1 0x0012
#define KERB_ETYPE_RC4_HMAC_NT          0x0017
#define KERB_ETYPE_RC4_HMAC_NT_EXP      0x0018

/* Ticket flags */
#define KERB_TICKET_FLAGS_forwardable     0x40000000
#define KERB_TICKET_FLAGS_forwarded       0x20000000
#define KERB_TICKET_FLAGS_proxiable       0x10000000
#define KERB_TICKET_FLAGS_proxy           0x08000000
#define KERB_TICKET_FLAGS_may_postdate    0x04000000
#define KERB_TICKET_FLAGS_postdated       0x02000000
#define KERB_TICKET_FLAGS_invalid         0x01000000
#define KERB_TICKET_FLAGS_renewable       0x00800000
#define KERB_TICKET_FLAGS_initial         0x00400000
#define KERB_TICKET_FLAGS_pre_authent     0x00200000
#define KERB_TICKET_FLAGS_hw_authent      0x00100000
#define KERB_TICKET_FLAGS_ok_as_delegate  0x00040000
#define KERB_TICKET_FLAGS_name_canonicalize 0x00010000

/* Query Ticket Cache */
typedef struct _KERB_QUERY_TKT_CACHE_REQUEST {
    KERB_PROTOCOL_MESSAGE_TYPE MessageType;  // KerbQueryTicketCacheEx2Message
    LUID LogonId;
} KERB_QUERY_TKT_CACHE_REQUEST, *PKERB_QUERY_TKT_CACHE_REQUEST;

typedef struct _KERB_TICKET_CACHE_INFO_EX {
    UNICODE_STRING ClientName;
    UNICODE_STRING ClientRealm;
    UNICODE_STRING ServerName;
    UNICODE_STRING ServerRealm;
    LARGE_INTEGER  StartTime;
    LARGE_INTEGER  EndTime;
    LARGE_INTEGER  RenewTime;
    LONG           EncryptionType;
    ULONG          TicketFlags;
} KERB_TICKET_CACHE_INFO_EX, *PKERB_TICKET_CACHE_INFO_EX;

typedef struct _KERB_TICKET_CACHE_INFO_EX2 {
    UNICODE_STRING ClientName;
    UNICODE_STRING ClientRealm;
    UNICODE_STRING ServerName;
    UNICODE_STRING ServerRealm;
    LARGE_INTEGER  StartTime;
    LARGE_INTEGER  EndTime;
    LARGE_INTEGER  RenewTime;
    LONG           EncryptionType;
    ULONG          TicketFlags;
    /* Extended fields in Ex2: */
    ULONG          SessionKeyType;
    ULONG          BranchId;
} KERB_TICKET_CACHE_INFO_EX2, *PKERB_TICKET_CACHE_INFO_EX2;

typedef struct _KERB_QUERY_TKT_CACHE_RESPONSE {
    KERB_PROTOCOL_MESSAGE_TYPE MessageType;
    ULONG CountOfTickets;
    KERB_TICKET_CACHE_INFO_EX Tickets[ANYSIZE_ARRAY];
} KERB_QUERY_TKT_CACHE_RESPONSE, *PKERB_QUERY_TKT_CACHE_RESPONSE;

typedef struct _KERB_QUERY_TKT_CACHE_EX2_RESPONSE {
    KERB_PROTOCOL_MESSAGE_TYPE MessageType;
    ULONG CountOfTickets;
    KERB_TICKET_CACHE_INFO_EX2 Tickets[ANYSIZE_ARRAY];
} KERB_QUERY_TKT_CACHE_EX2_RESPONSE, *PKERB_QUERY_TKT_CACHE_EX2_RESPONSE;

/* Retrieve Encoded Ticket (dump .kirbi) */
#define KERB_RETRIEVE_TICKET_DEFAULT    0x0
#define KERB_RETRIEVE_TICKET_DONT_USE_CACHE 0x1
#define KERB_RETRIEVE_TICKET_USE_CACHE_ONLY 0x2
#define KERB_RETRIEVE_TICKET_USE_CREDHANDLE 0x4
#define KERB_RETRIEVE_TICKET_AS_KERB_CRED   0x8
#define KERB_RETRIEVE_TICKET_WITH_SEC_CRED  0x10
#define KERB_RETRIEVE_TICKET_CACHE_TICKET   0x20
#define KERB_RETRIEVE_TICKET_MAX_LIFETIME   0x40

typedef struct _KERB_RETRIEVE_TKT_REQUEST {
    KERB_PROTOCOL_MESSAGE_TYPE MessageType;  // KerbRetrieveEncodedTicketMessage
    LUID LogonId;
    UNICODE_STRING TargetName;
    ULONG TicketFlags;
    ULONG CacheOptions;
    LONG  EncryptionType;
    SecHandle CredentialsHandle;
} KERB_RETRIEVE_TKT_REQUEST, *PKERB_RETRIEVE_TKT_REQUEST;

typedef struct _KERB_CRYPTO_KEY {
    LONG  KeyType;
    ULONG Length;
    PUCHAR Value;
} KERB_CRYPTO_KEY, *PKERB_CRYPTO_KEY;

typedef struct _KERB_EXTERNAL_NAME {
    SHORT  NameType;
    USHORT NameCount;
    UNICODE_STRING Names[ANYSIZE_ARRAY];
} KERB_EXTERNAL_NAME, *PKERB_EXTERNAL_NAME;

typedef struct _KERB_EXTERNAL_TICKET {
    PKERB_EXTERNAL_NAME ServiceName;
    PKERB_EXTERNAL_NAME TargetName;
    PKERB_EXTERNAL_NAME ClientName;
    UNICODE_STRING      DomainName;
    UNICODE_STRING      TargetDomainName;
    UNICODE_STRING      AltTargetDomainName;
    KERB_CRYPTO_KEY     SessionKey;
    ULONG               TicketFlags;
    ULONG               Flags;
    LARGE_INTEGER       KeyExpirationTime;
    LARGE_INTEGER       StartTime;
    LARGE_INTEGER       EndTime;
    LARGE_INTEGER       RenewUntil;
    LARGE_INTEGER       TimeSkew;
    ULONG               EncodedTicketSize;
    PUCHAR              EncodedTicket;      // The raw .kirbi data
} KERB_EXTERNAL_TICKET, *PKERB_EXTERNAL_TICKET;

typedef struct _KERB_RETRIEVE_TKT_RESPONSE {
    KERB_EXTERNAL_TICKET Ticket;
} KERB_RETRIEVE_TKT_RESPONSE, *PKERB_RETRIEVE_TKT_RESPONSE;

/* Submit Ticket (Pass-the-Ticket) */
typedef struct _KERB_SUBMIT_TKT_REQUEST {
    KERB_PROTOCOL_MESSAGE_TYPE MessageType;  // KerbSubmitTicketMessage
    LUID LogonId;
    ULONG Flags;
    KERB_CRYPTO_KEY Key;                     // Optional: session key
    ULONG KerbCredSize;
    ULONG KerbCredOffset;                    // Offset to KRB-CRED data
    // Variable: KRB-CRED data follows at KerbCredOffset
} KERB_SUBMIT_TKT_REQUEST, *PKERB_SUBMIT_TKT_REQUEST;

/* Purge Ticket Cache Extended (Selective purge) */
typedef struct _KERB_PURGE_TKT_CACHE_EX_REQUEST {
    KERB_PROTOCOL_MESSAGE_TYPE MessageType;  // KerbPurgeTicketCacheExMessage
    LUID LogonId;
    ULONG Flags;
    KERB_TICKET_CACHE_INFO_EX TicketTemplate;  // Match criteria
} KERB_PURGE_TKT_CACHE_EX_REQUEST, *PKERB_PURGE_TKT_CACHE_EX_REQUEST;

/* Query Domain Extended Policies */
typedef struct _KERB_QUERY_DOMAIN_EXTENDED_POLICIES_REQUEST {
    KERB_PROTOCOL_MESSAGE_TYPE MessageType;  // KerbQueryDomainExtendedPoliciesMessage
    ULONG Flags;
    UNICODE_STRING DomainName;
} KERB_QUERY_DOMAIN_EXTENDED_POLICIES_REQUEST;

typedef struct _KERB_QUERY_DOMAIN_EXTENDED_POLICIES_RESPONSE {
    KERB_PROTOCOL_MESSAGE_TYPE MessageType;
    ULONG Flags;
    // Flags indicate: FAST enforcement, claims support, compound auth, etc.
} KERB_QUERY_DOMAIN_EXTENDED_POLICIES_RESPONSE;

/* Add Binding Cache Entry (Domain binding for Golden Ticket) */
typedef struct _KERB_ADD_BINDING_CACHE_ENTRY_EX_REQUEST {
    KERB_PROTOCOL_MESSAGE_TYPE MessageType;
    UNICODE_STRING RealmName;
    UNICODE_STRING KdcAddress;
    ULONG AddressType;          // DS_INET_ADDRESS or DS_NETBIOS_ADDRESS
    ULONG DcFlags;
} KERB_ADD_BINDING_CACHE_ENTRY_EX_REQUEST;

/* Pin KDC (for local privilege escalation) */
typedef struct _KERB_PIN_KDC_REQUEST {
    KERB_PROTOCOL_MESSAGE_TYPE MessageType;  // KerbPinKdcMessage
    UNICODE_STRING RealmName;
    UNICODE_STRING KdcAddress;
    ULONG DcFlags;
} KERB_PIN_KDC_REQUEST;

typedef struct _KERB_UNPIN_ALL_KDCS_REQUEST {
    KERB_PROTOCOL_MESSAGE_TYPE MessageType;  // KerbUnpinAllKdcsMessage
} KERB_UNPIN_ALL_KDCS_REQUEST;

/* ============================================================
 * CLOUDAP - Cloud Authentication Package (Fully Undocumented)
 * ============================================================ */

/*
 * CloudAP Call IDs
 */
typedef enum _CLOUDAP_CALL_ID {
    CloudApDisableOptimizedLogon = 0,
    CloudApGenARSOPwd = 1,
    CloudApGetAuthenticatingProvider = 2,
    CloudApGetDpApiCredKeyDecryptStatus = 3,
    CloudApGetPwdExpiryInfo = 4,
    CloudApGetTokenBlob = 5,
    CloudApGetUnlockKeyType = 6,
    CloudApIsCloudToOnPremTgtPresentInCache = 7,
    CloudApPluginCall = 8,              // Dispatch to AAD/MSA plugin
    CloudApRefreshTokenBlob = 9,
    CloudApRenewableRetrievePrt = 10,
    CloudApSetTestParas = 11,
    CloudApTransferCreds = 12,
} CLOUDAP_CALL_ID;

/*
 * AAD Plugin Call IDs
 * These are sub-call IDs routed through CloudApPluginCall
 */
typedef enum _AAD_PLUGIN_CALL_ID {
    AadCreateDeviceSSOCookie = 0,
    AadCreateEnterpriseSSOCookie = 1,
    AadCreateSSOCookie = 2,
    AadDeviceValidityCheck = 3,
    AadGenerateBindingClaims = 4,
    AadGetAccountInfo = 5,
    AadGetPrtAuthority = 6,
    AadGetSSOData = 7,
    AadRefreshP2PCACert = 8,
    AadSignPayload = 9,
} AAD_PLUGIN_CALL_ID;

/* Known Plugin GUIDs */
// AAD / Entra ID Plugin:   {B16898C6-A148-4967-9171-64D755DA8520}
// MSA Plugin:              {D7F9888F-E3FC-49B0-9EA6-A85B5F392A4F}

static const GUID GUID_PLUGIN_AAD = {
    0xB16898C6, 0xA148, 0x4967,
    { 0x91, 0x71, 0x64, 0xD7, 0x55, 0xDA, 0x85, 0x20 }
};

static const GUID GUID_PLUGIN_MSA = {
    0xD7F9888F, 0xE3FC, 0x49B0,
    { 0x9E, 0xA6, 0xA8, 0x5B, 0x5F, 0x39, 0x2A, 0x4F }
};

/* Generic CloudAP Request Header */
typedef struct _CLOUDAP_REQUEST_HEADER {
    ULONG dwCallId;
    LUID  LogonId;
} CLOUDAP_REQUEST_HEADER, *PCLOUDAP_REQUEST_HEADER;

/* CloudAP PluginCall Request (routes to AAD or MSA) */
typedef struct _CLOUDAP_PLUGIN_CALL_REQUEST {
    ULONG dwCallId;               // = CloudApPluginCall (8)
    LUID  LogonId;
    GUID  PluginId;               // AAD or MSA GUID
    ULONG dwPluginCallId;         // AAD_PLUGIN_CALL_ID value
    ULONG cbPluginInput;          // Size of following data
    // Variable: Plugin-specific input data follows
} CLOUDAP_PLUGIN_CALL_REQUEST, *PCLOUDAP_PLUGIN_CALL_REQUEST;

/* GetAuthenticatingProvider Response */
typedef struct _CLOUDAP_GET_AUTH_PROVIDER_RESPONSE {
    ULONG dwCallId;
    GUID  ProviderGuid;
} CLOUDAP_GET_AUTH_PROVIDER_RESPONSE;

/* IsCloudToOnPremTgtPresentInCache Response */
typedef struct _CLOUDAP_CLOUD_TGT_RESPONSE {
    ULONG dwCallId;
    BOOL  bIsPresent;
} CLOUDAP_CLOUD_TGT_RESPONSE;

/* GetDpApiCredKeyDecryptStatus Response */
typedef struct _CLOUDAP_DPAPI_STATUS_RESPONSE {
    ULONG dwCallId;
    BOOL  bIsDecrypted;
} CLOUDAP_DPAPI_STATUS_RESPONSE;

/* AAD CreateSSOCookie Response */
// The response is a variable-length buffer containing the SSO cookie string
// Cookie format: typically a PRT-derived x-ms-RefreshTokenCredential value
typedef struct _AAD_SSO_COOKIE_RESPONSE {
    ULONG cbCookieLength;
    // wchar_t Cookie[] follows (null-terminated wide string)
} AAD_SSO_COOKIE_RESPONSE;

/* ============================================================
 * SECURITY_LOGON_SESSION_DATA (for session enumeration)
 * ============================================================ */

typedef struct _SECURITY_LOGON_SESSION_DATA {
    ULONG               Size;
    LUID                LogonId;
    LSA_UNICODE_STRING  UserName;
    LSA_UNICODE_STRING  LogonDomain;
    LSA_UNICODE_STRING  AuthenticationPackage;
    ULONG               LogonType;
    ULONG               Session;
    PSID                Sid;
    LARGE_INTEGER       LogonTime;
    LSA_UNICODE_STRING  LogonServer;
    LSA_UNICODE_STRING  DnsDomainName;
    LSA_UNICODE_STRING  Upn;
    /* Extended fields (Windows 2000+): */
    ULONG               UserFlags;
    LSA_LAST_INTER_LOGON_INFO LastLogonInfo;
    LSA_UNICODE_STRING  LogonScript;
    LSA_UNICODE_STRING  ProfilePath;
    LSA_UNICODE_STRING  HomeDirectory;
    LSA_UNICODE_STRING  HomeDirectoryDrive;
    LARGE_INTEGER       LogoffTime;
    LARGE_INTEGER       KickOffTime;
    LARGE_INTEGER       PasswordLastSet;
    LARGE_INTEGER       PasswordCanChange;
    LARGE_INTEGER       PasswordMustChange;
} SECURITY_LOGON_SESSION_DATA, *PSECURITY_LOGON_SESSION_DATA;

/* Logon types */
#define LOGON_TYPE_INTERACTIVE        2
#define LOGON_TYPE_NETWORK            3
#define LOGON_TYPE_BATCH              4
#define LOGON_TYPE_SERVICE            5
#define LOGON_TYPE_UNLOCK             7
#define LOGON_TYPE_NETWORK_CLEARTEXT  8
#define LOGON_TYPE_NEW_CREDENTIALS    9
#define LOGON_TYPE_REMOTE_INTERACTIVE 10
#define LOGON_TYPE_CACHED_INTERACTIVE 11
#define LOGON_TYPE_CACHED_REMOTE_INTERACTIVE 12
#define LOGON_TYPE_CACHED_UNLOCK      13

/* (type definitions moved to top of file) */
