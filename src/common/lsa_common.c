/*
 * lsa_common.c - Core LSA communication layer for BOF
 * 
 * Provides wrappers for LsaConnect, LsaLookupPackage, LsaCall, etc.
 * Included directly into each BOF module via #include.
 */

#include "beacon.h"
#include "bofdefs.h"
#include "lsa_structs.h"

/* ============================================================
 * LSA Connection Management
 * ============================================================ */

/*
 * Initialize connection to LSA.
 * bTrusted=TRUE requires SeTcbPrivilege (SYSTEM context)
 *   and allows targeting arbitrary logon sessions.
 * bTrusted=FALSE works from any user context
 *   but can only target the caller's own logon session.
 */
static NTSTATUS LsaInit(PHANDLE phLsa, BOOL bTrusted) {
    NTSTATUS status;

    if (bTrusted) {
        LSA_STRING processName;
        processName.Buffer = "LsaWhispererBOF";
        processName.Length = 16;
        processName.MaximumLength = 17;
        ULONG mode = 0;
        status = SECUR32$LsaRegisterLogonProcess(&processName, phLsa, &mode);
        if (!NT_SUCCESS(status)) {
            BeaconPrintf(CALLBACK_ERROR,
                "[!] LsaRegisterLogonProcess failed: 0x%08X\n"
                "    Requires SeTcbPrivilege (run as SYSTEM)\n"
                "    Falling back to untrusted connection...", status);
            status = SECUR32$LsaConnectUntrusted(phLsa);
        }
    } else {
        status = SECUR32$LsaConnectUntrusted(phLsa);
    }

    return status;
}

/*
 * Look up a package by name and get its ID.
 */
static NTSTATUS LsaGetPackageId(HANDLE hLsa, const char* packageName, PULONG pPackageId) {
    LSA_STRING name;
    name.Buffer = (PCHAR)packageName;
    name.Length = (USHORT)STRLEN(packageName);
    name.MaximumLength = name.Length + 1;
    return SECUR32$LsaLookupAuthenticationPackage(hLsa, &name, pPackageId);
}

/*
 * Send a package call request and get the response.
 */
static NTSTATUS LsaCallPackage(
    HANDLE hLsa,
    ULONG packageId,
    PVOID pRequest,
    ULONG requestLen,
    PVOID* ppResponse,
    PULONG pResponseLen,
    PNTSTATUS pProtocolStatus)
{
    return SECUR32$LsaCallAuthenticationPackage(
        hLsa, packageId,
        pRequest, requestLen,
        ppResponse, pResponseLen,
        pProtocolStatus);
}

/*
 * Cleanup: free response buffer and close LSA handle.
 */
static void LsaCleanup(HANDLE hLsa, PVOID pResponse) {
    if (pResponse) {
        SECUR32$LsaFreeReturnBuffer(pResponse);
    }
    if (hLsa) {
        SECUR32$LsaDeregisterLogonProcess(hLsa);
    }
}

/* ============================================================
 * LUID Parsing
 * ============================================================ */

/*
 * Parse a LUID from string. Supports:
 *   "0" or "" → use zero LUID (current session for untrusted)
 *   "0x1a2b3c" → hex value (as shown in logon session listing)
 *   "12345678" → decimal value
 */
static BOOL ParseLUID(const char* str, PLUID pLuid) {
    pLuid->HighPart = 0;
    pLuid->LowPart = 0;

    if (!str || !str[0] || (str[0] == '0' && str[1] == '\0')) {
        return TRUE;  // Zero LUID = current session
    }

    // Try hex (0x prefix)
    if (str[0] == '0' && (str[1] == 'x' || str[1] == 'X')) {
        pLuid->LowPart = MSVCRT$strtoul(str + 2, NULL, 16);
    } else {
        // Try decimal
        pLuid->LowPart = MSVCRT$strtoul(str, NULL, 10);
    }

    return TRUE;
}

/*
 * Check if LUID is zero (meaning "current session").
 */
static BOOL IsZeroLUID(PLUID pLuid) {
    return (pLuid->HighPart == 0 && pLuid->LowPart == 0);
}

/* ============================================================
 * Output Helpers
 * ============================================================ */

/*
 * Print hex dump of a buffer via BeaconPrintf.
 */
static void HexDump(const char* label, PUCHAR data, ULONG len) {
    char hexLine[128];
    char* p;
    ULONG i;

    BeaconPrintf(CALLBACK_OUTPUT, "[*] %s (%d bytes):", label, len);

    for (i = 0; i < len; i += 16) {
        p = hexLine;
        ULONG j;
        // Hex bytes
        for (j = i; j < i + 16 && j < len; j++) {
            SPRINTF(p, "%02X ", data[j]);
            p += 3;
        }
        // Pad if less than 16
        for (; j < i + 16; j++) {
            STRCPY(p, "   ");
            p += 3;
        }
        // ASCII
        *p++ = ' ';
        *p++ = '|';
        for (j = i; j < i + 16 && j < len; j++) {
            *p++ = (data[j] >= 0x20 && data[j] < 0x7f) ? (char)data[j] : '.';
        }
        *p++ = '|';
        *p = '\0';

        BeaconPrintf(CALLBACK_OUTPUT, "  %04X: %s", i, hexLine);
    }
}

/*
 * Print a hex string (no spaces, for copy-paste).
 */
static void HexString(const char* label, PUCHAR data, ULONG len) {
    // Allocate buffer: 2 chars per byte + null
    char* buf = (char*)HEAP_ALLOC(len * 2 + 1);
    if (!buf) return;

    char* p = buf;
    for (ULONG i = 0; i < len; i++) {
        SPRINTF(p, "%02X", data[i]);
        p += 2;
    }
    *p = '\0';

    BeaconPrintf(CALLBACK_OUTPUT, "[*] %s: %s", label, buf);
    HEAP_FREE(buf);
}

/*
 * Print a wide string safely.
 */
static void PrintUnicodeString(const char* label, UNICODE_STRING* pStr) {
    if (!pStr || !pStr->Buffer || pStr->Length == 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "  %s: (empty)", label);
        return;
    }

    // Convert wide to narrow for output
    int narrowLen = KERNEL32$WideCharToMultiByte(
        CP_UTF8, 0, pStr->Buffer, pStr->Length / sizeof(WCHAR),
        NULL, 0, NULL, NULL);

    if (narrowLen <= 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "  %s: (conversion error)", label);
        return;
    }

    char* narrow = (char*)HEAP_ALLOC(narrowLen + 1);
    if (!narrow) return;

    KERNEL32$WideCharToMultiByte(
        CP_UTF8, 0, pStr->Buffer, pStr->Length / sizeof(WCHAR),
        narrow, narrowLen, NULL, NULL);
    narrow[narrowLen] = '\0';

    BeaconPrintf(CALLBACK_OUTPUT, "  %s: %s", label, narrow);
    HEAP_FREE(narrow);
}

/*
 * Print an LSA_UNICODE_STRING safely.
 */
static void PrintLsaUnicodeString(const char* label, LSA_UNICODE_STRING* pStr) {
    PrintUnicodeString(label, (UNICODE_STRING*)pStr);
}

/*
 * Simple Base64 encoding for ticket output.
 */
static const char b64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static char* Base64Encode(PUCHAR data, ULONG dataLen, PULONG pOutLen) {
    ULONG outLen = ((dataLen + 2) / 3) * 4;
    char* output = (char*)HEAP_ALLOC(outLen + 1);
    if (!output) return NULL;

    ULONG i, j;
    for (i = 0, j = 0; i < dataLen; i += 3) {
        ULONG a = data[i];
        ULONG b = (i + 1 < dataLen) ? data[i + 1] : 0;
        ULONG c = (i + 2 < dataLen) ? data[i + 2] : 0;

        ULONG triple = (a << 16) | (b << 8) | c;

        output[j++] = b64_table[(triple >> 18) & 0x3F];
        output[j++] = b64_table[(triple >> 12) & 0x3F];
        output[j++] = (i + 1 < dataLen) ? b64_table[(triple >> 6) & 0x3F] : '=';
        output[j++] = (i + 2 < dataLen) ? b64_table[triple & 0x3F] : '=';
    }
    output[j] = '\0';

    if (pOutLen) *pOutLen = j;
    return output;
}

/*
 * Print NTSTATUS as human-readable error.
 */
static void PrintNTStatus(const char* context, NTSTATUS status) {
    ULONG win32Error = NTDLL$RtlNtStatusToDosError(status);
    BeaconPrintf(CALLBACK_ERROR, "[!] %s failed: NTSTATUS=0x%08X (Win32=%d)",
                 context, status, win32Error);
}

/*
 * Print Kerberos encryption type as string.
 */
static const char* EncTypeToString(LONG encType) {
    switch (encType) {
        case KERB_ETYPE_DES_CBC_CRC:          return "DES_CBC_CRC";
        case KERB_ETYPE_DES_CBC_MD5:          return "DES_CBC_MD5";
        case KERB_ETYPE_AES128_CTS_HMAC_SHA1: return "AES128_CTS_HMAC_SHA1";
        case KERB_ETYPE_AES256_CTS_HMAC_SHA1: return "AES256_CTS_HMAC_SHA1";
        case KERB_ETYPE_RC4_HMAC_NT:          return "RC4_HMAC_NT";
        case KERB_ETYPE_RC4_HMAC_NT_EXP:      return "RC4_HMAC_NT_EXP";
        default:                               return "UNKNOWN";
    }
}

/*
 * Print FILETIME as human-readable date.
 */
static void PrintFileTime(const char* label, LARGE_INTEGER* pTime) {
    FILETIME ft;
    SYSTEMTIME st;
    ft.dwLowDateTime = pTime->LowPart;
    ft.dwHighDateTime = pTime->HighPart;

    // Zero time = not set
    if (ft.dwLowDateTime == 0 && ft.dwHighDateTime == 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "  %s: (not set)", label);
        return;
    }

    // We can't use FileTimeToSystemTime in a BOF easily via DFR
    // So output raw FILETIME value and let operator convert
    BeaconPrintf(CALLBACK_OUTPUT, "  %s: 0x%08X%08X",
                 label, ft.dwHighDateTime, ft.dwLowDateTime);
}

/*
 * Get the logon type as a readable string.
 */
static const char* LogonTypeToString(ULONG logonType) {
    switch (logonType) {
        case LOGON_TYPE_INTERACTIVE:        return "Interactive";
        case LOGON_TYPE_NETWORK:            return "Network";
        case LOGON_TYPE_BATCH:              return "Batch";
        case LOGON_TYPE_SERVICE:            return "Service";
        case LOGON_TYPE_UNLOCK:             return "Unlock";
        case LOGON_TYPE_NETWORK_CLEARTEXT:  return "NetworkCleartext";
        case LOGON_TYPE_NEW_CREDENTIALS:    return "NewCredentials";
        case LOGON_TYPE_REMOTE_INTERACTIVE: return "RemoteInteractive";
        case LOGON_TYPE_CACHED_INTERACTIVE: return "CachedInteractive";
        default:                            return "Unknown";
    }
}
