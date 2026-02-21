/*
 * bofdefs.h - Dynamic Function Resolution for LSA Whisperer BOF
 * 
 * In BOFs, we can't link to DLLs normally. Instead we declare imports
 * using DECLSPEC_IMPORT with MODULE$FunctionName syntax.
 * The BOF loader resolves these at runtime.
 */
#pragma once

#include <windows.h>
#include <winternl.h>

/* ============================================================
 * SECUR32.DLL - LSA Client APIs (Core of LSA Whisperer)
 * ============================================================ */

// LSA Connection
DECLSPEC_IMPORT NTSTATUS NTAPI SECUR32$LsaConnectUntrusted(
    PHANDLE LsaHandle
);

DECLSPEC_IMPORT NTSTATUS NTAPI SECUR32$LsaDeregisterLogonProcess(
    HANDLE LsaHandle
);

// LSA Package Lookup & Call
DECLSPEC_IMPORT NTSTATUS NTAPI SECUR32$LsaLookupAuthenticationPackage(
    HANDLE LsaHandle,
    PVOID PackageName,     // PLSA_STRING
    PULONG AuthenticationPackage
);

DECLSPEC_IMPORT NTSTATUS NTAPI SECUR32$LsaCallAuthenticationPackage(
    HANDLE LsaHandle,
    ULONG AuthenticationPackage,
    PVOID ProtocolSubmitBuffer,
    ULONG SubmitBufferLength,
    PVOID* ProtocolReturnBuffer,
    PULONG ReturnBufferLength,
    PNTSTATUS ProtocolStatus
);

DECLSPEC_IMPORT NTSTATUS NTAPI SECUR32$LsaFreeReturnBuffer(
    PVOID Buffer
);

DECLSPEC_IMPORT NTSTATUS NTAPI SECUR32$LsaEnumerateLogonSessions(
    PULONG LogonSessionCount,
    PLUID* LogonSessionList
);

DECLSPEC_IMPORT NTSTATUS NTAPI SECUR32$LsaGetLogonSessionData(
    PLUID LogonId,
    PVOID* ppLogonSessionData  // PSECURITY_LOGON_SESSION_DATA
);

/* ============================================================
 * SECUR32.DLL - Privileged LSA Connection
 * (LsaRegisterLogonProcess lives in secur32/sspicli, NOT advapi32)
 * ============================================================ */

DECLSPEC_IMPORT NTSTATUS NTAPI SECUR32$LsaRegisterLogonProcess(
    PVOID LogonProcessName,    // PLSA_STRING
    PHANDLE LsaHandle,
    PVOID SecurityMode         // PLSA_OPERATIONAL_MODE
);

DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$OpenProcessToken(
    HANDLE ProcessHandle,
    DWORD DesiredAccess,
    PHANDLE TokenHandle
);

DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$LookupPrivilegeValueA(
    LPCSTR lpSystemName,
    LPCSTR lpName,
    PLUID lpLuid
);

DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$AdjustTokenPrivileges(
    HANDLE TokenHandle,
    BOOL DisableAllPrivileges,
    PVOID NewState,             // PTOKEN_PRIVILEGES
    DWORD BufferLength,
    PVOID PreviousState,
    PDWORD ReturnLength
);

DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$GetTokenInformation(
    HANDLE TokenHandle,
    TOKEN_INFORMATION_CLASS TokenInformationClass,
    LPVOID TokenInformation,
    DWORD TokenInformationLength,
    PDWORD ReturnLength
);

DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$ConvertSidToStringSidA(
    PSID Sid,
    LPSTR* StringSid
);

DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$LookupAccountSidA(
    LPCSTR lpSystemName,
    PSID Sid,
    LPSTR Name,
    LPDWORD cchName,
    LPSTR ReferencedDomainName,
    LPDWORD cchReferencedDomainName,
    PVOID peUse
);

/* ============================================================
 * KERNEL32.DLL - Memory, Process, String
 * ============================================================ */

DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$GetProcessHeap(void);
DECLSPEC_IMPORT LPVOID WINAPI KERNEL32$HeapAlloc(HANDLE, DWORD, SIZE_T);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$HeapFree(HANDLE, DWORD, LPVOID);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$GetCurrentProcess(void);
DECLSPEC_IMPORT DWORD  WINAPI KERNEL32$GetLastError(void);
DECLSPEC_IMPORT void   WINAPI KERNEL32$SetLastError(DWORD);
DECLSPEC_IMPORT DWORD  WINAPI KERNEL32$GetCurrentProcessId(void);
DECLSPEC_IMPORT void   NTAPI NTDLL$RtlZeroMemory(PVOID, SIZE_T);
DECLSPEC_IMPORT void   NTAPI NTDLL$RtlCopyMemory(PVOID, const VOID*, SIZE_T);
DECLSPEC_IMPORT void   NTAPI NTDLL$RtlFillMemory(PVOID, SIZE_T, BYTE);
DECLSPEC_IMPORT int    WINAPI KERNEL32$lstrlenA(LPCSTR);
DECLSPEC_IMPORT int    WINAPI KERNEL32$lstrlenW(LPCWSTR);
DECLSPEC_IMPORT LPSTR  WINAPI KERNEL32$lstrcpyA(LPSTR, LPCSTR);
DECLSPEC_IMPORT LPWSTR WINAPI KERNEL32$lstrcpyW(LPWSTR, LPCWSTR);
DECLSPEC_IMPORT int    WINAPI KERNEL32$lstrcmpA(LPCSTR, LPCSTR);
DECLSPEC_IMPORT int    WINAPI KERNEL32$lstrcmpiA(LPCSTR, LPCSTR);
DECLSPEC_IMPORT HLOCAL WINAPI KERNEL32$LocalFree(HLOCAL);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$CloseHandle(HANDLE);
DECLSPEC_IMPORT int    WINAPI KERNEL32$MultiByteToWideChar(UINT, DWORD, LPCCH, int, LPWSTR, int);
DECLSPEC_IMPORT int    WINAPI KERNEL32$WideCharToMultiByte(UINT, DWORD, LPCWCH, int, LPSTR, int, LPCCH, LPBOOL);

/* ============================================================
 * MSVCRT.DLL - C Runtime (used carefully in BOFs)
 * ============================================================ */

DECLSPEC_IMPORT int     MSVCRT$strcmp(const char*, const char*);
DECLSPEC_IMPORT int     MSVCRT$_stricmp(const char*, const char*);
DECLSPEC_IMPORT size_t  MSVCRT$strlen(const char*);
DECLSPEC_IMPORT size_t  MSVCRT$wcslen(const wchar_t*);
DECLSPEC_IMPORT char*   MSVCRT$strcpy(char*, const char*);
DECLSPEC_IMPORT char*   MSVCRT$strcat(char*, const char*);
DECLSPEC_IMPORT char*   MSVCRT$strncpy(char*, const char*, size_t);
DECLSPEC_IMPORT int     MSVCRT$sprintf(char*, const char*, ...);
DECLSPEC_IMPORT int     MSVCRT$_snprintf(char*, size_t, const char*, ...);
DECLSPEC_IMPORT void*   MSVCRT$memset(void*, int, size_t);
DECLSPEC_IMPORT void*   MSVCRT$memcpy(void*, const void*, size_t);
DECLSPEC_IMPORT int     MSVCRT$memcmp(const void*, const void*, size_t);
DECLSPEC_IMPORT unsigned long MSVCRT$strtoul(const char*, char**, int);
DECLSPEC_IMPORT int     MSVCRT$atoi(const char*);
DECLSPEC_IMPORT int     MSVCRT$_vsnprintf(char*, size_t, const char*, va_list);
DECLSPEC_IMPORT void*   MSVCRT$calloc(size_t, size_t);
DECLSPEC_IMPORT void    MSVCRT$free(void*);
DECLSPEC_IMPORT void*   MSVCRT$malloc(size_t);

/* ============================================================
 * NTDLL.DLL - NT Native API
 * ============================================================ */

DECLSPEC_IMPORT ULONG NTAPI NTDLL$RtlNtStatusToDosError(NTSTATUS);
DECLSPEC_IMPORT void  NTAPI NTDLL$RtlInitUnicodeString(PUNICODE_STRING, PCWSTR);
DECLSPEC_IMPORT void  NTAPI NTDLL$RtlInitAnsiString(PVOID, PCSTR);  // PANSI_STRING

/* ============================================================
 * Convenience Macros
 * ============================================================ */

// Heap allocation helpers
#define HEAP_ALLOC(size) KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, (size))
#define HEAP_FREE(ptr)   KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, (ptr))

// String helpers
#define STRLEN  MSVCRT$strlen
#define STRCMP   MSVCRT$strcmp
#define STRICMP MSVCRT$_stricmp
#define STRCPY  MSVCRT$strcpy
#define STRCAT  MSVCRT$strcat
#define MEMSET  MSVCRT$memset
#define MEMCPY  MSVCRT$memcpy
#define MEMCMP  MSVCRT$memcmp
#define SPRINTF MSVCRT$sprintf
#define SNPRINTF MSVCRT$_snprintf

// NTSTATUS helpers
#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif
#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS     ((NTSTATUS)0x00000000L)
#endif
