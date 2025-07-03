#include <stddef.h>
#include <stdio.h>
#include <wchar.h>
#include <windows.h>
#include <initguid.h>
#include <fwpmu.h>
#include <tlhelp32.h>

#define NtCurrentProcess      ( ( HANDLE ) (LONG_PTR ) -1 )
#define NtCurrentThread       ( ( HANDLE )( LONG_PTR ) -2 )

// 1D586097-0D5D-441B-9509-F30679DCB13B
DEFINE_GUID(
   FWPM_CUSTOM_SUBLAYER_UUID,
   0x1d586097,
   0x0d5d,
   0x441b,
   0x95, 0x09, 0xf3, 0x06, 0x79, 0xdc, 0xb1, 0x3b
);

// d78e1e87-8644-4ea5-9437-d809ecefc971
DEFINE_GUID(
   FWPM_CONDITION_ALE_APP_ID,
   0xd78e1e87,
   0x8644,
   0x4ea5,
   0x94, 0x37, 0xd8, 0x09, 0xec, 0xef, 0xc9, 0x71
);

// af043a0a-b34d-4f86-979c-c90371af6e66
DEFINE_GUID(
   FWPM_CONDITION_ALE_USER_ID,
   0xaf043a0a,
   0xb34d,
   0x4f86,
   0x97, 0x9c, 0xc9, 0x03, 0x71, 0xaf, 0x6e, 0x66
);
// c35a604d-d22b-4e1a-91b4-68f674ee674b
DEFINE_GUID(
   FWPM_CONDITION_IP_REMOTE_PORT,
   0xc35a604d,
   0xd22b,
   0x4e1a,
   0x91, 0xb4, 0x68, 0xf6, 0x74, 0xee, 0x67, 0x4b
);

DEFINE_GUID(
   FWPM_LAYER_OUTBOUND_TRANSPORT_V6,
   0xe1735bde,
   0x013f,
   0x4655,
   0xb3, 0x51, 0xa4, 0x9e, 0x15, 0x76, 0x2d, 0xf0
);

// b235ae9a-1d64-49b8-a44c-5ff3d9095045
DEFINE_GUID(
   FWPM_CONDITION_IP_REMOTE_ADDRESS,
   0xb235ae9a,
   0x1d64,
   0x49b8,
   0xa4, 0x4c, 0x5f, 0xf3, 0xd9, 0x09, 0x50, 0x45
);

// 0c1ba1af-5765-453f-af22-a8f791ac775b
DEFINE_GUID(
   FWPM_CONDITION_IP_LOCAL_PORT,
   0x0c1ba1af,
   0x5765,
   0x453f,
   0xaf, 0x22, 0xa8, 0xf7, 0x91, 0xac, 0x77, 0x5b
);

// c38d57d1-05a7-4c33-904f-7fbceee60e82
DEFINE_GUID(
   FWPM_LAYER_ALE_AUTH_CONNECT_V4,
   0xc38d57d1,
   0x05a7,
   0x4c33,
   0x90, 0x4f, 0x7f, 0xbc, 0xee, 0xe6, 0x0e, 0x82
);

// 09e61aea-d214-46e2-9b21-b26b0b2f28c8
DEFINE_GUID(
   FWPM_LAYER_OUTBOUND_TRANSPORT_V4,
   0x09e61aea,
   0xd214,
   0x46e2,
   0x9b, 0x21, 0xb2, 0x6b, 0x0b, 0x2f, 0x28, 0xc8
);

// 1247d66d-0b60-4a15-8d44-7155d0f53a0c
DEFINE_GUID(
   FWPM_LAYER_ALE_RESOURCE_ASSIGNMENT_V4,
   0x1247d66d,
   0x0b60,
   0x4a15,
   0x8d, 0x44, 0x71, 0x55, 0xd0, 0xf5, 0x3a, 0x0c
);

// af80470a-5596-4c13-9992-539e6fe57967
DEFINE_GUID(
   FWPM_LAYER_ALE_FLOW_ESTABLISHED_V4,
   0xaf80470a,
   0x5596,
   0x4c13,
   0x99, 0x92, 0x53, 0x9e, 0x6f, 0xe5, 0x79, 0x67
);

// 1e5c9fae-8a84-4135-a331-950b54229ecd
DEFINE_GUID(
   FWPM_LAYER_OUTBOUND_IPPACKET_V4,
   0x1e5c9fae,
   0x8a84,
   0x4135,
   0xa3, 0x31, 0x95, 0x0b, 0x54, 0x22, 0x9e, 0xcd
);

// 4a72393b-319f-44bc-84c3-ba54dcb3b6b4
DEFINE_GUID(
   FWPM_LAYER_ALE_AUTH_CONNECT_V6,
   0x4a72393b,
   0x319f,
   0x44bc,
   0x84, 0xc3, 0xba, 0x54, 0xdc, 0xb3, 0xb6, 0xb4
);

typedef enum ErrorCode {
    CUSTOM_SUCCESS = 0,
    CUSTOM_FILE_NOT_FOUND = 0x1,
    CUSTOM_MEMORY_ALLOCATION_ERROR = 0x2,
    CUSTOM_NULL_INPUT = 0x3,
    CUSTOM_DRIVE_NAME_NOT_FOUND = 0x4,
    CUSTOM_FAILED_TO_GET_DOS_DEVICE_NAME = 0x5,
} ErrorCode;

#define FWPM_FILTER_FLAG_PERSISTENT (0x00000001)
#define FWPM_PROVIDER_FLAG_PERSISTENT (0x00000001)
#define FWPM_SUBLAYER_FLAG_PERSISTENT       (0x00000001)
#define FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT (0x00000008)


// Fwpuclnt functions
typedef DWORD (WINAPI *__FwpmProviderAdd0)(
    HANDLE               engineHandle,
    const FWPM_PROVIDER0 *provider,
    PSECURITY_DESCRIPTOR sd
);
typedef DWORD (WINAPI *__FwpmFilterAdd0)(
    HANDLE               engineHandle,
    const FWPM_FILTER0   *filter,
    PSECURITY_DESCRIPTOR sd,
    UINT64               *id
);
typedef DWORD (WINAPI *__FwpmEngineOpen0)(
    const wchar_t             *serverName,
    UINT32                    authnService,
    SEC_WINNT_AUTH_IDENTITY_W *authIdentity,
    const FWPM_SESSION0       *session,
    HANDLE                    *engineHandle
);

typedef DWORD (WINAPI *__FwpmFilterGetById0)(
    HANDLE               engineHandle,
    UINT64               id,
    const FWPM_FILTER0   **filter
);

typedef DWORD (WINAPI *__FwpmEngineClose0)(HANDLE engineHandle);
typedef DWORD (WINAPI *__FwpmProviderCreateEnumHandle0)(
    HANDLE                             engineHandle,
    const FWPM_PROVIDER_ENUM_TEMPLATE0 *enumTemplate,
    HANDLE                             *enumHandle
);
typedef DWORD (WINAPI *__FwpmProviderDestroyEnumHandle0)(HANDLE engineHandle, HANDLE enumHandle);
typedef DWORD (WINAPI *__FwpmFilterCreateEnumHandle0)(
    HANDLE                           engineHandle,
    const FWPM_FILTER_ENUM_TEMPLATE0 *enumTemplate,
    HANDLE                           *enumHandle
);
typedef DWORD (WINAPI *__FwpmFilterDestroyEnumHandle0)(HANDLE engineHandle, HANDLE enumHandle);
typedef DWORD (WINAPI *__FwpmProviderEnum0)(
    HANDLE         engineHandle,
    HANDLE         enumHandle,
    UINT32         numEntriesRequested,
    FWPM_PROVIDER0 ***entries,
    UINT32         *numEntriesReturned
);
typedef DWORD (WINAPI *__FwpmFilterEnum0)(
    HANDLE       engineHandle,
    HANDLE       enumHandle,
    UINT32       numEntriesRequested,
    FWPM_FILTER0 ***entries,
    UINT32       *numEntriesReturned
);

typedef DWORD (WINAPI *__FwpmGetAppIdFromFileName0)(
    const wchar_t*       fileName,
    FWP_BYTE_BLOB **appId
);

typedef DWORD (WINAPI *__FwpmSubLayerAdd0)(
  HANDLE               engineHandle,
  const FWPM_SUBLAYER0 *subLayer,
  PSECURITY_DESCRIPTOR sd
);

typedef DWORD (WINAPI *__FwpmProviderDeleteByKey0)(HANDLE engineHandle, const GUID *key);
typedef DWORD (WINAPI *__FwpmFilterDeleteById0)(HANDLE engineHandle, UINT64 id);
typedef void (WINAPI *__FwpmFreeMemory0)(void **p);

__FwpmProviderAdd0 _FwpmProviderAdd0 = NULL;
__FwpmFilterAdd0 _FwpmFilterAdd0 = NULL;
__FwpmEngineOpen0 _FwpmEngineOpen0 = NULL;
__FwpmFilterGetById0 _FwpmFilterGetById0 = NULL;
__FwpmEngineClose0 _FwpmEngineClose0 = NULL;
__FwpmProviderCreateEnumHandle0 _FwpmProviderCreateEnumHandle0 = NULL;
__FwpmProviderDestroyEnumHandle0 _FwpmProviderDestroyEnumHandle0 = NULL;
__FwpmFilterCreateEnumHandle0 _FwpmFilterCreateEnumHandle0 = NULL;
__FwpmFilterDestroyEnumHandle0 _FwpmFilterDestroyEnumHandle0 = NULL;
__FwpmProviderEnum0 _FwpmProviderEnum0 = NULL;
__FwpmFilterEnum0 _FwpmFilterEnum0 = NULL;
__FwpmProviderDeleteByKey0 _FwpmProviderDeleteByKey0 = NULL;
__FwpmFilterDeleteById0 _FwpmFilterDeleteById0 = NULL;
__FwpmFreeMemory0 _FwpmFreeMemory0 = NULL;
__FwpmGetAppIdFromFileName0 _FwpmGetAppIdFromFileName0 = NULL;
__FwpmSubLayerAdd0 _FwpmSubLayerAdd0 = NULL;

BOOL InitFWPM(){
    HMODULE fwpuclnt = KERNEL32$LoadLibraryA("Fwpuclnt.dll");
    if (!fwpuclnt){
        err("LoadLibraryA failed: 0x%lx.\n", KERNEL32$GetLastError());
        return FALSE;
    }
    _FwpmProviderAdd0 = (__FwpmProviderAdd0)KERNEL32$GetProcAddress(fwpuclnt, "FwpmProviderAdd0");
    _FwpmFilterAdd0 = (__FwpmFilterAdd0)KERNEL32$GetProcAddress(fwpuclnt, "FwpmFilterAdd0");
    _FwpmEngineOpen0 = (__FwpmEngineOpen0)KERNEL32$GetProcAddress(fwpuclnt, "FwpmEngineOpen0");
    _FwpmFilterGetById0 = (__FwpmFilterGetById0)KERNEL32$GetProcAddress(fwpuclnt, "FwpmFilterGetById0");
    _FwpmEngineClose0 = (__FwpmEngineClose0)KERNEL32$GetProcAddress(fwpuclnt, "FwpmEngineClose0");
    _FwpmProviderCreateEnumHandle0 = (__FwpmProviderCreateEnumHandle0)KERNEL32$GetProcAddress(fwpuclnt, "FwpmProviderCreateEnumHandle0");
    _FwpmProviderDestroyEnumHandle0 = (__FwpmProviderDestroyEnumHandle0)KERNEL32$GetProcAddress(fwpuclnt, "FwpmProviderDestroyEnumHandle0");
    _FwpmFilterCreateEnumHandle0 = (__FwpmFilterCreateEnumHandle0)KERNEL32$GetProcAddress(fwpuclnt, "FwpmFilterCreateEnumHandle0");
    _FwpmFilterDestroyEnumHandle0 = (__FwpmFilterDestroyEnumHandle0)KERNEL32$GetProcAddress(fwpuclnt, "FwpmFilterDestroyEnumHandle0");
    _FwpmProviderEnum0 = (__FwpmProviderEnum0)KERNEL32$GetProcAddress(fwpuclnt, "FwpmProviderEnum0");
    _FwpmFilterEnum0 = (__FwpmFilterEnum0)KERNEL32$GetProcAddress(fwpuclnt, "FwpmFilterEnum0");
    _FwpmProviderDeleteByKey0 = (__FwpmProviderDeleteByKey0)KERNEL32$GetProcAddress(fwpuclnt, "FwpmProviderDeleteByKey0");
    _FwpmFilterDeleteById0 = (__FwpmFilterDeleteById0)KERNEL32$GetProcAddress(fwpuclnt, "FwpmFilterDeleteById0");
    _FwpmFreeMemory0 = (__FwpmFreeMemory0)KERNEL32$GetProcAddress(fwpuclnt, "FwpmFreeMemory0");
    _FwpmGetAppIdFromFileName0 = (__FwpmGetAppIdFromFileName0)KERNEL32$GetProcAddress(fwpuclnt, "FwpmGetAppIdFromFileName0");
    _FwpmSubLayerAdd0 = (__FwpmSubLayerAdd0)KERNEL32$GetProcAddress(fwpuclnt, "FwpmSubLayerAdd0");

    return TRUE;
}

INT StringCompareA( _In_ LPCSTR String1, _In_ LPCSTR String2 )
{
    for ( ; *String1 == *String2; String1++, String2++ )
    {
        if ( *String1 == '\0' )
        {
            return 0;
        };
    };
    return ( ( *( LPCSTR )String1 < *( LPCSTR )String2 ) ? -1 : +1 );
};

INT StringCompareW(_In_ LPCWSTR String1, _In_ LPCWSTR String2)
{
    for (; *String1 == *String2; String1++, String2++)
    {
        if (*String1 == '\0')
            return 0;
    }

    return ((*(LPCWSTR)String1 < *(LPCWSTR)String2) ? -1 : +1);
}

SIZE_T StringLengthW(_In_ LPCWSTR String)
{
    LPCWSTR String2;

    for (String2 = String; *String2; ++String2);

    return (String2 - String);
}

PVOID CopyMemoryEx(_Inout_ PVOID Destination, _In_ CONST PVOID Source, _In_ SIZE_T Length)
{
    PBYTE D = (PBYTE)Destination;
    PBYTE S = (PBYTE)Source;

    while (Length--)
        *D++ = *S++;

    return Destination;
}

PWCHAR StringCopyW(_Inout_ PWCHAR String1, _In_ LPCWSTR String2, INT count)
{
    PWCHAR p = String1;
    INT i = 0;
    while ( i <= count && (*p++ = *String2++) != 0){
        i++;
    }

    return String1;
}

PWCHAR ToLower(_In_ PWCHAR Ptr)
{
    PWCHAR sv = Ptr;
    while (*sv != '\0')
    {
        if (*sv >= 'A' && *sv <= 'Z')
            *sv = *sv + ('a' - 'A');

        sv++;
    }
    return Ptr;
}

PWCHAR StringLocateCharW(_Inout_ PCWSTR String, _In_ INT Character)
{
    do
    {
        if (*String == Character)
            return (PWCHAR)String;

    } while (*String++);

    return NULL;
}

UINT64 StringToUINT64(const char *str, char **endptr, int base) {
    unsigned long long result = 0;
    int digit;

    // Skip leading white-space characters
    while (*str == ' ' || (*str >= '\t' && *str <= '\r')) {
        str++;
    }

    // Determine the base if not specified
    if (base == 0) {
        if (*str == '0') {
            base = (*(str + 1) == 'x' || *(str + 1) == 'X') ? 16 : 8;
        } else {
            base = 10;
        }
    }

    // Handle hexadecimal prefix if present
    if (base == 16 && *str == '0' && (*(str + 1) == 'x' || *(str + 1) == 'X')) {
        str += 2;
    }

    // Process digits
    while ((digit = *str - '0') >= 0) {
        if (digit > base) {
            break;  // Invalid digit for the base
        }
        result = result * base + digit;
        str++;
    }

    // Set endptr if provided
    if (endptr != NULL) {
        *endptr = (char*)str;
    }

    return result;
}

/*
s1 and s2 are the string sizes NOT counting terminating NULL, dstSz is the TOTAL destination string size, including termination
*/
BOOL StringConcatW(PWCHAR dest, size_t dstSz, PCWSTR str1, size_t s1, PCWSTR str2, size_t s2){
    if (s1 > StringLengthW(str1) || s2 > StringLengthW(str2) || dstSz < s1 + s2 + 1){
        //printf("bad input string size\n");
        return FALSE;
    }
    for (int i = 0; i < s1; i++){
        dest[i] = str1[i];
    }
    for (int i = 0; i < s2; i++){
        dest[s1+i] = str2[i];
    }
    dest[dstSz-1] = '\0';
    return TRUE;
}

BOOL CheckProcessIntegrityLevel() {
    HANDLE hToken = NULL;
    DWORD dwLength = 0;
    PTOKEN_MANDATORY_LABEL pTIL = NULL;
    DWORD dwIntegrityLevel = 0;
    BOOL isHighIntegrity = FALSE;

    if (!ADVAPI32$OpenThreadToken(NtCurrentThread, TOKEN_QUERY, TRUE, &hToken)) {
        if (KERNEL32$GetLastError() != ERROR_NO_TOKEN) {
            err("OpenThreadToken failed with error code: 0x%lx.\n", KERNEL32$GetLastError());
            return FALSE;
        }

        if (!ADVAPI32$OpenProcessToken(NtCurrentProcess, TOKEN_QUERY, &hToken)) {
            err("OpenProcessToken failed with error code: 0x%lx.\n", KERNEL32$GetLastError());
            return FALSE;
        }
    }

    // Get the size of the integrity level information
    if (!ADVAPI32$GetTokenInformation(hToken, TokenIntegrityLevel, NULL, 0, &dwLength) && 
        KERNEL32$GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
        err("GetTokenInformation failed with error code: 0x%lx.\n", KERNEL32$GetLastError());
        KERNEL32$CloseHandle(hToken);
        return FALSE;
    }

    pTIL = (PTOKEN_MANDATORY_LABEL)KERNEL32$LocalAlloc(LPTR, dwLength);
    if (pTIL == NULL) {
        err("LocalAlloc failed with error code: 0x%lx.\n", KERNEL32$GetLastError());
        KERNEL32$CloseHandle(hToken);
        return FALSE;
    }

    if (!ADVAPI32$GetTokenInformation(hToken, TokenIntegrityLevel, pTIL, dwLength, &dwLength)) {
        err("GetTokenInformation failed with error code: 0x%lx.\n", KERNEL32$GetLastError());
        KERNEL32$LocalFree(pTIL);
        KERNEL32$CloseHandle(hToken);
        return FALSE;
    }

    dwIntegrityLevel = *ADVAPI32$GetSidSubAuthority(pTIL->Label.Sid, (DWORD)(UCHAR)(*ADVAPI32$GetSidSubAuthorityCount(pTIL->Label.Sid) - 1));

    if (dwIntegrityLevel >= SECURITY_MANDATORY_HIGH_RID) {
        isHighIntegrity = TRUE;
    } else {
        err("This program requires to run in high integrity level.\n");
    }

    KERNEL32$LocalFree(pTIL);
    KERNEL32$CloseHandle(hToken);
    return isHighIntegrity;
}

// Enable SeDebugPrivilege to obtain full path of running processes
BOOL EnableSeDebugPrivilege() {
	HANDLE hToken = NULL;
	TOKEN_PRIVILEGES tokenPrivileges = {0};
	
    if (!ADVAPI32$OpenThreadToken(NtCurrentThread, TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, TRUE, &hToken)) {
        if (KERNEL32$GetLastError() != ERROR_NO_TOKEN) {
            err("OpenThreadToken failed with error code: 0x%lx.\n", KERNEL32$GetLastError());
            return FALSE;
        }

        if (!ADVAPI32$OpenProcessToken(NtCurrentProcess, TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &hToken)) {
            err("OpenProcessToken failed with error code: 0x%lx.\n", KERNEL32$GetLastError());
            return FALSE;
        }
    }

	if (!ADVAPI32$LookupPrivilegeValueA(NULL, "SeDebugPrivilege", &tokenPrivileges.Privileges[0].Luid)){
        err("LookupPrivilegeValueA failed with error code: 0x%lx.\n", KERNEL32$GetLastError());
		KERNEL32$CloseHandle(hToken);
		return FALSE;
	}

	tokenPrivileges.PrivilegeCount = 1;
	tokenPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	if (!ADVAPI32$AdjustTokenPrivileges(hToken, FALSE, &tokenPrivileges, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
        err("AdjustTokenPrivileges failed with error code: 0x%lx.\n", KERNEL32$GetLastError());
		KERNEL32$CloseHandle(hToken);
		return FALSE;
	}

    if (KERNEL32$GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
        err("Failed to get SeDebugPrivilege. You might not be able to get the process handle of the EDR process.\n");
		KERNEL32$CloseHandle(hToken);
		return FALSE;
    }

	KERNEL32$CloseHandle(hToken);
	return TRUE;
}

void CharArrayToWCharArray(const char charArray[], WCHAR wCharArray[], size_t wCharArraySize) {
    int result = KERNEL32$MultiByteToWideChar(CP_UTF8, 0, charArray, -1, wCharArray, wCharArraySize);

    if (result == 0) {
        err("MultiByteToWideChar failed with error code: 0x%lx.\n", KERNEL32$GetLastError());
        wCharArray[0] = L'\0';
    }
}

BOOL GetDriveName(PCWSTR filePath, wchar_t* driveName, size_t driveNameSize) {
    if (!filePath) {
        return FALSE;
    }
    const wchar_t *colon = StringLocateCharW(filePath, L':');
    if (colon && (colon - filePath + 1) < driveNameSize) {
        StringCopyW(driveName, filePath, colon - filePath + 1);
        driveName[colon - filePath + 1] = L'\0';
        return TRUE;
    } else {
        return FALSE;
    }
}

#define MAX_DRIVE_PATH 100
ErrorCode ConvertToNtPath(PCWSTR filePath, wchar_t* ntPathBuffer, size_t bufferSize) {
    WCHAR driveName[10];
    WCHAR ntDrivePath[MAX_DRIVE_PATH];
    if (!filePath || !ntPathBuffer) {
        return CUSTOM_NULL_INPUT;
    }

    if (!GetDriveName(filePath, driveName, sizeof(driveName) / sizeof(WCHAR))) {
        return CUSTOM_DRIVE_NAME_NOT_FOUND;
    }

    if (KERNEL32$QueryDosDeviceW(driveName, ntDrivePath, sizeof(ntDrivePath) / sizeof(WCHAR)) == 0) {
        return CUSTOM_FAILED_TO_GET_DOS_DEVICE_NAME;
    }

    //MSVCRT$swprintf(ntPathBuffer, bufferSize, L"%S%S", ntDrivePath, filePath + StringLengthW(driveName));
    size_t pathLen = StringLengthW(filePath) - StringLengthW(driveName);
    size_t ntDrivePathLen = StringLengthW(ntDrivePath);
    if (!StringConcatW(ntPathBuffer, bufferSize, ntDrivePath, ntDrivePathLen, filePath + StringLengthW(driveName), pathLen)){
        return CUSTOM_MEMORY_ALLOCATION_ERROR;
    }

    ntPathBuffer = ToLower(ntPathBuffer);
    //for (size_t i = 0; ntPathBuffer[i] != L'\0'; ++i) {
    //    ntPathBuffer[i] = towlower(ntPathBuffer[i]);
    //}
    ntPathBuffer[ntDrivePathLen + pathLen] = L'\0';
    return CUSTOM_SUCCESS;
}

BOOL FileExists(PCWSTR filePath) {
    if (!filePath) {
        return FALSE;
    }

    DWORD fileAttrib = KERNEL32$GetFileAttributesW(filePath);
    if (fileAttrib == INVALID_FILE_ATTRIBUTES) {
        return FALSE;
    }

    return TRUE;
}

ErrorCode CustomFwpmGetAppIdFromFileName0(PCWSTR filePath, FWP_BYTE_BLOB** appId) {
    if (!FileExists(filePath)) {
        return CUSTOM_FILE_NOT_FOUND;
    }

    WCHAR ntPath[MAX_PATH+MAX_DRIVE_PATH+1];
    ErrorCode errorCode = ConvertToNtPath(filePath, ntPath, MAX_PATH);

    if (errorCode != CUSTOM_SUCCESS) {
        return errorCode;
    }
    *appId = (FWP_BYTE_BLOB*)intAlloc(sizeof(FWP_BYTE_BLOB));
    if (!*appId) {
        return CUSTOM_MEMORY_ALLOCATION_ERROR;
    }

    (*appId)->size = StringLengthW(ntPath) * sizeof(WCHAR) + sizeof(WCHAR);
    
    (*appId)->data = (UINT8*)intAlloc((*appId)->size);
    if (!(*appId)->data) {
        intFree(*appId);
        return CUSTOM_MEMORY_ALLOCATION_ERROR;
    }
    CopyMemoryEx((*appId)->data, ntPath, (*appId)->size);
    return CUSTOM_SUCCESS;
}

void FreeAppId(FWP_BYTE_BLOB* appId) {
    if (appId) {
        if (appId->data) {
            intFree(appId->data);
        }
        intFree(appId);
    }
}

// Get provider GUID by description
BOOL GetProviderGUIDByDescription(PCWSTR providerDescription, GUID* outProviderGUID) {
    DWORD result = 0;
    HANDLE hEngine = NULL;
    HANDLE enumHandle = NULL;
    FWPM_PROVIDER0** providers = NULL;
    UINT32 numProviders = 0;

    result = _FwpmEngineOpen0(NULL, RPC_C_AUTHN_DEFAULT, NULL, NULL, &hEngine);
    if (result != ERROR_SUCCESS) {
        err("FwpmEngineOpen0 failed with error code: 0x%lx.\n", result);
        return FALSE;
    }

    result = _FwpmProviderCreateEnumHandle0(hEngine, NULL, &enumHandle);
    if (result != ERROR_SUCCESS) {
        err("FwpmProviderCreateEnumHandle0 failed with error code: 0x%lx.\n", result);
        _FwpmEngineClose0(hEngine);
        return FALSE;
    }

    result = _FwpmProviderEnum0(hEngine, enumHandle, 100, &providers, &numProviders);
    if (result != ERROR_SUCCESS) {
        err("FwpmProviderEnum0 failed with error code: 0x%lx.\n", result);
        _FwpmEngineClose0(hEngine);
        return FALSE;
    }

    for (UINT32 i = 0; i < numProviders; i++) {
        if (providers[i]->displayData.description != NULL) {
            if (StringCompareW(providers[i]->displayData.description, providerDescription) == 0) {
                *outProviderGUID = providers[i]->providerKey;
                return TRUE;
            }
        }   
    }

    if (providers) {
        _FwpmFreeMemory0((void**)&providers);
    }

    _FwpmProviderDestroyEnumHandle0(hEngine, enumHandle);
    _FwpmEngineClose0(hEngine);
    return FALSE;
}