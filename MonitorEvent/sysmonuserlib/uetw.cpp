#include <winsock2.h>
#include <IPTypes.h>
#include <iphlpapi.h>
#include <WS2tcpip.h>
#include <Windows.h>
#include <memory>
#include <Psapi.h>
#include <tdh.h>
#include <in6addr.h>
#include <sysinfo.h>
#include <map>
#include <mutex>
#include <vector>
#include <queue>
#include <string>
#include <wchar.h>
#include <direct.h>
#include <memory>
#include <sstream>

#include "sync.h"
#include "uetw.h"

#pragma comment(lib, "Tdh.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "Ws2_32.lib")
using namespace std;

// Etw Event Manage Session - Guid - tracconfig
typedef struct _TracGuidNode
{
    DWORD                        event_tracid;
    EVENT_TRACE_PROPERTIES* bufconfig;
}TracGuidNode, * PTracGuidNode;

// mutex
static std::mutex                       g_ms;
static map<TRACEHANDLE, TracGuidNode>   g_tracMap;
static std::mutex                       g_th;
static vector<HANDLE>                   g_thrhandle;

// Process Event_Notify
static std::function<void(const PROCESSINFO&)> g_OnProcessNotify = nullptr;

// [Guid File Logger] Event File Logger
static const wchar_t SESSION_NAME_FILE[] = L"HadesEtwTrace";
static EVENT_TRACE_PROPERTIES g_traceConfigNode;
typedef struct _TraceConfig {
    EVENT_TRACE_PROPERTIES trace_propertise;
    std::wstring session_name;
    std::wstring filelog_path;

    _TraceConfig() {
        RtlSecureZeroMemory(&trace_propertise, sizeof(EVENT_TRACE_PROPERTIES));
        session_name.clear();
        filelog_path.clear();
    }
}TraceConfig, * pTraceConfig;
static TraceConfig g_pTraceConfig;

// Write Read Offset Filter
static std::mutex g_FileReadLock;
static std::map<UINT64, UINT64> g_etwFileReadFilter;

static std::mutex g_FileWriteLock;
static std::map<UINT64, UINT64> g_etwFileWriteilter;

static std::mutex g_FileDirEnumLock;
static std::map<UINT64, UINT64> g_etwFileDirEnumFilter;

// Report Task Queue_buffer ptr
static std::queue<UPubNode*>* g_EtwQueue_Ptr = nullptr;
static std::mutex* g_EtwQueueCs_Ptr = nullptr;
static HANDLE                         g_JobQueue_Event = nullptr;
static bool                           g_EtwEventExit = false;
static TRACEHANDLE                    g_ProcessTracehandle = 0;

// File - Microsoft-Windows-Kernel-File
const GUID FileProviderGuid =
{ 0xedd08927, 0x9cc4, 0x4e65, {0xb9, 0x70, 0xc2, 0x56, 0x0f, 0xb5, 0xc2, 0x89} };
// Register - Microsoft-Windows-Kernel-Registry
const GUID RegistryProviderGuid =
{ 0x70eb4f03, 0xc1de, 0x4f74, {0xa8, 0x0c, 0x18, 0x65, 0x5f, 0x2b, 0x8c, 0x8b} };
// Process
const GUID ProcessProviderGuid =
{ 0x22fb2cd6, 0x0e7b, 0x422b, {0xa0, 0xc7, 0x2f, 0xad, 0x1f, 0xd0, 0xe7, 0x16} };
// Dns
static const GUID DnsClientWin7Guid =
{ 0x609151dd, 0x4f5, 0x4da7, { 0x97, 0x4c, 0xfc, 0x69, 0x47, 0xea, 0xa3, 0x23 } };
static const GUID DnsClientGuid =
{ 0x1c95126e, 0x7eea, 0x49a9, { 0xa3, 0xfe, 0xa3, 0x78, 0xb0, 0x3d, 0xdb, 0x4d } };

// Struct Size
static int g_EtwNetworkDataLens = 0;
static int g_EtwProcessDataLens = 0;
static int g_EtwThreadDataLens = 0;
static int g_EtwImageDataLens = 0;
static int g_EtwRegtabDataLens = 0;
static int g_EtwFileIoDataLens = 0;

const char* newGUID()
{
    try
    {
        GUID guid;
        char cBuf[64] = { 0, };
        if (S_OK == ::CoCreateGuid(&guid))
        {
            _snprintf(cBuf, sizeof(cBuf), "{%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
                guid.Data1, guid.Data2, guid.Data3,
                guid.Data4[0], guid.Data4[1], guid.Data4[2], guid.Data4[3],
                guid.Data4[4], guid.Data4[5], guid.Data4[6], guid.Data4[7]);
        }
        return cBuf;
    }
    catch (const std::exception&)
    {
        return "";
    }
}

void Wchar_tToString(std::string& szDst, const wchar_t* wchar)
{
    if (!wchar) {
        szDst = " ";
        return;
    }

    try
    {
        if (lstrlenW(wchar) <= 0)
        {
            szDst = " ";
            return;
        }
        const wchar_t* wText = wchar;
        DWORD dwNum = WideCharToMultiByte(CP_ACP, 0, wText, -1, NULL, 0, NULL, FALSE);
        if (dwNum <= 0)
        {
            szDst = " ";
            return;
        }
        char* psText = nullptr;
        psText = (char*)new char[dwNum + 1];
        if (psText)
        {
            WideCharToMultiByte(CP_ACP, 0, wText, -1, psText, dwNum, NULL, FALSE);
            psText[dwNum - 1] = 0;
            szDst = psText;
            delete[] psText;
        }
    }
    catch (const std::exception&)
    {
    }
}

DWORD GetPathByProcessId(wchar_t* path, const  DWORD dwPid)
{
    const HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPid);
    if (hProcess == NULL)
        return false;
    const DWORD dwRet = GetModuleFileNameEx(hProcess, NULL, path, MAX_PATH);
    if (hProcess)
        CloseHandle(hProcess);
    return dwRet;
}

DWORD uf_GetNetWrokEventStr(wstring& propName)
{
    DWORD Code = 0;

    // Ipv4/v6
    if (0 == lstrcmpW(propName.c_str(), L"PID"))
        Code = 1;
    else if (0 == lstrcmpW(propName.c_str(), L"size"))
        Code = 2;
    else if (0 == lstrcmpW(propName.c_str(), L"daddr"))
        Code = 3;
    else if (0 == lstrcmpW(propName.c_str(), L"saddr"))
        Code = 4;
    else if (0 == lstrcmpW(propName.c_str(), L"dport"))
        Code = 5;
    else if (0 == lstrcmpW(propName.c_str(), L"sport"))
        Code = 6;
    else if (0 == lstrcmpW(propName.c_str(), L"seqnum"))
        Code = 7;
    else if (0 == lstrcmpW(propName.c_str(), L"connid"))
        Code = 8;
    else if (0 == lstrcmpW(propName.c_str(), L"size"))
        Code = 9;
    else if (0 == lstrcmpW(propName.c_str(), L"startime"))
        Code = 10;
    else if (0 == lstrcmpW(propName.c_str(), L"endtime"))
        Code = 11;
    return Code;
}

std::wstring SockAddrToWString(const SOCKADDR_STORAGE* addr) {
    char ipStr[INET6_ADDRSTRLEN] = { 0 };
    std::wstring result;

    if (addr->ss_family == AF_INET) {
        inet_ntop(AF_INET, &((const SOCKADDR_IN*)addr)->sin_addr,
            ipStr, sizeof(ipStr));
        result = std::wstring(ipStr, ipStr + strlen(ipStr));
    }
    else if (addr->ss_family == AF_INET6) {
        inet_ntop(AF_INET6, &((const SOCKADDR_IN6*)addr)->sin6_addr,
            ipStr, sizeof(ipStr));
        result = std::wstring(ipStr, ipStr + strlen(ipStr));
    }
    else if (addr->ss_family == 0x31) {  // AF_NETBIOS
        PIP_ADAPTER_ADDRESSES adapterInfo = nullptr;
        ULONG bufLen = 0;
        DWORD ret = GetAdaptersAddresses(AF_UNSPEC, 0, nullptr, nullptr, &bufLen);
        if (ret == ERROR_BUFFER_OVERFLOW) {
            adapterInfo = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(malloc(bufLen));
            ret = GetAdaptersAddresses(AF_UNSPEC, 0, nullptr, adapterInfo, &bufLen);
        }

        if (ret == ERROR_SUCCESS) {
            for (auto adapter = adapterInfo; adapter; adapter = adapter->Next) {
                if (adapter->IfIndex == reinterpret_cast<const SOCKADDR_IN*>(addr)->sin_addr.S_un.S_addr) {
                    wchar_t wbuf[256];
                    swprintf_s(wbuf, L"[NetBIOS] %s", adapter->FriendlyName);
                    result = wbuf;
                    break;
                }
            }
        }

        if (adapterInfo) free(adapterInfo);
    }
    else {
        wchar_t wbuf[64];
        swprintf_s(wbuf, L"Unknown family: 0x%X", addr->ss_family);
        result = wbuf;
    }
    return result;
}

// [Guid File Logger] File Log Event
void WINAPI ProcessDnsEvent(PEVENT_RECORD rec) {
    if (rec == nullptr)
        return;
    try {
        ULONG bufferSize = 0;
        TdhGetEventInformation(rec, 0, nullptr, nullptr, &bufferSize);
        auto buffer = std::make_unique<BYTE[]>(bufferSize);
        auto info = reinterpret_cast<TRACE_EVENT_INFO*>(buffer.get());

        if (TdhGetEventInformation(rec, 0, nullptr, info, &bufferSize) != ERROR_SUCCESS)
            return;

        // ��ȡ������Ϣ
        ULONG processId = rec->EventHeader.ProcessId;
        wchar_t processPath[MAX_PATH] = L"";
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processId);
        if (hProcess) {
            DWORD size = MAX_PATH;
            QueryFullProcessImageNameW(hProcess, 0, processPath, &size);
            CloseHandle(hProcess);
        }
        else {
            wcscpy_s(processPath, L"Unknown");
        }

        // ��ʼ�� DNS ��Ϣ�ṹ
        _UEwtDns DnsInfo;
        DnsInfo.clear();
        DnsInfo.processId = processId;
        DnsInfo.processPath = processPath;

        // ��ȡ�¼�����
        for (DWORD i = 0; i < info->TopLevelPropertyCount; i++) {
            PROPERTY_DATA_DESCRIPTOR desc;
            wchar_t propName[128] = { 0 };

            if (info->EventPropertyInfoArray[i].NameOffset) {
                wcscpy_s(propName, reinterpret_cast<wchar_t*>(
                    reinterpret_cast<BYTE*>(info) + info->EventPropertyInfoArray[i].NameOffset));

                DnsInfo.EventName = propName;
                desc.PropertyName = reinterpret_cast<ULONGLONG>(propName);
                desc.ArrayIndex = ULONG_MAX;

                // ͨ����ֵ���Դ���
                auto SetNumericField = [&](auto& field, ULONG size) {
                    ULONG value;
                    if (TdhGetProperty(rec, 0, nullptr, 1, &desc, size, (PBYTE)&value) == ERROR_SUCCESS) {
                        field = std::to_wstring(value);
                    }
                };

                // �ַ������Դ���
                auto SetStringField = [&](std::wstring& field) {
                    ULONG size = 0;
                    if (TdhGetPropertySize(rec, 0, nullptr, 1, &desc, &size) == ERROR_SUCCESS) {
                        if (size > 0) {
                            auto buffer = std::make_unique<BYTE[]>(size);
                            if (TdhGetProperty(rec, 0, nullptr, 1, &desc, size, buffer.get()) == ERROR_SUCCESS) {
                                if (info->EventPropertyInfoArray[i].nonStructType.InType == TDH_INTYPE_UNICODESTRING) {
                                    field = std::wstring(reinterpret_cast<wchar_t*>(buffer.get()), size / sizeof(wchar_t));
                                }
                                else {
                                    // ���� ANSI �ַ���
                                    std::string ansiStr(reinterpret_cast<char*>(buffer.get()), size);
                                    field = std::wstring(ansiStr.begin(), ansiStr.end());
                                }
                            }
                        }
                    }
                };

                // ��ַ���Դ���
                auto SetAddressField = [&](std::wstring& field) {
                    SOCKADDR_STORAGE addr = { 0 };
                    if (TdhGetProperty(rec, 0, nullptr, 1, &desc, sizeof(addr), (PBYTE)&addr) == ERROR_SUCCESS) {
                        field = SockAddrToWString(&addr);
                    }
                };

                // ��ַ���鴦��
                auto SetAddressArrayField = [&](std::wstring& field) {
                    ULONG size = 0;
                    if (TdhGetPropertySize(rec, 0, nullptr, 1, &desc, &size) == ERROR_SUCCESS) {
                        if (size > 0) {
                            auto buffer = std::make_unique<BYTE[]>(size);
                            if (TdhGetProperty(rec, 0, nullptr, 1, &desc, size, buffer.get()) == ERROR_SUCCESS) {
                                DWORD elementCount = size / sizeof(SOCKADDR_STORAGE);
                                auto servers = reinterpret_cast<SOCKADDR_STORAGE*>(buffer.get());

                                std::wstringstream ss;
                                for (DWORD j = 0; j < elementCount; j++) {
                                    if (j > 0) ss << L", ";
                                    ss << SockAddrToWString(&servers[j]);
                                }
                                field = ss.str();
                            }
                        }
                    }
                };

                // ���������������ֶ�
                if (wcscmp(propName, L"QueryName") == 0 || wcscmp(propName, L"Name") == 0) {
                    SetStringField(DnsInfo.QueryName);
                }
                else if (wcscmp(propName, L"QueryType") == 0) {
                    SetNumericField(DnsInfo.QueryType, sizeof(USHORT));
                }
                else if (wcscmp(propName, L"QueryOptions") == 0) {
                    SetNumericField(DnsInfo.QueryOptions, sizeof(ULONG));
                }
                else if (wcscmp(propName, L"IsNetworkQuery") == 0) {
                    SetNumericField(DnsInfo.IsNetworkQuery, sizeof(BOOLEAN));
                }
                else if (wcscmp(propName, L"NetworkQueryIndex") == 0) {
                    SetNumericField(DnsInfo.NetworkQueryIndex, sizeof(ULONG));
                }
                else if (wcscmp(propName, L"InterfaceIndex") == 0) {
                    SetNumericField(DnsInfo.InterfaceIndex, sizeof(ULONG));
                }
                else if (wcscmp(propName, L"IsAsyncQuery") == 0) {
                    SetNumericField(DnsInfo.IsAsyncQuery, sizeof(BOOLEAN));
                }
                else if (wcscmp(propName, L"QueryStatus") == 0) {
                    SetNumericField(DnsInfo.QueryStatus, sizeof(ULONG));
                }
                else if (wcscmp(propName, L"QueryResults") == 0) {
                    SetStringField(DnsInfo.QueryResults);
                }
                else if (wcscmp(propName, L"IsParallelNetworkQuery") == 0) {
                    SetNumericField(DnsInfo.IsParallelNetworkQuery, sizeof(BOOLEAN));
                }
                else if (wcscmp(propName, L"NetworkIndex") == 0) {
                    SetNumericField(DnsInfo.NetworkIndex, sizeof(ULONG));
                }
                else if (wcscmp(propName, L"InterfaceCount") == 0) {
                    SetNumericField(DnsInfo.InterfaceCount, sizeof(ULONG));
                }
                else if (wcscmp(propName, L"AdapterName") == 0) {
                    SetStringField(DnsInfo.AdapterName);
                }
                else if (wcscmp(propName, L"LocalAddress") == 0 || wcscmp(propName, L"Source") == 0) {
                    SetAddressField(DnsInfo.LocalAddress);
                }
                else if (wcscmp(propName, L"DNSServerAddress") == 0) {
                    SetAddressArrayField(DnsInfo.DNSServerAddress);
                }
                else if (wcscmp(propName, L"Status") == 0 || wcscmp(propName, L"Result") == 0) {
                    SetNumericField(DnsInfo.Status, sizeof(ULONG));
                }
                else if (wcscmp(propName, L"Interface") == 0) {
                    SetStringField(DnsInfo.Interface);
                }
                else if (wcscmp(propName, L"TotalServerCount") == 0) {
                    SetNumericField(DnsInfo.TotalServerCount, sizeof(ULONG));
                }
                else if (wcscmp(propName, L"Index") == 0) {
                    SetNumericField(DnsInfo.Index, sizeof(ULONG));
                }
                else if (wcscmp(propName, L"DynamicAddress") == 0) {
                    SetNumericField(DnsInfo.DynamicAddress, sizeof(BOOLEAN));
                }
                else if (wcscmp(propName, L"AddressLength") == 0) {
                    SetNumericField(DnsInfo.AddressLength, sizeof(ULONG));
                }
                else if (wcscmp(propName, L"Address") == 0) {
                    SetAddressField(DnsInfo.Address);
                }
                else if (wcscmp(propName, L"Location") == 0) {
                    SetStringField(DnsInfo.Location);
                }
                else if (wcscmp(propName, L"Context") == 0) {
                    SetStringField(DnsInfo.Context);
                }
            }
        }

        std::wstring sOutPut;
        const USHORT eventId = rec->EventHeader.EventDescriptor.Id;
        OutputDebugString((L"[Etw Trace] DnsEventID " + std::to_wstring(eventId) + L" DomainName " + DnsInfo.QueryName).c_str());
        switch (eventId) {
            // Windows 10 �¼�
        case WIN10_QUERY_START:
            sOutPut = L"[Etw Trace] Process: " + DnsInfo.processPath +
                L" PID: " + std::to_wstring(DnsInfo.processId) +
                L"\n  Query: " + DnsInfo.QueryName +
                L" Type: " + DnsInfo.QueryType +
                L"\n  Options: " + DnsInfo.QueryOptions +
                L"\n  Network: " + DnsInfo.IsNetworkQuery +
                L" Async: " + DnsInfo.IsAsyncQuery +
                L"\n  Local: " + DnsInfo.LocalAddress;
            break;

        case WIN10_RESPONSE_RECV:
            sOutPut = L"[Etw Trace] Process: " + DnsInfo.processPath +
                L" PID: " + std::to_wstring(DnsInfo.processId) +
                L"\n  Query: " + DnsInfo.QueryName +
                L" Status: " + DnsInfo.Status +
                L"\n  Results: " + DnsInfo.QueryResults +
                L"\n  Servers: " + DnsInfo.DNSServerAddress;
            break;

        case WIN10_CONFIG_CHANGE:
            sOutPut = L"[Etw Trace] Process: " + DnsInfo.processPath +
                L" PID: " + std::to_wstring(DnsInfo.processId) +
                L"\n  Adapter: " + DnsInfo.AdapterName +
                L" Index: " + DnsInfo.InterfaceIndex +
                L" Count: " + DnsInfo.InterfaceCount;
            break;

            // Windows 7 �¼�
        case WIN7_QUERY_START:
            sOutPut = L"[Etw Trace] Process: " + DnsInfo.processPath +
                L" PID: " + std::to_wstring(DnsInfo.processId) +
                L"\n  Query: " + DnsInfo.QueryName +
                L" Type: " + DnsInfo.QueryType +
                L"\n  Context: " + DnsInfo.Context +
                L"\n  Source: " + DnsInfo.LocalAddress;
            break;

        case WIN7_RESPONSE_RECV:
            sOutPut = L"[Etw Trace] Process: " + DnsInfo.processPath +
                L" PID: " + std::to_wstring(DnsInfo.processId) +
                L"\n  Query: " + DnsInfo.QueryName +
                L" Status: " + DnsInfo.Status +
                L"\n  Location: " + DnsInfo.Location;
            break;

        case WIN7_CONFIG_CHANGE:
            sOutPut = L"[Etw Trace] Process: " + DnsInfo.processPath +
                L" PID: " + std::to_wstring(DnsInfo.processId) +
                L"\n  Interface: " + DnsInfo.Interface +
                L" Index: " + DnsInfo.Index +
                L"\n  Address: " + DnsInfo.Address +
                L" Length: " + DnsInfo.AddressLength;
            break;

        case WIN7_QUERY_FAILED:
            sOutPut = L"[Etw Trace] Process: " + DnsInfo.processPath +
                L" PID: " + std::to_wstring(DnsInfo.processId) +
                L"\n  Query: " + DnsInfo.QueryName +
                L" Status: " + DnsInfo.Status +
                L"\n  Context: " + DnsInfo.Context;
            break;

        default:
            sOutPut = L"[Etw Trace] ID: " + std::to_wstring(eventId) +
                L" Process: " + DnsInfo.processPath +
                L" PID: " + std::to_wstring(DnsInfo.processId) +
                L"\n  Type: " + DnsInfo.EventName;
        }

        if (!sOutPut.empty()) {
            OutputDebugString(sOutPut.c_str());
        }

        //UPubNode* pEtwData = nullptr;
        //pEtwData = (UPubNode*)new char[g_EtwProcessDataLens];
        //if (pEtwData == nullptr)
        //    return;
        //RtlZeroMemory(pEtwData, g_EtwProcessDataLens);
        //pEtwData->taskid = UF_ETW_NETWORK_DNS;
        //RtlCopyMemory(&pEtwData->data[0], &DnsInfo, sizeof(UEwtDns));

        //if (g_EtwQueue_Ptr && g_EtwQueueCs_Ptr && g_JobQueue_Event)
        //{
        //    std::unique_lock<std::mutex> lock(*g_EtwQueueCs_Ptr);
        //    g_EtwQueue_Ptr->push(pEtwData);
        //    SetEvent(g_JobQueue_Event);
        //}
    }
    catch (const std::exception& e) {
        OutputDebugStringA(("[Etw Trace] DNS Event Error: " + std::string(e.what())).c_str());
    }
    catch (...) {
        OutputDebugString(L"[Etw Trace] Unknown error in ProcessDnsEvent");
    }
}
void WINAPI ProcessRecord(PEVENT_RECORD EventRecord)
{
    if (EventRecord == nullptr)
        return;

    try
    {
        const int EventProcesId = EventRecord->EventHeader.EventDescriptor.Id;
        if ((EventProcesId == 1) || (EventProcesId == 2))
        {
            UEtwProcessInfo etwProcessInfo = { 0, };
            if (1 == EventProcesId)
            {
                std::wstring processPath = wstring((wchar_t*)(((PUCHAR)EventRecord->UserData) + 60));
                size_t found = 0;
                if (!processPath.empty())
                    found = processPath.find_last_of(L"/\\");
                etwProcessInfo.processStatus = true;
                etwProcessInfo.processId = *(ULONG*)(((PUCHAR)EventRecord->UserData) + 0);
                // Name: std::wstring((wchar_t*)(((PUCHAR)EventRecord->UserData) + 84));
                if ((found > 0) && (found < MAX_PATH))
                    lstrcpyW(etwProcessInfo.processPath, processPath.c_str());
                OutputDebugString((L"[Etw Trace] Process Event " + to_wstring(etwProcessInfo.processId) + L" - " + to_wstring(EventProcesId) + L" - " + processPath).c_str());
            }
            else if (2 == EventProcesId)
            {
                etwProcessInfo.processStatus = false;
                etwProcessInfo.processId = *(ULONG*)(((PUCHAR)EventRecord->UserData) + 0);
            }

            UPubNode* pEtwData = nullptr;
            pEtwData = (UPubNode*)new char[g_EtwProcessDataLens];
            if (pEtwData == nullptr)
                return;
            RtlZeroMemory(pEtwData, g_EtwProcessDataLens);
            pEtwData->taskid = UF_ETW_PROCESSINFO;
            RtlCopyMemory(&pEtwData->data[0], &etwProcessInfo, sizeof(UEtwProcessInfo));

            if (g_EtwQueue_Ptr && g_EtwQueueCs_Ptr && g_JobQueue_Event)
            {
                std::unique_lock<std::mutex> lock(*g_EtwQueueCs_Ptr);
                g_EtwQueue_Ptr->push(pEtwData);
                SetEvent(g_JobQueue_Event);
            }
            // Callback
            //if (g_OnProcessNotify)
            //    g_OnProcessNotify(etwProcessInfo);
        }
    }
    catch (...)
    {
    }
}
void WINAPI ProcessFileRecord(PEVENT_RECORD rec)
{
    if (rec == nullptr)
        return;
    try
    {
        EVENT_HEADER& Header = rec->EventHeader;
        if (Header.EventDescriptor.Id == 12 || Header.EventDescriptor.Id == 30) {
            if (*(PULONGLONG)((SIZE_T)rec->UserData + 0x20) == 0x007600650044005c &&
                *(PULONGLONG)((SIZE_T)rec->UserData + 0x30) == 0x0064007200610048)
                return;

            char cFileInfo[4096] = { 0, };
            sprintf(cFileInfo, "[Etw Trace] FILE %d - PID %d - FileName %S - CreateOptions %.8X - CreateAttributes %.8X - ShareAccess %.8X\n",
                Header.EventDescriptor.Id,
                Header.ProcessId,
                (PWSTR)((SIZE_T)rec->UserData + 0x20),
                *(PULONG)((SIZE_T)(rec->UserData) + 0x14),
                *(PULONG)((SIZE_T)(rec->UserData) + 0x18),
                *(PULONG)((SIZE_T)(rec->UserData) + 0x1C));
            OutputDebugStringA(cFileInfo);
        }
        else if (Header.EventDescriptor.Id == 10 || Header.EventDescriptor.Id == 11) {

            // on skippe tout ce qui est sur le disque
            if (*(PULONGLONG)((SIZE_T)rec->UserData + 0x8) == 0x007600650044005c &&
                *(PULONGLONG)((SIZE_T)rec->UserData + 0x18) == 0x0064007200610048)
                return;

            char cFileInfo[4096] = { 0, };
            sprintf(cFileInfo, "[Etw Trace] FILE %d - PID %d - FileName %S\n",
                Header.EventDescriptor.Id,
                Header.ProcessId,
                (PWSTR)((SIZE_T)rec->UserData + 0x8));
            OutputDebugStringA(cFileInfo);
        }
    }
    catch (...)
    {
    }
}
void WINAPI DispatchLogEventCallback(PEVENT_RECORD rec)
{
    /*
        �û�ģʽ�ɼ�ص� ETW �ṩ���б�
        һ������ϵͳ���
        �������̣߳�
        Microsoft-Windows-Kernel-Process (��ʹ��)
        Microsoft-Windows-Kernel-Thread (��ʹ��)
        �ļ�ϵͳ��
        Microsoft-Windows-Kernel-File (��ʹ��)
        Microsoft-Windows-Win32File - �ļ������¼�
        ע���
        Microsoft-Windows-Kernel-Registry (��ʹ��)
        ���磺
        DNS �ͻ��ˣ�
        Microsoft-Windows-DNS-Client (��ʹ��)
        GUID: {1c95126e-7eea-49a9-a3fe-a378b03ddb4d}
        HTTP ����
        Microsoft-Windows-HttpService - HTTP.sys ����
        GUID: {dd5ef90a-6398-47a4-ad34-4dcecdef795f}
        WebIO��
        Microsoft-Windows-WebIO - �ͼ� HTTP ����
        GUID: {50b3e73c-9370-461d-bb9f-26f32d68887d}
        WinINet��
        Microsoft-Windows-WinINet - WinINet API �¼�
        GUID: {43d1a55c-76d6-4f7e-995c-64c711e5cafe}
        WinHTTP��
        Microsoft-Windows-WinHttp - WinHTTP API �¼�
        GUID: {7d44233d-3055-4b9c-ba64-0d47ca40a232}
        SMB �ͻ��ˣ�
        Microsoft-Windows-SMBClient - SMB �ļ�����ͻ���
        GUID: {988c59c5-0a1c-45b6-a555-0c62276e327d}

        ������ȫ���
        ��֤��
        Microsoft-Windows-Authentication - �û���֤�¼�
        GUID: {c7bde5a8-0000-0000-0000-000000000000}
        ��Ȩ��
        Microsoft-Windows-Authorization - ���ʿ����¼�
        GUID: {6b1d8c3f-0000-0000-0000-000000000000}
        ��ƣ�
        Microsoft-Windows-Security-Auditing - ��ȫ����¼�
        GUID: {54849625-5478-4994-a5ba-3e3b0328c30d}

        ����Ӧ�ó�����
        .NET��
        Microsoft-Windows-DotNETRuntime - CLR ����ʱ�¼�
        GUID: {e13c0d23-ccbc-4e12-931b-d9cc2eee27e4}
        Microsoft-Windows-ASP.NET - ASP.NET �¼�
        GUID: {aff081fe-0247-4275-9c4e-021f3dc1da35}
        COM/OLE��
        Microsoft-Windows-COM - �������ģ��
        GUID: {b7e34f1b-6c83-4118-aaf5-be1e267b1a92}
        Microsoft-Windows-OLE - OLE �Զ���
        GUID: {5c8bb950-959e-4309-8908-67961a1205d5}
        RPC��
        Microsoft-Windows-RPC - Զ�̹��̵���
        GUID: {6ad52b32-d609-4be9-ae07-ce8dae937e39}

        �ġ���ý��
        ý�������
        Microsoft-Windows-MediaFoundation - ý�岥��
        GUID: {f404b94e-27e0-4384-bfe8-1d8d390b0aa3}
        ��Ƶ��
        Microsoft-Windows-Audio - ��Ƶ����
        GUID: {f0f3e8db-2e99-4c9a-a537-0c9b6b8a0e8b}

        �塢ϵͳ����
        ������ƣ�
        Microsoft-Windows-Services - ��������/ֹͣ
        GUID: {2a9c6dd1-5701-4e0e-9f4a-8a8e9e1a1a8a}
        ����ƻ���
        Microsoft-Windows-TaskScheduler - �ƻ�����
        GUID: {de7b24ea-73c8-4a09-985d-5bdd3a6c5d2c}
        �豸����
        Microsoft-Windows-DeviceManagement - �豸����
        GUID: {6ad52b32-d609-4be9-ae07-ce8dae937e39}

        �����û�����
        ���룺
        Microsoft-Windows-UserInput - ����/�������
        GUID: {f0f3e8db-2e99-4c9a-a537-0c9b6b8a0e8b}
        ���ڹ���
        Microsoft-Windows-Win32k - ���ڹ�����
        GUID: {8c416c79-d49b-4f01-a467-e56d3b5e7f2f}

        �ߡ��ű�����
        PowerShell��
        Microsoft-Windows-PowerShell - PowerShell ִ��
        GUID: {a0c1853b-5c40-4b15-8766-3cf1c58f985a}
        JScript��
        Microsoft-Windows-JScript - JScript ����
        GUID: {57277741-3638-4a4b-bdba-0ac6e45da56c}
        VBScript��
        Microsoft-Windows-VBScript - VBScript ����
        GUID: {f1c3b79a-8765-4b5a-8a3a-7c4140c7d8c3}

        �ˡ����ݿ����
        ODBC��
        Microsoft-Windows-ODBC - ODBC ���ݿ����
        GUID: {2a9c6dd1-5701-4e0e-9f4a-8a8e9e1a1a8a}
        OLEDB��
        Microsoft-Windows-OLEDB - OLEDB ���ݿ����
        GUID: {6b1d8c3f-0000-0000-0000-000000000000}

        �š������߹���
        ���ԣ�
        Microsoft-Windows-Debug - �����¼�
        GUID: {6b1d8c3f-0000-0000-0000-000000000000}
        ���ܷ�����
        Microsoft-Windows-Perf - ���ܼ�����
        GUID: {ce1dbfb4-137e-4da6-87b0-3f59aa102cbc}

        ʮ��������Ҫ�ṩ��
        ���󱨸棺
        Microsoft-Windows-WindowsErrorReporting - WER �¼�
        GUID: {b4e9e8d7-5a5e-4c8e-8b8d-7d9d7d9d7d9d}
        ���¹���
        Microsoft-Windows-WindowsUpdateClient - Windows ����
        GUID: {945a8954-c147-4acd-923f-40c9b9d8e7b1}
        �洢��
        Microsoft-Windows-Storage - �洢����
        GUID: {c7bde5a8-0000-0000-0000-000000000000}

        // win32K
        GUID providerGuid = { 0x8C416C79, 0xD49B, 0x4F01, {0xA4, 0x67, 0xE5, 0x6D, 0x3A, 0xA8, 0x23, 0x4C} };
        GUID providerGuidWin7 = { 0xe7ef96be, 0x969f, 0x414f, {0x97, 0xd7, 0x3d, 0xdb, 0x7b, 0x55, 0x8c, 0xcc} };
        ULONGLONG keyWord = 0x400 | 0x800000 | 0x1000 | 0x40000000000 | 0x80000000000;
        status = EnableTraceEx2(
            g_sessionHandle,
            &providerGuid,
            EVENT_CONTROL_CODE_ENABLE_PROVIDER,
            TRACE_LEVEL_INFORMATION,
            keyWord,
            0,
            0,
            NULL);
    */
    try
    {
        if (rec) {
            auto header = rec->EventHeader;
            if (IsEqualGUID(header.ProviderId, DnsClientWin7Guid) || \
                IsEqualGUID(header.ProviderId, DnsClientGuid)) {
                ProcessDnsEvent(rec);
            }
            else if (IsEqualGUID(header.ProviderId, ProcessProviderGuid)) {
                ProcessRecord(rec);
            }
            else if (IsEqualGUID(header.ProviderId, FileProviderGuid)) {
                ProcessFileRecord(rec);
            }
        }
    }
    catch (...)
    {
    }
}

// �����ߣ�Etw�¼��ص� - ����������������Ϣ����(������)
// [NT Kernel Logger] PEVENT_RECORD�ص�
void WINAPI NetWorkEventInfo(PEVENT_RECORD rec, PTRACE_EVENT_INFO info)
{
    if ((info == nullptr) || (rec == nullptr))
        return;
    if (info->TaskNameOffset <= 0)
        return;

    try
    {
        std::wstring taskName = (PCWSTR)((BYTE*)info + info->TaskNameOffset);
        if (taskName.empty())
            return;
        size_t task_tcplen = taskName.find(L"TcpIp");
        size_t task_udplen = taskName.find(L"UdpIp");

        UEtwNetWork etwNetInfo;
        etwNetInfo.clear();
        if (info->OpcodeNameOffset)
        {
            const wstring EventName = (PCWSTR)((BYTE*)info + info->OpcodeNameOffset);
            if (!EventName.empty())
                wcscpy_s(etwNetInfo.EventName, EventName.c_str());
        }

        if (task_tcplen >= 0 && task_tcplen <= 100)
        {
            etwNetInfo.protocol = IPPROTO_TCP;
        }
        else if (task_udplen >= 0 && task_udplen <= 100)
        {
            etwNetInfo.protocol = IPPROTO_UDP;
        }
        else
            return;

        auto userlen = rec->UserDataLength;
        auto data = (PBYTE)rec->UserData;
        auto pointerSize = (rec->EventHeader.Flags & EVENT_HEADER_FLAG_32_BIT_HEADER) ? 4 : 8;

        ULONG len; WCHAR value[512] = { 0, };
        string  tmpstr; wstring propName; DWORD nCode = 0;
        wchar_t cProcessPath[MAX_PATH] = { 0, };
        for (DWORD i = 0; i < info->TopLevelPropertyCount; i++) {

            propName.clear(); nCode = 0; tmpstr.clear();

            auto& pi = info->EventPropertyInfoArray[i];
            propName = (PCWSTR)((BYTE*)info + pi.NameOffset);

            nCode = uf_GetNetWrokEventStr(propName);

            len = pi.length;
            if ((pi.Flags & (PropertyStruct | PropertyParamCount)) == 0) {
                PEVENT_MAP_INFO mapInfo = nullptr;
                std::unique_ptr<BYTE[]> mapBuffer;
                PWSTR mapName = nullptr;
                if (pi.nonStructType.MapNameOffset) {
                    ULONG size = 0;
                    mapName = (PWSTR)((BYTE*)info + pi.nonStructType.MapNameOffset);
                    if (ERROR_INSUFFICIENT_BUFFER == ::TdhGetEventMapInformation(rec, mapName, mapInfo, &size)) {
                        mapBuffer = std::make_unique<BYTE[]>(size);
                        mapInfo = reinterpret_cast<PEVENT_MAP_INFO>(mapBuffer.get());
                        if (ERROR_SUCCESS != ::TdhGetEventMapInformation(rec, mapName, mapInfo, &size))
                            mapInfo = nullptr;
                    }
                }

                ULONG size = sizeof(value);
                USHORT consumed;

                // special case for IPv6 address
                if (pi.nonStructType.InType == TDH_INTYPE_BINARY && pi.nonStructType.OutType == TDH_OUTTYPE_IPV6)
                    len = sizeof(IN6_ADDR);

                auto error = ::TdhFormatProperty(info, mapInfo, pointerSize,
                    pi.nonStructType.InType, pi.nonStructType.OutType,
                    (USHORT)len, userlen, data, &size, value, &consumed);

                if (ERROR_SUCCESS == error) {
                    len = consumed;
                    if (mapName)
                        lstrcatW(value, mapName);
                }
                else if (mapInfo) {
                    error = ::TdhFormatProperty(info, nullptr, pointerSize,
                        pi.nonStructType.InType, pi.nonStructType.OutType,
                        (USHORT)len, userlen, data, &size, value, &consumed);
                }

                userlen -= (USHORT)len;
                data += len;

                if (ERROR_SUCCESS == error)
                {
                    switch (nCode)
                    {
                    case 1: // PID
                    {
                        // wtoi������ת��16���ƿ��ַ� - ����valuse�ڴ���ʮ���� - ������wcstol
                        etwNetInfo.processId = _wtoi(value);
                        etwNetInfo.processPathSize = GetPathByProcessId(cProcessPath, etwNetInfo.processId);
                        if (etwNetInfo.processPathSize)
                            RtlCopyMemory(etwNetInfo.processPath, cProcessPath, MAX_PATH);
                    }
                    break;
                    case 3: // daddr
                        Wchar_tToString(tmpstr, value);
                        etwNetInfo.ipv4toRemoteAddr = inet_addr(tmpstr.c_str());
                        break;
                    case 4: // saddr
                        Wchar_tToString(tmpstr, value);
                        etwNetInfo.ipv4LocalAddr = inet_addr(tmpstr.c_str());
                        break;
                    case 5: // dport
                        etwNetInfo.toRemotePort = _wtoi(value);
                        break;
                    case 6: // sport
                        etwNetInfo.toLocalPort = _wtoi(value);
                        break;
                    }
                }

            }
        }

        UPubNode* pEtwData = nullptr;
        pEtwData = (UPubNode*)new char[g_EtwNetworkDataLens];
        if (pEtwData == nullptr)
            return;
        RtlZeroMemory(pEtwData, g_EtwNetworkDataLens);
        pEtwData->taskid = UF_ETW_NETWORK;
        RtlCopyMemory(&pEtwData->data[0], &etwNetInfo, sizeof(UEtwNetWork));

        if (g_EtwQueue_Ptr && g_EtwQueueCs_Ptr && g_JobQueue_Event)
        {
            std::unique_lock<std::mutex> lock(*g_EtwQueueCs_Ptr);
            g_EtwQueue_Ptr->push(pEtwData);
            SetEvent(g_JobQueue_Event);
        }
    }
    catch (...)
    {
    }
}
void WINAPI ProcessEventInfo(PEVENT_RECORD rec, PTRACE_EVENT_INFO info)
{
    if ((info == nullptr) || (rec == nullptr))
        return;
    if (info->TaskNameOffset <= 0)
        return;

    try
    {
        auto userlen = rec->UserDataLength;
        auto data = (PBYTE)rec->UserData;
        auto pointerSize = (rec->EventHeader.Flags & EVENT_HEADER_FLAG_32_BIT_HEADER) ? 4 : 8;

        wchar_t* pEnd = nullptr;
        ULONG len = 0; WCHAR value[512] = { 0, };
        wstring tmpstr = L""; wstring propName = L"";

        UEtwProcessInfo etwProcessInfo;
        etwProcessInfo.clear();
        if (info->OpcodeNameOffset)
        {
            const wstring EventName = (PCWSTR)((BYTE*)info + info->OpcodeNameOffset);
            if (!EventName.empty())
                wcscpy_s(etwProcessInfo.EventName, EventName.c_str());
        }

        for (DWORD i = 0; i < info->TopLevelPropertyCount; i++) {

            propName.clear(); tmpstr.clear();

            auto& pi = info->EventPropertyInfoArray[i];
            propName = (PCWSTR)((BYTE*)info + pi.NameOffset);
            len = pi.length;
            if ((pi.Flags & (PropertyStruct | PropertyParamCount)) == 0) {
                PEVENT_MAP_INFO mapInfo = nullptr;
                std::unique_ptr<BYTE[]> mapBuffer;
                PWSTR mapName = nullptr;
                if (pi.nonStructType.MapNameOffset) {
                    ULONG size = 0;
                    mapName = (PWSTR)((BYTE*)info + pi.nonStructType.MapNameOffset);
                    if (ERROR_INSUFFICIENT_BUFFER == ::TdhGetEventMapInformation(rec, mapName, mapInfo, &size)) {
                        mapBuffer = std::make_unique<BYTE[]>(size);
                        mapInfo = reinterpret_cast<PEVENT_MAP_INFO>(mapBuffer.get());
                        if (ERROR_SUCCESS != ::TdhGetEventMapInformation(rec, mapName, mapInfo, &size))
                            mapInfo = nullptr;
                    }
                }

                ULONG size = sizeof(value);
                USHORT consumed;
                auto error = ::TdhFormatProperty(info, mapInfo, pointerSize,
                    pi.nonStructType.InType, pi.nonStructType.OutType,
                    (USHORT)len, userlen, data, &size, value, &consumed);

                // ��ȡ����
                if (ERROR_SUCCESS == error) {
                    len = consumed;
                    if (mapName)
                        lstrcatW(value, mapName);
                }
                else if (mapInfo) {
                    error = ::TdhFormatProperty(info, nullptr, pointerSize,
                        pi.nonStructType.InType, pi.nonStructType.OutType,
                        (USHORT)len, userlen, data, &size, value, &consumed);
                }

            }

            userlen -= (USHORT)len;
            data += len;

            if (0 == lstrcmpW(L"ProcessId", propName.c_str()))
            {
                const long pid = wcstol(value, &pEnd, 16);
                etwProcessInfo.processId = pid;
            }
            else if (0 == lstrcmpW(L"ParentId", propName.c_str()))
            {
                const long pid = wcstol(value, &pEnd, 16);
                etwProcessInfo.parentId = pid;
            }
            else if (0 == lstrcmpW(L"ExitStatus", propName.c_str()))
            {
                if (0 >= _wtoi(value))
                    etwProcessInfo.processStatus = false;
                else
                    etwProcessInfo.processStatus = true;
            }
            else if (0 == lstrcmpW(L"CommandLine", propName.c_str()))
            {
                wcscpy_s(etwProcessInfo.processPath, value);
            }
            else if (0 == lstrcmpW(L"ImageFileName", propName.c_str()))
            {
                wcscpy_s(etwProcessInfo.processName, value);
            }
        }

        UPubNode* pEtwData = nullptr;
        pEtwData = (UPubNode*)new char[g_EtwProcessDataLens];
        if (pEtwData == nullptr)
            return;
        RtlZeroMemory(pEtwData, g_EtwProcessDataLens);
        pEtwData->taskid = UF_ETW_PROCESSINFO;
        RtlCopyMemory(&pEtwData->data[0], &etwProcessInfo, sizeof(UEtwProcessInfo));

        if (g_EtwQueue_Ptr && g_EtwQueueCs_Ptr && g_JobQueue_Event)
        {
            std::unique_lock<std::mutex> lock(*g_EtwQueueCs_Ptr);
            g_EtwQueue_Ptr->push(pEtwData);
            SetEvent(g_JobQueue_Event);
        }
    }
    catch (...)
    {
    }
}
void WINAPI ThreadEventInfo(PEVENT_RECORD rec, PTRACE_EVENT_INFO info)
{
    if ((info == nullptr) || (rec == nullptr))
        return;
    if (info->TaskNameOffset <= 0)
        return;

    try
    {
        auto userlen = rec->UserDataLength;
        auto data = (PBYTE)rec->UserData;
        auto pointerSize = (rec->EventHeader.Flags & EVENT_HEADER_FLAG_32_BIT_HEADER) ? 4 : 8;

        wchar_t* pEnd = nullptr;
        ULONG len = 0; WCHAR value[512] = { 0, };
        wstring  tmpstr = L""; wstring propName = L"";

        UEtwThreadInfo etwThreadInfo;
        etwThreadInfo.clear();
        if (info->OpcodeNameOffset)
        {
            const wstring EventName = (PCWSTR)((BYTE*)info + info->OpcodeNameOffset);
            if (!EventName.empty())
                wcscpy_s(etwThreadInfo.EventName, EventName.c_str());
        }

        for (DWORD i = 0; i < info->TopLevelPropertyCount; i++) {

            propName.clear(); tmpstr.clear();

            auto& pi = info->EventPropertyInfoArray[i];
            propName = (PCWSTR)((BYTE*)info + pi.NameOffset);
            len = pi.length;
            if ((pi.Flags & (PropertyStruct | PropertyParamCount)) == 0) {
                PEVENT_MAP_INFO mapInfo = nullptr;
                std::unique_ptr<BYTE[]> mapBuffer;
                PWSTR mapName = nullptr;
                if (pi.nonStructType.MapNameOffset) {
                    ULONG size = 0;
                    mapName = (PWSTR)((BYTE*)info + pi.nonStructType.MapNameOffset);
                    if (ERROR_INSUFFICIENT_BUFFER == ::TdhGetEventMapInformation(rec, mapName, mapInfo, &size)) {
                        mapBuffer = std::make_unique<BYTE[]>(size);
                        mapInfo = reinterpret_cast<PEVENT_MAP_INFO>(mapBuffer.get());
                        if (ERROR_SUCCESS != ::TdhGetEventMapInformation(rec, mapName, mapInfo, &size))
                            mapInfo = nullptr;
                    }
                }

                ULONG size = sizeof(value);
                USHORT consumed;
                auto error = ::TdhFormatProperty(info, mapInfo, pointerSize,
                    pi.nonStructType.InType, pi.nonStructType.OutType,
                    (USHORT)len, userlen, data, &size, value, &consumed);

                if (ERROR_SUCCESS == error) {
                    len = consumed;
                    if (mapName)
                        lstrcatW(value, mapName);
                }
                else if (mapInfo) {
                    error = ::TdhFormatProperty(info, nullptr, pointerSize,
                        pi.nonStructType.InType, pi.nonStructType.OutType,
                        (USHORT)len, userlen, data, &size, value, &consumed);
                }

            }

            userlen -= (USHORT)len;
            data += len;

            if (0 == lstrcmpW(propName.c_str(), L"ProcessId")) {
                etwThreadInfo.processId = wcstol(value, &pEnd, 16);
            }
            else if (0 == lstrcmpW(propName.c_str(), L"TThreadId")) {
                etwThreadInfo.threadId = wcstol(value, &pEnd, 16);
            }
            else if (0 == lstrcmpW(propName.c_str(), L"StackBase")) {
            }
            else if (0 == lstrcmpW(propName.c_str(), L"StackLimit")) {
            }
            else if (0 == lstrcmpW(propName.c_str(), L"UserStackBase")) {
            }
            else if (0 == lstrcmpW(propName.c_str(), L"UserStackLimit")) {
            }
            else if (0 == lstrcmpW(propName.c_str(), L"Affinity")) {
            }
            else if (0 == lstrcmpW(propName.c_str(), L"Win32StartAddr")) {
                etwThreadInfo.Win32StartAddr = _wcstoui64(value, &pEnd, 16);
            }
            else if (0 == lstrcmpW(propName.c_str(), L"TebBase")) {
            }
            else if (0 == lstrcmpW(propName.c_str(), L"SubProcessTag")) {
            }
            else if (0 == lstrcmpW(propName.c_str(), L"BasePriority")) {
            }
            else if (0 == lstrcmpW(propName.c_str(), L"PagePriority")) {
            }
            else if (0 == lstrcmpW(propName.c_str(), L"IoPriority")) {
            }
            else if (0 == lstrcmpW(propName.c_str(), L"ThreadFlags")) {
                etwThreadInfo.ThreadFlags = _wtoi(value);
            }
        }

        // filter pid - threadid
        if (etwThreadInfo.processId && etwThreadInfo.threadId)
        {
            UPubNode* pEtwData = nullptr;
            pEtwData = (UPubNode*)new char[g_EtwThreadDataLens];
            if (pEtwData == nullptr)
                return;
            RtlZeroMemory(pEtwData, g_EtwThreadDataLens);
            pEtwData->taskid = UF_ETW_THREADINFO;
            RtlCopyMemory(&pEtwData->data[0], &etwThreadInfo, sizeof(UEtwThreadInfo));

            if (g_EtwQueue_Ptr && g_EtwQueueCs_Ptr && g_JobQueue_Event)
            {
                std::unique_lock<std::mutex> lock(*g_EtwQueueCs_Ptr);
                g_EtwQueue_Ptr->push(pEtwData);
                SetEvent(g_JobQueue_Event);
            }
        }
    }
    catch (...)
    {
    }
}
void WINAPI FileEventInfo(PEVENT_RECORD rec, PTRACE_EVENT_INFO info)
{
    if ((info == nullptr) || (rec == nullptr))
        return;
    if (info->TaskNameOffset <= 0)
        return;

    try
    {
        auto userlen = rec->UserDataLength;
        auto data = (PBYTE)rec->UserData;
        const auto pointerSize = (rec->EventHeader.Flags & EVENT_HEADER_FLAG_32_BIT_HEADER) ? 4 : 8;

        wchar_t* pEnd = nullptr;
        ULONG len = 0; WCHAR value[512] = { 0, };
        wstring tmpstr = L""; wstring propName = L"";

        UEtwFileIoTabInfo etwFileIoInfo;
        etwFileIoInfo.clear();
        if (info->OpcodeNameOffset)
        {
            const wstring EventName = (PCWSTR)((BYTE*)info + info->OpcodeNameOffset);
            // filter evenet
            if (EventName == L"OperationEnd")
                return;
            if (EventName == L"QueryInfo")
                return;
            if (EventName == L"FSControl")
                return;
            if (!EventName.empty())
                wcscpy_s(etwFileIoInfo.EventName, EventName.c_str());
        }

        for (DWORD i = 0; i < info->TopLevelPropertyCount; i++) {

            propName.clear(); tmpstr.clear();

            auto& pi = info->EventPropertyInfoArray[i];
            propName = (PCWSTR)((BYTE*)info + pi.NameOffset);
            len = pi.length;
            if ((pi.Flags & (PropertyStruct | PropertyParamCount)) == 0) {
                PEVENT_MAP_INFO mapInfo = nullptr;
                std::unique_ptr<BYTE[]> mapBuffer;
                PWSTR mapName = nullptr;
                if (pi.nonStructType.MapNameOffset) {
                    ULONG size = 0;
                    mapName = (PWSTR)((BYTE*)info + pi.nonStructType.MapNameOffset);
                    if (ERROR_INSUFFICIENT_BUFFER == ::TdhGetEventMapInformation(rec, mapName, mapInfo, &size)) {
                        mapBuffer = std::make_unique<BYTE[]>(size);
                        mapInfo = reinterpret_cast<PEVENT_MAP_INFO>(mapBuffer.get());
                        if (ERROR_SUCCESS != ::TdhGetEventMapInformation(rec, mapName, mapInfo, &size))
                            mapInfo = nullptr;
                    }
                }

                ULONG size = sizeof(value);
                USHORT consumed;
                auto error = ::TdhFormatProperty(info, mapInfo, pointerSize,
                    pi.nonStructType.InType, pi.nonStructType.OutType,
                    (USHORT)len, userlen, data, &size, value, &consumed);

                // ��ȡ����
                if (ERROR_SUCCESS == error) {
                    len = consumed;
                    if (mapName)
                        lstrcatW(value, mapName);
                }
                else if (mapInfo) {
                    error = ::TdhFormatProperty(info, nullptr, pointerSize,
                        pi.nonStructType.InType, pi.nonStructType.OutType,
                        (USHORT)len, userlen, data, &size, value, &consumed);
                }

            }

            userlen -= (USHORT)len;
            data += len;

            if (0 == lstrcmpW(propName.c_str(), L"TTID")) {
                // �߳�ID
                etwFileIoInfo.TTID = _wtoi(value);
                // Get Pid����׼ȷ
                //const HANDLE hthread = OpenThread(THREAD_ALL_ACCESS, NULL, fileio_info.TTID);
                //if (hthread) {
                //    fileio_info.PID = (DWORD)GetProcessIdOfThread(hthread);
                //    CloseHandle(hthread);
                //}
                //else
                //    fileio_info.PID = 0;
            }
            else if (0 == lstrcmpW(propName.c_str(), L"IrpPtr")) {
                // IRP
                etwFileIoInfo.IrpPtr = _wcstoui64(value, &pEnd, 16);
            }
            else if (0 == lstrcmpW(propName.c_str(), L"FileObject")) {
                etwFileIoInfo.FileObject = _wcstoui64(value, &pEnd, 16);
            }
            else if (0 == lstrcmpW(propName.c_str(), L"FileKey")) {
                etwFileIoInfo.FileKey = _wcstoui64(value, &pEnd, 16);
            }
            /*
            * FileIo_DirEnum
            * FileIo_Info
            * FileIo_OpEnd
            */
            else if (0 == lstrcmpW(propName.c_str(), L"InfoClass")) {
            }
            else if (0 == lstrcmpW(propName.c_str(), L"ExtraInfo")) {
            }
            else if (0 == lstrcmpW(propName.c_str(), L"NtStatus")) {
            }
            /*
            * File_Create
            */
            else if (0 == lstrcmpW(propName.c_str(), L"OpenPath")) {
                wcscpy_s(etwFileIoInfo.FilePath, value);
            }
            else if (0 == lstrcmpW(propName.c_str(), L"CreateOptions")) {
                etwFileIoInfo.CreateOptions = _wtoi(value);
            }
            else if (0 == lstrcmpW(propName.c_str(), L"ShareAccess")) {
                etwFileIoInfo.ShareAccess = _wtoi(value);
            }
            else if (0 == lstrcmpW(propName.c_str(), L"FileAttributes")) {
                etwFileIoInfo.FileAttributes = _wtoi(value);
            }
            /*
            * FileIo_Name
            */
            else if (0 == lstrcmpW(propName.c_str(), L"FileName")) {
                wcscpy_s(etwFileIoInfo.FileName, value);
            }
            /*
            * File_ReadWrite
            */
            else if (0 == lstrcmpW(propName.c_str(), L"IoSize")) {
            }
            else if (0 == lstrcmpW(propName.c_str(), L"IoFlags")) {
            }
            else if (0 == lstrcmpW(propName.c_str(), L"Offset")) {
                // �ļ���д��ֹλ��
                etwFileIoInfo.Offset = _wtoi(value);
            }
        }

        // Filter
        if (0 == lstrcmpW(etwFileIoInfo.EventName, L"Read")) {
            std::unique_lock<std::mutex> lock(g_FileReadLock);
            if (g_etwFileReadFilter.end() == g_etwFileReadFilter.find(etwFileIoInfo.FileKey)) {
                g_etwFileReadFilter[etwFileIoInfo.FileKey] = 0;
            }
            else {
                return;
            }
        }
        else if (0 == lstrcmpW(etwFileIoInfo.EventName, L"Write")) {
            std::unique_lock<std::mutex> lock(g_FileWriteLock);
            if (g_etwFileWriteilter.end() == g_etwFileWriteilter.find(etwFileIoInfo.FileKey)) {
                g_etwFileWriteilter[etwFileIoInfo.FileKey] = 0;
            }
            else {
                return;
            }
        }
        else if (0 == lstrcmpW(etwFileIoInfo.EventName, L"DirEnum")) {
            std::unique_lock<std::mutex> lock(g_FileDirEnumLock);
            if (g_etwFileDirEnumFilter.end() == g_etwFileDirEnumFilter.find(etwFileIoInfo.FileKey)) {
                g_etwFileDirEnumFilter[etwFileIoInfo.FileKey] = 0;
            }
            else {
                return;
            }
        }
        else if (0 == lstrcmpW(etwFileIoInfo.EventName, L"Close")) {
            {
                std::unique_lock<std::mutex> lock(g_FileReadLock);
                const auto& iter = g_etwFileReadFilter.find(etwFileIoInfo.FileKey);
                if (iter != g_etwFileReadFilter.end())
                    g_etwFileReadFilter.erase(iter);
            }
            {
                std::unique_lock<std::mutex> lock(g_FileWriteLock);
                const auto& iter = g_etwFileWriteilter.find(etwFileIoInfo.FileKey);
                if (iter != g_etwFileWriteilter.end())
                    g_etwFileWriteilter.erase(iter);
            }
            {
                std::unique_lock<std::mutex> lock(g_FileDirEnumLock);
                const auto& iter = g_etwFileDirEnumFilter.find(etwFileIoInfo.FileKey);
                if (iter != g_etwFileDirEnumFilter.end())
                    g_etwFileDirEnumFilter.erase(iter);
            }
        }

        UPubNode* pEtwData = nullptr;
        pEtwData = (UPubNode*)new char[g_EtwFileIoDataLens];
        if (pEtwData == nullptr)
            return;
        RtlSecureZeroMemory(pEtwData, g_EtwFileIoDataLens);
        pEtwData->taskid = UF_ETW_FILEIO;
        RtlCopyMemory(&pEtwData->data[0], &etwFileIoInfo, sizeof(UEtwFileIoTabInfo));

        if (g_EtwQueue_Ptr && g_EtwQueueCs_Ptr && g_JobQueue_Event)
        {
            std::unique_lock<std::mutex> lock(*g_EtwQueueCs_Ptr);
            g_EtwQueue_Ptr->push(pEtwData);
            SetEvent(g_JobQueue_Event);
        }
    }
    catch (...)
    {
    }
}
void WINAPI RegisterTabEventInfo(PEVENT_RECORD rec, PTRACE_EVENT_INFO info)
{
    if ((info == nullptr) || (rec == nullptr))
        return;
    if (info->TaskNameOffset <= 0)
        return;

    try
    {
        auto userlen = rec->UserDataLength;
        auto data = (PBYTE)rec->UserData;
        const auto pointerSize = (rec->EventHeader.Flags & EVENT_HEADER_FLAG_32_BIT_HEADER) ? 4 : 8;

        wchar_t* pEnd = nullptr;
        ULONG len = 0; WCHAR value[512] = { 0, };
        wstring tmpstr = L""; wstring propName = L"";

        UEtwRegisterTabInfo etwRegtabInfo;
        etwRegtabInfo.clear();
        if (info->OpcodeNameOffset)
        {
            const wstring EventName = (PCWSTR)((BYTE*)info + info->OpcodeNameOffset);
            if (!EventName.empty())
                wcscpy_s(etwRegtabInfo.EventName, EventName.c_str());
        }

        for (DWORD i = 0; i < info->TopLevelPropertyCount; i++) {

            propName.clear(); tmpstr.clear();

            auto& pi = info->EventPropertyInfoArray[i];
            propName = (PCWSTR)((BYTE*)info + pi.NameOffset);
            len = pi.length;
            if ((pi.Flags & (PropertyStruct | PropertyParamCount)) == 0) {
                PEVENT_MAP_INFO mapInfo = nullptr;
                std::unique_ptr<BYTE[]> mapBuffer;
                PWSTR mapName = nullptr;
                if (pi.nonStructType.MapNameOffset) {
                    ULONG size = 0;
                    mapName = (PWSTR)((BYTE*)info + pi.nonStructType.MapNameOffset);
                    if (ERROR_INSUFFICIENT_BUFFER == ::TdhGetEventMapInformation(rec, mapName, mapInfo, &size)) {
                        mapBuffer = std::make_unique<BYTE[]>(size);
                        mapInfo = reinterpret_cast<PEVENT_MAP_INFO>(mapBuffer.get());
                        if (ERROR_SUCCESS != ::TdhGetEventMapInformation(rec, mapName, mapInfo, &size))
                            mapInfo = nullptr;
                    }
                }

                ULONG size = sizeof(value);
                USHORT consumed;
                auto error = ::TdhFormatProperty(info, mapInfo, pointerSize,
                    pi.nonStructType.InType, pi.nonStructType.OutType,
                    (USHORT)len, userlen, data, &size, value, &consumed);
                if (ERROR_SUCCESS == error) {
                    len = consumed;
                    if (mapName)
                        lstrcatW(value, mapName);
                }
                else if (mapInfo) {
                    error = ::TdhFormatProperty(info, nullptr, pointerSize,
                        pi.nonStructType.InType, pi.nonStructType.OutType,
                        (USHORT)len, userlen, data, &size, value, &consumed);
                }

            }

            userlen -= (USHORT)len;
            data += len;

            if (0 == lstrcmpW(propName.c_str(), L"InitialTime")) {
                etwRegtabInfo.InitialTime = wcstoll(value, &pEnd, 10);
            }
            else if (0 == lstrcmpW(propName.c_str(), L"Status")) {
                etwRegtabInfo.Status = _wtoi(value);
            }
            else if (0 == lstrcmpW(propName.c_str(), L"Index")) {
                etwRegtabInfo.Index = _wtoi(value);
            }
            else if (0 == lstrcmpW(propName.c_str(), L"KeyHandle")) {
                etwRegtabInfo.KeyHandle = _wcstoui64(value, &pEnd, 16);
            }
            else if (0 == lstrcmpW(propName.c_str(), L"KeyName")) {
                lstrcpynW(etwRegtabInfo.KeyName, value, MAX_PATH);
            }
        }

        UPubNode* pEtwData = nullptr;
        pEtwData = (UPubNode*)new char[g_EtwRegtabDataLens];
        if (pEtwData == nullptr)
            return;
        RtlZeroMemory(pEtwData, g_EtwRegtabDataLens);
        pEtwData->taskid = UF_ETW_REGISTERTAB;
        RtlCopyMemory(&pEtwData->data[0], &etwRegtabInfo, sizeof(UEtwRegisterTabInfo));
        if (g_EtwQueue_Ptr && g_EtwQueueCs_Ptr && g_JobQueue_Event)
        {
            std::unique_lock<std::mutex> lock(*g_EtwQueueCs_Ptr);
            g_EtwQueue_Ptr->push(pEtwData);
            SetEvent(g_JobQueue_Event);
        }
    }
    catch (...)
    {
    }
}
void WINAPI ImageModEventInfo(PEVENT_RECORD rec, PTRACE_EVENT_INFO info)
{
    if ((info == nullptr) || (rec == nullptr))
        return;
    if (info->TaskNameOffset <= 0)
        return;

    wchar_t* pEnd = nullptr;
    ULONG len = 0; WCHAR value[512] = { 0, };
    wstring tmpstr = L""; wstring propName = L"";

    try
    {
        UEtwImageInfo eImageInfo;
        eImageInfo.clear();
        if (info->OpcodeNameOffset)
        {
            const wstring EventName = (PCWSTR)((BYTE*)info + info->OpcodeNameOffset);
            if (EventName == L"DCStart")
                return;
            if (!EventName.empty())
                wcscpy_s(eImageInfo.EventName, EventName.c_str());
        }

        auto userlen = rec->UserDataLength;
        auto data = (PBYTE)rec->UserData;
        const auto pointerSize = (rec->EventHeader.Flags & EVENT_HEADER_FLAG_32_BIT_HEADER) ? 4 : 8;

        for (DWORD i = 0; i < info->TopLevelPropertyCount; i++) {

            propName.clear(); tmpstr.clear();

            auto& pi = info->EventPropertyInfoArray[i];
            propName = (PCWSTR)((BYTE*)info + pi.NameOffset);
            len = pi.length;
            if ((pi.Flags & (PropertyStruct | PropertyParamCount)) == 0) {
                PEVENT_MAP_INFO mapInfo = nullptr;
                std::unique_ptr<BYTE[]> mapBuffer;
                PWSTR mapName = nullptr;
                if (pi.nonStructType.MapNameOffset) {
                    ULONG size = 0;
                    mapName = (PWSTR)((BYTE*)info + pi.nonStructType.MapNameOffset);
                    if (ERROR_INSUFFICIENT_BUFFER == ::TdhGetEventMapInformation(rec, mapName, mapInfo, &size)) {
                        mapBuffer = std::make_unique<BYTE[]>(size);
                        mapInfo = reinterpret_cast<PEVENT_MAP_INFO>(mapBuffer.get());
                        if (ERROR_SUCCESS != ::TdhGetEventMapInformation(rec, mapName, mapInfo, &size))
                            mapInfo = nullptr;
                    }
                }

                ULONG size = sizeof(value);
                USHORT consumed;
                auto error = ::TdhFormatProperty(info, mapInfo, pointerSize,
                    pi.nonStructType.InType, pi.nonStructType.OutType,
                    (USHORT)len, userlen, data, &size, value, &consumed);
                if (ERROR_SUCCESS == error) {
                    len = consumed;
                    if (mapName)
                        lstrcatW(value, mapName);
                }
                else if (mapInfo) {
                    error = ::TdhFormatProperty(info, nullptr, pointerSize,
                        pi.nonStructType.InType, pi.nonStructType.OutType,
                        (USHORT)len, userlen, data, &size, value, &consumed);
                }

            }

            userlen -= (USHORT)len;
            data += len;

            if (0 == lstrcmpW(propName.c_str(), L"ImageBase")) {
                eImageInfo.ImageBase = _wcstoui64(value, &pEnd, 16);
            }
            else if (0 == lstrcmpW(propName.c_str(), L"ImageSize")) {
                eImageInfo.ImageSize = _wcstoui64(value, &pEnd, 16);
            }
            else if (0 == lstrcmpW(propName.c_str(), L"ProcessId")) {
                eImageInfo.ProcessId = _wtoi(value);
                if (eImageInfo.ProcessId <= 4)
                    return;
            }
            else if (0 == lstrcmpW(propName.c_str(), L"ImageChecksum")) {
                eImageInfo.ImageChecksum = _wtoi(value);
            }
            else if (0 == lstrcmpW(propName.c_str(), L"TimeDateStamp")) {
                eImageInfo.TimeDateStamp = _wtoi(value);
            }
            else if (0 == lstrcmpW(propName.c_str(), L"SignatureLevel")) {
                eImageInfo.SignatureLevel = _wtoi(value);
            }
            else if (0 == lstrcmpW(propName.c_str(), L"SignatureType")) {
                eImageInfo.SignatureType = _wtoi(value);
            }
            else if (0 == lstrcmpW(propName.c_str(), L"Reserved0")) {
            }
            else if (0 == lstrcmpW(propName.c_str(), L"DefaultBase")) {
                eImageInfo.DefaultBase = _wcstoui64(value, &pEnd, 16);
            }
            else if (0 == lstrcmpW(propName.c_str(), L"Reserved1")) {
            }
            else if (0 == lstrcmpW(propName.c_str(), L"Reserved2")) {
            }
            else if (0 == lstrcmpW(propName.c_str(), L"Reserved3")) {
            }
            else if (0 == lstrcmpW(propName.c_str(), L"Reserved4")) {
            }
            else if (0 == lstrcmpW(propName.c_str(), L"FileName")) {
                lstrcpynW(eImageInfo.FileName, value, MAX_PATH);
            }
        }

        UPubNode* pEtwData = nullptr;
        pEtwData = (UPubNode*)new char[g_EtwImageDataLens];
        if (pEtwData == nullptr)
            return;
        pEtwData->taskid = UF_ETW_IMAGEMOD;
        RtlCopyMemory(&pEtwData->data[0], &eImageInfo, sizeof(UEtwImageInfo));
        if (g_EtwQueue_Ptr && g_EtwQueueCs_Ptr && g_JobQueue_Event)
        {
            std::unique_lock<std::mutex> lock(*g_EtwQueueCs_Ptr);
            g_EtwQueue_Ptr->push(pEtwData);
            SetEvent(g_JobQueue_Event);
        }
    }
    catch (...)
    {
    }
}
void WINAPI SystemCallEventInfo(PEVENT_RECORD rec, PTRACE_EVENT_INFO info)
{
    if ((info == nullptr) || (rec == nullptr))
        return;
    if (info->TaskNameOffset <= 0)
        return;

    auto userlen = rec->UserDataLength;
    auto data = (PBYTE)rec->UserData;
    auto pointerSize = (rec->EventHeader.Flags & EVENT_HEADER_FLAG_32_BIT_HEADER) ? 4 : 8;

    wchar_t* pEnd = nullptr;
    ULONG len = 0; WCHAR value[512] = { 0, };
    wstring tmpstr = L""; wstring propName = L"";
    if (info->OpcodeNameOffset)
    {
        const wstring EventName = (PCWSTR)((BYTE*)info + info->OpcodeNameOffset);
        if (EventName != L"SysClEnter")
            return;
        //if (!EventName.empty())
        //    wcscpy_s(thread_info.EventName, EventName.c_str());
    }

    for (DWORD i = 0; i < info->TopLevelPropertyCount; i++) {

        propName.clear(); tmpstr.clear();

        auto& pi = info->EventPropertyInfoArray[i];
        propName = (PCWSTR)((BYTE*)info + pi.NameOffset);
        len = pi.length;
        if ((pi.Flags & (PropertyStruct | PropertyParamCount)) == 0) {
            PEVENT_MAP_INFO mapInfo = nullptr;
            std::unique_ptr<BYTE[]> mapBuffer;
            PWSTR mapName = nullptr;
            if (pi.nonStructType.MapNameOffset) {
                ULONG size = 0;
                mapName = (PWSTR)((BYTE*)info + pi.nonStructType.MapNameOffset);
                if (ERROR_INSUFFICIENT_BUFFER == ::TdhGetEventMapInformation(rec, mapName, mapInfo, &size)) {
                    mapBuffer = std::make_unique<BYTE[]>(size);
                    mapInfo = reinterpret_cast<PEVENT_MAP_INFO>(mapBuffer.get());
                    if (ERROR_SUCCESS != ::TdhGetEventMapInformation(rec, mapName, mapInfo, &size))
                        mapInfo = nullptr;
                }
            }

            ULONG size = sizeof(value);
            USHORT consumed;
            auto error = ::TdhFormatProperty(info, mapInfo, pointerSize,
                pi.nonStructType.InType, pi.nonStructType.OutType,
                (USHORT)len, userlen, data, &size, value, &consumed);
            if (ERROR_SUCCESS == error) {
                len = consumed;
                if (mapName)
                    lstrcatW(value, mapName);
            }
            else if (mapInfo) {
                error = ::TdhFormatProperty(info, nullptr, pointerSize,
                    pi.nonStructType.InType, pi.nonStructType.OutType,
                    (USHORT)len, userlen, data, &size, value, &consumed);
            }

        }

        userlen -= (USHORT)len;
        data += len;

        if (0 == lstrcmpW(propName.c_str(), L"SysCallAddress")) {
            //thread_info.processId = wcstol(value, &end, 16);
        }
    }
}
void WINAPI DispatchEventCallback(PEVENT_RECORD pEvent)
{
    try
    {
        if (g_EtwEventExit || (pEvent == nullptr))
        {
            if (g_ProcessTracehandle)
                CloseTrace(g_ProcessTracehandle);
            g_ProcessTracehandle = 0;
            return;
        }

        WCHAR sGuid[64] = { 0, };
        auto header = pEvent->EventHeader;
        if (0 == ::StringFromGUID2(header.ProviderId, sGuid, _countof(sGuid)))
            return;

        ULONG size = 0;
        auto nStatus = ::TdhGetEventInformation(pEvent, 0, nullptr, nullptr, &size);
        if (size <= 0)
            return;

        const auto buffer = std::make_unique<BYTE[]>(size);
        if (buffer == nullptr) {
            return;
        }

        const auto info = reinterpret_cast<PTRACE_EVENT_INFO>(buffer.get());
        nStatus = ::TdhGetEventInformation(pEvent, 0, nullptr, info, &size);
        if (nStatus != ERROR_SUCCESS)
            return;

        if (0 == lstrcmpW(L"{9A280AC0-C8E0-11D1-84E2-00C04FB998A2}", sGuid) || \
            0 == lstrcmpW(L"{BF3A50C5-A9C9-4988-A005-2DF0B7C80F80}", sGuid))
            NetWorkEventInfo(pEvent, info);
        else if (0 == lstrcmpW(L"{3D6FA8D1-FE05-11D0-9DDA-00C04FD7BA7C}", sGuid))
            ThreadEventInfo(pEvent, info);
        else if (0 == lstrcmpW(L"{3D6FA8D0-FE05-11D0-9DDA-00C04FD7BA7C}", sGuid))
            ProcessEventInfo(pEvent, info);
        else if (0 == lstrcmpW(L"{90CBDC39-4A3E-11D1-84F4-0000F80464E3}", sGuid))
            FileEventInfo(pEvent, info);
        else if (0 == lstrcmpW(L"{AE53722E-C863-11D2-8659-00C04FA321A1}", sGuid))
            RegisterTabEventInfo(pEvent, info);
        else if (0 == lstrcmpW(L"{2CB15D1D-5FC1-11D2-ABE1-00A0C911F518}", sGuid))
            ImageModEventInfo(pEvent, info);
        else if (0 == lstrcmpW(L"{CE1DBFB4-137E-4DA6-87B0-3F59AA102CBC}", sGuid))
            SystemCallEventInfo(pEvent, info);
    }
    catch (...)
    {
    }
}

UEtw::UEtw()
{
    g_EtwEventExit = false;
    g_EtwNetworkDataLens = sizeof(UPubNode) + sizeof(UEtwNetWork);
    g_EtwProcessDataLens = sizeof(UPubNode) + sizeof(UEtwProcessInfo);
    g_EtwThreadDataLens = sizeof(UPubNode) + sizeof(UEtwThreadInfo);
    g_EtwImageDataLens = sizeof(UPubNode) + sizeof(UEtwImageInfo);
    g_EtwRegtabDataLens = sizeof(UPubNode) + sizeof(UEtwRegisterTabInfo);
    g_EtwFileIoDataLens = sizeof(UPubNode) + sizeof(UEtwFileIoTabInfo);
}
UEtw::~UEtw()
{
    g_EtwEventExit = true;

    if (g_OnProcessNotify)
        g_OnProcessNotify = nullptr;

    g_EtwQueue_Ptr = nullptr;
    g_EtwQueueCs_Ptr = nullptr;
    g_JobQueue_Event = nullptr;
}

// �����ߣ����Ķ��ж�ָ���ʼ��
void UEtw::uf_setqueuetaskptr(std::queue<UPubNode*>& qptr) { g_EtwQueue_Ptr = &qptr; }
void UEtw::uf_setqueuelockptr(std::mutex& qptrcs) { g_EtwQueueCs_Ptr = &qptrcs; }
void UEtw::uf_setqueueeventptr(HANDLE& eventptr) { g_JobQueue_Event = eventptr; }

// [NT Kernel Logger] Sessionע������/����/�ص�
static DWORD WINAPI tracDispaththread(LPVOID param)
{
    g_EtwEventExit = false;
    EVENT_TRACE_LOGFILE trace;
    memset(&trace, 0, sizeof(trace));
    trace.LoggerName = const_cast<wchar_t*>(KERNEL_LOGGER_NAME);
    trace.LogFileName = NULL;
    trace.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    trace.Context = NULL;
    trace.IsKernelTrace = true;

    // ȱ�ݣ�EventRecordCallback���ַ�ʽ������Event�������ز�ͬ���¼�����������
    // �ٶ�(�Բ�����): ImageLoad & Process & Thread >= RegisterTab & FileIO >= Network 
    trace.EventRecordCallback = DispatchEventCallback;

    g_ProcessTracehandle = OpenTrace(&trace);
    if (g_ProcessTracehandle == (TRACEHANDLE)INVALID_HANDLE_VALUE)
        return 0;
    OutputDebugString(L"[Etw Trace] KernelMod ProcessTrace Start");
    ProcessTrace(&g_ProcessTracehandle, 1, 0, 0);
    CloseTrace(g_ProcessTracehandle);
    return 0;
}
bool UEtw::uf_RegisterTrace(const int dwEnableFlags)
{
    OutputDebugString(L"[Etw Trace] KernelMod uf_RegisterTrace Entry");

    ULONG status = 0;
    TRACEHANDLE hSession;
    uint32_t event_buffer = sizeof(EVENT_TRACE_PROPERTIES) + sizeof(KERNEL_LOGGER_NAME);
    if (event_buffer <= 0)
        return false;

    EVENT_TRACE_PROPERTIES* m_traceconfig = reinterpret_cast<EVENT_TRACE_PROPERTIES*>(new char[event_buffer]);
    if (!m_traceconfig)
        return false;

    // ע��
    //auto nret = SetTraceCallback(&FileIoGuid, FileTraceEventInfo);
    RtlZeroMemory(m_traceconfig, event_buffer);
    m_traceconfig->Wnode.BufferSize = event_buffer;
    m_traceconfig->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    // ��¼�¼���ʱ�� 100ns
    m_traceconfig->Wnode.ClientContext = 1;
    // ʹ�� NT Kernel Logger + SystemTraceControlGuid {9e814aad-3204-11d2-9a82-006008a86939}
    // See Msdn: https://docs.microsoft.com/en-us/windows/win32/etw/nt-kernel-logger-constants
    GUID GSystem;
    RtlSecureZeroMemory(&GSystem, sizeof(GSystem));
    GSystem.Data1 = 0x9e814aad;
    GSystem.Data2 = 0x3204;
    GSystem.Data3 = 0x11d2;
    GSystem.Data4[0] = 0x9a;   GSystem.Data4[1] = 0x82;   GSystem.Data4[2] = 0x00;   GSystem.Data4[3] = 0x60;
    GSystem.Data4[4] = 0x08;   GSystem.Data4[5] = 0xa8;   GSystem.Data4[6] = 0x69;   GSystem.Data4[4] = 0x39;
    m_traceconfig->Wnode.Guid = GSystem;
    m_traceconfig->EnableFlags = dwEnableFlags;
    m_traceconfig->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    m_traceconfig->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);

    EVENT_TRACE_PROPERTIES* temp_config = reinterpret_cast<EVENT_TRACE_PROPERTIES*>(new char[event_buffer]);
    memcpy(temp_config, m_traceconfig, event_buffer);

    bool memflag = false;
    TracGuidNode tracinfo = { 0, };
    tracinfo.bufconfig = temp_config;
    tracinfo.event_tracid = dwEnableFlags;

    /// NT Kernel Logger
    status = StartTrace((PTRACEHANDLE)&hSession, KERNEL_LOGGER_NAME, temp_config);
    if (ERROR_SUCCESS != status)
    {
        /// �Ѿ����� Stop
        if (ERROR_ALREADY_EXISTS == status)
        {
            status = ControlTrace(NULL, KERNEL_LOGGER_NAME, temp_config, EVENT_TRACE_CONTROL_STOP);
            if (SUCCEEDED(status))
            {
                status = StartTrace(&hSession, KERNEL_LOGGER_NAME, m_traceconfig);
                if (ERROR_SUCCESS != status)
                {
                    OutputDebugString((L"[Etw Trace] ����EtwStartTraceʧ�� " + std::to_wstring(GetLastError())).c_str());
                    return 0;
                }
                tracinfo.bufconfig = m_traceconfig;
                tracinfo.event_tracid = dwEnableFlags;
                memflag = true;
            }
            // ʹ���Ժ�temp_config��Ч,ʹ��m_traceconfig,�ͷ�
            if (temp_config)
            {
                delete[] temp_config;
                temp_config = nullptr;
            }
        }
    }
    // û��ʹ��m_traceconfig�����ڴ�,�ͷ�
    if (false == memflag)
    {
        if (m_traceconfig)
        {
            delete[] m_traceconfig;
            m_traceconfig = nullptr;
        }
    }

    {
        std::unique_lock<std::mutex> lock(g_ms);
        g_tracMap[hSession] = tracinfo;
    }

    {
        std::unique_lock<std::mutex> lock(g_th);
        DWORD ThreadID = 0;
        HANDLE hThread = CreateThread(NULL, 0, tracDispaththread, (PVOID)dwEnableFlags, 0, &ThreadID);
        g_thrhandle.emplace_back(hThread);
    }

    OutputDebugString(L"[Etw Trace] KernelMod Register TracGuid Success");
    return true;
}

// [Guid File Logger] Sessionע������/����/�ص�
static DWORD WINAPI tracDispaththreadFile(LPVOID param)
{
    EVENT_TRACE_LOGFILE trace;
    memset(&trace, 0, sizeof(trace));
    trace.LoggerName = const_cast<LPWSTR>(SESSION_NAME_FILE);
    trace.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    trace.Context = NULL;
    trace.EventRecordCallback = DispatchLogEventCallback;

    g_ProcessTracehandle = OpenTrace(&trace);
    if (g_ProcessTracehandle == (TRACEHANDLE)INVALID_HANDLE_VALUE)
        return 0;
    OutputDebugString(L"[Etw Trace] UserMod ProcessTrace Start.");
    ProcessTrace(&g_ProcessTracehandle, 1, 0, 0);
    CloseTrace(g_ProcessTracehandle);
    OutputDebugString(L"[Etw Trace] UserMod ProcessTrace End.");
    return 0;
}
bool UEtw::uf_RegisterTraceFile()
{
    OutputDebugString(L"[Etw Trace] UserMod uf_RegisterTraceFile");

    static const GUID UserModGuid = { 0x6f16819e, 0x0432, 0xd211, { 0x9a, 0x82, 0x00, 0x60, 0x08, 0xa8, 0x69, 0x39 } };
    WCHAR m_LogEventPath[MAX_PATH * 2] = { 0 };
    GetCurrentDirectoryW(MAX_PATH, m_LogEventPath);
    wcscat_s(m_LogEventPath, L"\\HadesHidsWinEtwFile.etl");

    // ע��
    ULONG bufferSize = sizeof(EVENT_TRACE_PROPERTIES) + (wcslen(SESSION_NAME_FILE) + 1) * sizeof(WCHAR) + 0x1000 * 2;
    g_traceConfigNode.Wnode.BufferSize = bufferSize;
    g_traceConfigNode.Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    // ��¼�¼���ʱ�� 100ns
    g_traceConfigNode.Wnode.ClientContext = 1;
    // See Msdn: https://docs.microsoft.com/en-us/windows/win32/etw/nt-kernel-logger-constants
    g_traceConfigNode.BufferSize = 64;  // 64kb
    g_traceConfigNode.FlushTimer = 0;   // flush time
    g_traceConfigNode.MinimumBuffers = 16;
    g_traceConfigNode.MaximumBuffers = 128;
    g_traceConfigNode.LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    g_traceConfigNode.LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
    g_traceConfigNode.MaximumFileSize = 1; // 1MB

    g_pTraceConfig.trace_propertise = g_traceConfigNode;
    g_pTraceConfig.trace_propertise.Wnode.Guid = UserModGuid;
    g_pTraceConfig.session_name = SESSION_NAME_FILE;
    g_pTraceConfig.filelog_path = m_LogEventPath;

    ULONG nStatus = 0;
    nStatus = StartTrace((PTRACEHANDLE)&m_hFileSession, g_pTraceConfig.session_name.c_str(), (PEVENT_TRACE_PROPERTIES)(&g_pTraceConfig.trace_propertise));
    do
    {
        if (ERROR_SUCCESS == nStatus)
            break;
        // ������
        if (ERROR_ALREADY_EXISTS == nStatus)
        {
            StopTrace(m_hFileSession, g_pTraceConfig.session_name.c_str(), (PEVENT_TRACE_PROPERTIES)(&g_pTraceConfig.trace_propertise));
            nStatus = ControlTrace(m_hFileSession, g_pTraceConfig.session_name.c_str(), (PEVENT_TRACE_PROPERTIES)(&g_pTraceConfig.trace_propertise), EVENT_TRACE_CONTROL_STOP);
            if (SUCCEEDED(nStatus))
            {
                nStatus = StartTrace(&m_hFileSession, g_pTraceConfig.session_name.c_str(), (PEVENT_TRACE_PROPERTIES)(&g_pTraceConfig.trace_propertise));
                if (ERROR_SUCCESS != nStatus)
                {
                    OutputDebugString((L"[Etw Trace] ����EtwStartTraceʧ�� " + std::to_wstring(nStatus)).c_str());
                    return 0;
                }
            }
        }
        else {
            OutputDebugString((L"[Etw Trace] ����EtwStartTraceʧ��  " + std::to_wstring(nStatus)).c_str());
            return 0;
        }
    } while (false);


    // Enable Trace
    //EnableTraceEx2(m_hFileSession, &RegistryProviderGuid,
    //    EVENT_CONTROL_CODE_ENABLE_PROVIDER,
    //    TRACE_LEVEL_VERBOSE, 0x14, 0, 0, nullptr);
    //EnableTraceEx2(m_hFileSession, &FileProviderGuid,
    //    EVENT_CONTROL_CODE_ENABLE_PROVIDER,
    //    TRACE_LEVEL_VERBOSE, 0x10, 0, 0, nullptr);
    EnableTraceEx2(m_hFileSession, &ProcessProviderGuid,
        EVENT_CONTROL_CODE_ENABLE_PROVIDER,
        TRACE_LEVEL_VERBOSE, 0x10, 0, 0, nullptr);
    EnableTraceEx2(m_hFileSession, &DnsClientWin7Guid,
        EVENT_CONTROL_CODE_ENABLE_PROVIDER,
        TRACE_LEVEL_VERBOSE, 0, 0, 0, nullptr);
    EnableTraceEx2(m_hFileSession, &DnsClientGuid,
        EVENT_CONTROL_CODE_ENABLE_PROVIDER,
        TRACE_LEVEL_VERBOSE, 0, 0, 0, nullptr);

    //��ʼ���ٽ���
    {
        std::unique_lock<std::mutex> lock(g_th);
        DWORD dwTid = 0;
        HANDLE hThread = CreateThread(NULL, 0, tracDispaththreadFile, NULL, 0, &dwTid);
        g_thrhandle.emplace_back(hThread);
    }

    OutputDebugString(L"[Etw Trace] UserMod Register TracGuid Success");
    return true;
}

// [NT Kernel Logger]
bool UEtw::uf_init()
{
    // EVENT_TRACE_FLAG_REGISTRY
    OutputDebugString(L"[Etw Trace] KernelMod ETW Init.");
    bool test = false;
    if (!test && !uf_RegisterTrace(
        EVENT_TRACE_FLAG_NETWORK_TCPIP | \
        EVENT_TRACE_FLAG_PROCESS | \
        EVENT_TRACE_FLAG_THREAD | \
        EVENT_TRACE_FLAG_IMAGE_LOAD | \
        EVENT_TRACE_FLAG_FILE_IO | EVENT_TRACE_FLAG_FILE_IO_INIT)) {
        return 0;
    }
    else if (test)
    {
        // EVENT_TRACE_FLAG_SYSTEMCALL ��Ҫӳ���ַ�ͽ��̵�ַ������PID
        if (!uf_RegisterTrace(EVENT_TRACE_FLAG_SYSTEMCALL))
            return 0;
    }
    return 1;
}
bool UEtw::uf_close()
{
    if (g_EtwEventExit)
        return false;
    try
    {
        // ���⣺ControlTraceֹͣ��ProcessTrace�Ի�������ͨ��logman -ets query "NT Kernel Logger"��ѯ���Ѿ��ر�״̬
        // ����취��ProcessTrace�ص��������˳���־λ����Event����ر�ProcessTrace����.
        g_EtwEventExit = true;
        // ֹͣEtw_Session
        map<TRACEHANDLE, TracGuidNode>::iterator  iter;
        for (iter = g_tracMap.begin(); iter != g_tracMap.end();)
        {
            if (iter->first && iter->second.bufconfig)
            {
                ControlTrace(iter->first, KERNEL_LOGGER_NAME, iter->second.bufconfig, EVENT_TRACE_CONTROL_STOP);
                CloseTrace(iter->first);
            }
            else
                ControlTrace(NULL, KERNEL_LOGGER_NAME, iter->second.bufconfig, EVENT_TRACE_CONTROL_STOP);

            if (iter->second.bufconfig)
            {
                delete[] iter->second.bufconfig;
                iter->second.bufconfig = NULL;
            }

            std::unique_lock<std::mutex> lock(g_ms);
            g_tracMap.erase(iter++);
        }

        g_etwFileReadFilter.clear();
        g_etwFileWriteilter.clear();
        g_etwFileDirEnumFilter.clear();

        {
            std::unique_lock<std::mutex> lock(g_th);
            for (size_t i = 0; i < g_thrhandle.size(); ++i)
            {
                WaitForSingleObject(g_thrhandle[i], 1000);
                CloseHandle(g_thrhandle[i]);
            }
            g_thrhandle.clear();
        }
    }
    catch (const std::exception&)
    {
    }
    return true;
}

// [Guid File Logger]
bool UEtw::uf_init(const bool flag)
{
    OutputDebugString(L"[Etw Trace] UserMod ETW Init.");
    if (!uf_RegisterTraceFile())
        return 0;
    return 1;
}
bool UEtw::uf_close(const bool flag)
{
    // ֹͣEtw_Session
    StopTrace(m_hFileSession, g_pTraceConfig.session_name.c_str(), (PEVENT_TRACE_PROPERTIES)(&g_pTraceConfig.trace_propertise));
    ControlTrace(m_hFileSession, g_pTraceConfig.session_name.c_str(), (PEVENT_TRACE_PROPERTIES)(&g_pTraceConfig.trace_propertise), EVENT_TRACE_CONTROL_STOP);
    m_hFileSession = 0;

    std::unique_lock<std::mutex> lock(g_th);
    for (size_t i = 0; i < g_thrhandle.size(); ++i)
    {
        WaitForSingleObject(g_thrhandle[i], 1000);
        CloseHandle(g_thrhandle[i]);
    }
    g_thrhandle.clear();
    return true;
}

// Setting Callback
void UEtw::set_on_processMonitor(const std::function<void(const PROCESSINFO&)>& g_OnProcessNotifydata)
{
    g_OnProcessNotify = g_OnProcessNotifydata;
}

// [NT Kernel Logger] Setting Stu
unsigned long UEtw::uf_setmonitor(unsigned __int64 hSession, PVOID64 m_traceconfig, const int ioct)
{
    ULONG nRet = 0;
    if (hSession && m_traceconfig)
        nRet = ControlTrace(hSession, KERNEL_LOGGER_NAME, (PEVENT_TRACE_PROPERTIES)m_traceconfig, ioct);

    if (m_traceconfig)
    {
        delete[] m_traceconfig;
        m_traceconfig = NULL;
    }
    return nRet;
}