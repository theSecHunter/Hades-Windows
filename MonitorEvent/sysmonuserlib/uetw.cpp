#include <winsock2.h>
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

#include "sync.h"
#include "uetw.h"

#pragma comment(lib, "Tdh.lib")
#pragma comment(lib,"psapi.lib")
#pragma comment(lib, "Ws2_32.lib")
using namespace std;

// Etw Event Manage Session - Guid - tracconfig
typedef struct _TracGuidNode
{
    DWORD                        event_tracid;
    EVENT_TRACE_PROPERTIES* bufconfig;
}TracGuidNode, * PTracGuidNode;
static AutoCriticalSection              g_ms;
static map<TRACEHANDLE, TracGuidNode>   g_tracMap;
static AutoCriticalSection              g_th;
static vector<HANDLE>                   g_thrhandle;

// Process Event_Notify
static std::function<void(const PROCESSINFO&)> g_OnProcessNotify = nullptr;

// [Guid File Logger] Event File Logger
static const wchar_t SESSION_NAME_FILE[] = L"HadesEtwTrace";
static EVENT_TRACE_PROPERTIES g_traceconfig;
static UCHAR g_pTraceConfig[2048] = { 0, };

// Write Read Offset Filter
static std::mutex g_FileReadLock;
static std::map<UINT64, UINT64> g_etwFileReadFilter;

static std::mutex g_FileWriteLock;
static std::map<UINT64, UINT64> g_etwFileWriteilter;

static std::mutex g_FileDirEnumLock;
static std::map<UINT64, UINT64> g_etwFileDirEnumFilter;

// Report Task Queue_buffer ptr
static std::queue<UPubNode*>*         g_EtwQueue_Ptr = nullptr;
static std::mutex*                    g_EtwQueueCs_Ptr = nullptr;
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
static const GUID DnsClientWin7Guid =
{ 0x609151dd, 0x4f5, 0x4da7, { 0x97, 0x4c, 0xfc, 0x69, 0x47, 0xea, 0xa3, 0x23 } };
static const GUID DnsClientGuid =
{ 0x1c95126e, 0x7eea, 0x49a9, { 0xa3, 0xfe, 0xa3, 0x78, 0xb0, 0x3d, 0xdb, 0x4d } };
//DEFINE_GUID( /* 609151dd-04f5-4da7-974c-fc6947eaa323 */
//    DnsClientWin7Guid,
//    0x609151dd,
//    0x4f5,
//    0x4da7,
//    0x97, 0x4c, 0xfc, 0x69, 0x47, 0xea, 0xa3, 0x23
//);
//DEFINE_GUID( /*1c95126e-7eea-49a9-a3fe-a378b03ddb4d*/
//    DnsClientGuid,
//    0x1c95126e,
//    0x7eea,
//    0x49a9,
//    0xa3, 0xfe, 0xa3, 0x78, 0xb0, 0x3d, 0xdb, 0x4d);

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
        char buf[64] = { 0. };
        if (S_OK == ::CoCreateGuid(&guid))
        {
            _snprintf(buf, sizeof(buf), "{%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
                guid.Data1, guid.Data2, guid.Data3,
                guid.Data4[0], guid.Data4[1], guid.Data4[2], guid.Data4[3],
                guid.Data4[4], guid.Data4[5], guid.Data4[6], guid.Data4[7]);
        }
        return buf;
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

// [Guid File Logger] File Log Event
void WINAPI ProcessDnsEvent(PEVENT_RECORD rec)
{
    try
    {
        ULONG bufferSize = 0;
        TdhGetEventInformation(rec, 0, nullptr, nullptr, &bufferSize);

        auto buffer = std::make_unique<BYTE[]>(bufferSize);
        auto info = reinterpret_cast<TRACE_EVENT_INFO*>(buffer.get());

        if (TdhGetEventInformation(rec, 0, nullptr, info, &bufferSize) != ERROR_SUCCESS)
            return;

        std::wstring queryName = L"";
        USHORT queryType = 0;

        for (DWORD i = 0; i < info->TopLevelPropertyCount; i++) {
            PROPERTY_DATA_DESCRIPTOR desc;
            DWORD size = 0;
            wchar_t propName[128] = { 0, };

            if (info->EventPropertyInfoArray[i].NameOffset) {
                wcscpy_s(propName, reinterpret_cast<wchar_t*>(
                    reinterpret_cast<BYTE*>(info) + info->EventPropertyInfoArray[i].NameOffset));

                if (wcscmp(propName, L"QueryName") == 0) {
                    desc.PropertyName = reinterpret_cast<ULONGLONG>(propName);
                    desc.ArrayIndex = ULONG_MAX;

                    TdhGetPropertySize(rec, 0, nullptr, 1, &desc, &size);
                    queryName.resize(size / sizeof(wchar_t));
                    TdhGetProperty(rec, 0, nullptr, 1, &desc, size, reinterpret_cast<PBYTE>(&queryName[0]));
                }
                else if (wcscmp(propName, L"QueryType") == 0) {
                    TdhGetProperty(rec, 0, nullptr, 1, &desc, sizeof(queryType), (PBYTE)&queryType);
                }
            }
        }

        std::wstring sOutPut = L"";
        switch (rec->EventHeader.EventDescriptor.Id) {
        case 3008: // DNS 查询开始
            sOutPut = (L"[UetwMM Network] DNS Query: " + queryName + L" Type: " + std::to_wstring(queryType)).c_str();
            break;

        case 3009: {
            // DNS 响应接收
            PROPERTY_DATA_DESCRIPTOR desc;
            desc.PropertyName = reinterpret_cast<ULONGLONG>(L"Result");
            desc.ArrayIndex = ULONG_MAX;
            ULONG result;
            TdhGetProperty(rec, 0, nullptr, 1, &desc, sizeof(result), (PBYTE)&result);
            sOutPut = (L"[UetwMM Network] DNS Response: " + queryName + L" Status: " + std::to_wstring(result)).c_str();
        }
                 break;
        }
        if (!sOutPut.empty())
            OutputDebugString(sOutPut.c_str());
    }
    catch (const std::exception&)
    {
    }
}
void WINAPI ProcessNetworkRecord(PEVENT_RECORD rec)
{
    if (rec == nullptr)
        return;

    ULONG bufferSize = 0;
    ULONG status = ERROR_SUCCESS;
    PTRACE_EVENT_INFO info = nullptr;

    try
    {
        UEtwNetWork etwNetInfo;
        etwNetInfo.clear();
        status = TdhGetEventInformation(rec, 0, nullptr, nullptr, &bufferSize);
        if (status == ERROR_INSUFFICIENT_BUFFER) {
            auto buffer = std::make_unique<BYTE[]>(bufferSize);
            info = reinterpret_cast<PTRACE_EVENT_INFO>(buffer.get());
            status = TdhGetEventInformation(rec, 0, nullptr, info, &bufferSize);
            if (status != ERROR_SUCCESS) return;
        }

        if (info->TaskNameOffset) {
            wstring taskName = (PCWSTR)((BYTE*)info + info->TaskNameOffset);
            if (taskName.find(L"TcpIp") != wstring::npos) {
                etwNetInfo.protocol = IPPROTO_TCP;
            }
            else if (taskName.find(L"UdpIp") != wstring::npos) {
                etwNetInfo.protocol = IPPROTO_UDP;
            }
        }

        if (info->OpcodeNameOffset) {
            wstring opcodeName = (PCWSTR)((BYTE*)info + info->OpcodeNameOffset);
            wcsncpy_s(etwNetInfo.EventName, opcodeName.c_str(), _TRUNCATE);
        }

        auto userData = (PBYTE)rec->UserData;
        auto userDataLength = rec->UserDataLength;
        auto pointerSize = (rec->EventHeader.Flags & EVENT_HEADER_FLAG_32_BIT_HEADER) ? 4 : 8;

        std::string sScrAddress = "";
        std::string sDesAddress = "";
        for (DWORD i = 0; i < info->TopLevelPropertyCount; i++) {
            auto& propInfo = info->EventPropertyInfoArray[i];
            wstring propName = (PCWSTR)((BYTE*)info + propInfo.NameOffset);

            if (propInfo.Flags & (PropertyStruct | PropertyParamCount))
                continue;

            PEVENT_MAP_INFO mapInfo = nullptr;
            std::unique_ptr<BYTE[]> mapBuffer;
            ULONG size = 0;
            WCHAR value[512] = { 0 };
            USHORT consumed = 0;

            status = TdhFormatProperty(
                info,
                nullptr,
                pointerSize,
                propInfo.nonStructType.InType,
                propInfo.nonStructType.OutType,
                static_cast<USHORT>(propInfo.length),
                userDataLength,
                userData,
                &size,
                value,
                &consumed
            );

            if (status != ERROR_SUCCESS) continue;

            userData += consumed;
            userDataLength -= consumed;

            if (propName == L"PID") {
                etwNetInfo.processId = _wtoi(value);
            }
            else if (propName == L"saddr") {
                std::string sTmp = "";
                Wchar_tToString(sTmp, value);
                sScrAddress.append(sTmp).append(":");
                etwNetInfo.ipv4LocalAddr = inet_addr(sTmp.c_str());
            }
            else if (propName == L"daddr") {
                std::string sTmp = "";
                Wchar_tToString(sTmp, value);
                sDesAddress.append(sTmp).append(":");
                etwNetInfo.ipv4toRemoteAddr = inet_addr(sTmp.c_str());
            }
            else if (propName == L"sport") {
                etwNetInfo.toLocalPort = static_cast<USHORT>(_wtoi(value));
                sScrAddress.append(std::to_string(etwNetInfo.toLocalPort));
            }
            else if (propName == L"dport") {
                etwNetInfo.toRemotePort = static_cast<USHORT>(_wtoi(value));
                sDesAddress.append(std::to_string(etwNetInfo.toLocalPort));
            }
            else if (propName == L"size") {
                // netInfo.size = _wtoi(value);
            }
            else if (propName == L"connid") {
                // netInfo.connId = _wtoi64(value);
            }
        }

        OutputDebugStringA(("[UetwMM Process] NetWork Event " + to_string(etwNetInfo.protocol) + " - " + to_string(etwNetInfo.processId) + " - " + sScrAddress + " -> " + sDesAddress).c_str());
        sScrAddress.clear();
        sDesAddress.clear();

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
void WINAPI ProcessRecord(PEVENT_RECORD EventRecord)
{
    if (EventRecord == nullptr)
        return;

    try
    {
        const int EventProcesId = EventRecord->EventHeader.EventDescriptor.Id;
        if ((EventProcesId == 1) || (EventProcesId == 2))
        {
            PROCESSINFO etwProcessInfo = { 0, };
            if (1 == EventProcesId)
            {
                std::wstring processPath = wstring((wchar_t*)(((PUCHAR)EventRecord->UserData) + 60));
                size_t found = 0;
                if (!processPath.empty())
                    found = processPath.find_last_of(L"/\\");
                etwProcessInfo.endprocess = true;
                etwProcessInfo.pid = *(ULONG*)(((PUCHAR)EventRecord->UserData) + 0);
                // Name: wstring((wchar_t*)(((PUCHAR)EventRecord->UserData) + 84));
  /*              if ((found > 0) && (found < MAX_PATH))
                    processinfo_data.processpath = processPath.substr(found + 1);
                else
                    processinfo_data.processName = L"";
                processinfo_data.commandLine = processPath.c_str();*/
                OutputDebugString((L"[UetwMM Process] Process Event " + to_wstring(etwProcessInfo.pid) + L" - " + to_wstring(EventProcesId) + L" - " + processPath).c_str());
            }
            else if (2 == EventProcesId)
            {                
                //etwProcessInfo.processStatus = false;
                //etwProcessInfo.processsid = *(ULONG*)(((PUCHAR)EventRecord->UserData) + 0);
                //etwProcessInfo.processName = L"";
                
            }
            if (g_OnProcessNotify)
                g_OnProcessNotify(etwProcessInfo);
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

            // on skippe tout ce qui est sur le disque
            if (*(PULONGLONG)((SIZE_T)rec->UserData + 0x20) == 0x007600650044005c &&
                *(PULONGLONG)((SIZE_T)rec->UserData + 0x30) == 0x0064007200610048)
                return;

            printf("FILE %d - PID %d - FileName %S - CreateOptions %.8X - CreateAttributes %.8X - ShareAccess %.8X\n",
                Header.EventDescriptor.Id,
                Header.ProcessId,
                (PWSTR)((SIZE_T)rec->UserData + 0x20),
                *(PULONG)((SIZE_T)(rec->UserData) + 0x14),
                *(PULONG)((SIZE_T)(rec->UserData) + 0x18),
                *(PULONG)((SIZE_T)(rec->UserData) + 0x1C));
        }
        else if (Header.EventDescriptor.Id == 10 || Header.EventDescriptor.Id == 11) {

            // on skippe tout ce qui est sur le disque
            if (*(PULONGLONG)((SIZE_T)rec->UserData + 0x8) == 0x007600650044005c &&
                *(PULONGLONG)((SIZE_T)rec->UserData + 0x18) == 0x0064007200610048)
                return;

            printf("FILE %d - PID %d - FileName %S\n",
                Header.EventDescriptor.Id,
                Header.ProcessId,
                (PWSTR)((SIZE_T)rec->UserData + 0x8));

        }
    }
    catch (...)
    {
    }
}
void WINAPI DispatchLogEventCallback(PEVENT_RECORD rec)
{
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
        }
    }
    catch (...)
    {
    }
}

// 生产者：Etw事件回调 - 数据推送至订阅消息队列(消费者)
// [NT Kernel Logger] PEVENT_RECORD回调
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
                        // wtoi不可以转换16进制宽字符 - 这里valuse内存是十进制 - 否则用wcstol
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

                // 提取数据
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

                // 提取数据
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
                // 线程ID
                etwFileIoInfo.TTID = _wtoi(value);
                // Get Pid并不准确
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
                // 文件读写起止位置
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

// 消费者：订阅队列队指针初始化
void UEtw::uf_setqueuetaskptr(std::queue<UPubNode*>& qptr) { g_EtwQueue_Ptr = &qptr; }
void UEtw::uf_setqueuelockptr(std::mutex& qptrcs) { g_EtwQueueCs_Ptr = &qptrcs; }
void UEtw::uf_setqueueeventptr(HANDLE& eventptr) { g_JobQueue_Event = eventptr; }

// [NT Kernel Logger] Session注册启动/跟踪/回调
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

    // 缺陷：EventRecordCallback这种方式如果多个Event，处理单回不同的事件调触发很慢
    // 速度(自测评估): ImageLoad & Process & Thread >= RegisterTab & FileIO >= Network 
    trace.EventRecordCallback = DispatchEventCallback;

    g_ProcessTracehandle = OpenTrace(&trace);
    if (g_ProcessTracehandle == (TRACEHANDLE)INVALID_HANDLE_VALUE)
        return 0;
    OutputDebugString(L"ProcessTrace Start");
    ProcessTrace(&g_ProcessTracehandle, 1, 0, 0);
    CloseTrace(g_ProcessTracehandle);
    return 0;
}
bool UEtw::uf_RegisterTrace(const int dwEnableFlags)
{
    printf("uf_RegisterTrace Entry\n");
    ULONG status = 0;
    TRACEHANDLE hSession;
    uint32_t event_buffer = sizeof(EVENT_TRACE_PROPERTIES) + sizeof(KERNEL_LOGGER_NAME);
    if (event_buffer <= 0)
        return false;

    EVENT_TRACE_PROPERTIES* m_traceconfig = reinterpret_cast<EVENT_TRACE_PROPERTIES*>(new char[event_buffer]);
    if (!m_traceconfig)
        return false;

    // 注册
    //auto nret = SetTraceCallback(&FileIoGuid, FileTraceEventInfo);
    RtlZeroMemory(m_traceconfig, event_buffer);
    m_traceconfig->Wnode.BufferSize = event_buffer;
    m_traceconfig->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    // 记录事件的时钟 100ns
    m_traceconfig->Wnode.ClientContext = 1;
    // 使用 NT Kernel Logger + SystemTraceControlGuid {9e814aad-3204-11d2-9a82-006008a86939}
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
        /// 已经存在 Stop
        if (ERROR_ALREADY_EXISTS == status)
        {
            status = ControlTrace(NULL, KERNEL_LOGGER_NAME, temp_config, EVENT_TRACE_CONTROL_STOP);
            if (SUCCEEDED(status))
            {
                status = StartTrace(&hSession, KERNEL_LOGGER_NAME, m_traceconfig);
                if (ERROR_SUCCESS != status)
                {
                    OutputDebugString(L"启动EtwStartTrace失败");
                    printf("err %d\n", GetLastError());
                    return 0;
                }
                tracinfo.bufconfig = m_traceconfig;
                tracinfo.event_tracid = dwEnableFlags;
                memflag = true;
            }
            // 使用以后temp_config无效,使用m_traceconfig,释放
            if (temp_config)
            {
                delete[] temp_config;
                temp_config = nullptr;
            }
        }
    }
    // 没有使用m_traceconfig申请内存,释放
    if (false == memflag)
    {
        if (m_traceconfig)
        {
            delete[] m_traceconfig;
            m_traceconfig = nullptr;
        }
    }
    g_ms.Lock();
    g_tracMap[hSession] = tracinfo;
    g_ms.Unlock();

    DWORD ThreadID = 0;
    //初始化临界区
    g_th.Lock();
    HANDLE hThread = CreateThread(NULL, 0, tracDispaththread, (PVOID)dwEnableFlags, 0, &ThreadID);
    g_thrhandle.push_back(hThread);
    g_th.Unlock();

    OutputDebugString(L"Register TracGuid Success");
    return true;
}

// [Guid File Logger] Session注册启动/跟踪/回调
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
    OutputDebugString(L"[UetwMM] ProcessTrace Start");
    ProcessTrace(&g_ProcessTracehandle, 1, 0, 0);  
    return 0;
}
bool UEtw::uf_RegisterTraceFile()
{
    OutputDebugString(L"[UetwMM] uf_RegisterTraceFile");

    ULONG status = 0;
    // SystemTraceControlGuid - {9e814aad-3204-11d2-9a82-006008a86939}
    const UCHAR _Flag[] = { 111, 22, 129, 158, 4, 50, 210, 17, 154, 130, 0, 96, 8, 168, 105, 57 };
    char m_LogEventPath[256] = { 0, };
    _getcwd(m_LogEventPath, sizeof(m_LogEventPath));
    strcat_s(m_LogEventPath, "\\HadesHidsWinEtwFile.etl");

    // 注册
    g_traceconfig.Wnode.BufferSize = 1024;
    g_traceconfig.Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    // 记录事件的时钟 100ns
    g_traceconfig.Wnode.ClientContext = 1;
    // See Msdn: https://docs.microsoft.com/en-us/windows/win32/etw/nt-kernel-logger-constants
    g_traceconfig.BufferSize = 1;
    g_traceconfig.FlushTimer = 1;
    g_traceconfig.MinimumBuffers = 16;
    g_traceconfig.LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    g_traceconfig.LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);

    /*
        +8：EVENT_TRACE_PROPERTIES 结构开始位置（跳过8字节头部）
        +28：GUID 在结构中的位置（Wnode.Guid 字段偏移量）
        +128：会话名称存储位置
        +128 + sizeof(SESSION_NAME_FILE)：日志文件路径存储位置 
    */
    RtlMoveMemory(g_pTraceConfig + 8, &g_traceconfig, 120);
    RtlCopyMemory(g_pTraceConfig + 28, _Flag, sizeof(_Flag));
    RtlCopyMemory(g_pTraceConfig + 128, SESSION_NAME_FILE, sizeof(SESSION_NAME_FILE));
    RtlCopyMemory(g_pTraceConfig + 128 + sizeof(SESSION_NAME_FILE), m_LogEventPath, strlen(m_LogEventPath));

    status = StartTrace((PTRACEHANDLE)&m_hFileSession, SESSION_NAME_FILE, (PEVENT_TRACE_PROPERTIES)(g_pTraceConfig + 8));
    if (ERROR_SUCCESS != status)
    {
        /// 已经存在 Stop
        if (ERROR_ALREADY_EXISTS == status)
        {
            StopTrace(m_hFileSession, SESSION_NAME_FILE, (PEVENT_TRACE_PROPERTIES)(g_pTraceConfig + 8));
            status = ControlTrace(m_hFileSession, SESSION_NAME_FILE, (PEVENT_TRACE_PROPERTIES)(g_pTraceConfig + 8), EVENT_TRACE_CONTROL_STOP);
            if (SUCCEEDED(status))
            {
                status = StartTrace(&m_hFileSession, SESSION_NAME_FILE, (PEVENT_TRACE_PROPERTIES)(g_pTraceConfig + 8));
                if (ERROR_SUCCESS != status)
                {
                    OutputDebugString(L"[UetwMM] 启动EtwStartTrace失败");
                    printf("err %d\n", GetLastError());
                    return 0;
                }
            }
        }
    }

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
    EnableTraceEx2(m_hFileSession, &DnsClientGuid,
        EVENT_CONTROL_CODE_ENABLE_PROVIDER,
        TRACE_LEVEL_VERBOSE, 0, 0, 0, nullptr);
    
    DWORD ThreadID = 0;
    //初始化临界区
    g_th.Lock();
    HANDLE hThread = CreateThread(NULL, 0, tracDispaththreadFile, NULL, 0, &ThreadID);
    g_thrhandle.push_back(hThread);
    g_th.Unlock();

    OutputDebugString(L"[UetwMM] Register TracGuid Success");
    return true;
}

// [NT Kernel Logger]
bool UEtw::uf_init()
{
    // EVENT_TRACE_FLAG_REGISTRY
    OutputDebugString(L"Etw nf_init - uf_RegisterTrace");
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
        // EVENT_TRACE_FLAG_SYSTEMCALL 需要映射地址和进程地址，关联PID
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
        // 问题：ControlTrace停止后，ProcessTrace仍会阻塞，通过logman -ets query "NT Kernel Logger"查询是已经关闭状态
        // 解决办法：ProcessTrace回调函数做退出标志位，从Event里面关闭ProcessTrace即可.
        g_EtwEventExit = true;
        // 停止Etw_Session
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

            g_ms.Lock();
            g_tracMap.erase(iter++);
            g_ms.Unlock();
        }

        g_etwFileReadFilter.clear();
        g_etwFileWriteilter.clear();
        g_etwFileDirEnumFilter.clear();

        g_th.Lock();
        for (size_t i = 0; i < g_thrhandle.size(); ++i)
        {
            WaitForSingleObject(g_thrhandle[i], 1000);
            CloseHandle(g_thrhandle[i]);
        }
        g_thrhandle.clear();
        g_th.Unlock();
    }
    catch (const std::exception&)
    {
    }
    return true;
}

// [Guid File Logger]
bool UEtw::uf_init(const bool flag)
{
    OutputDebugString(L"[UetwMM] File Etw nf_init - uf_RegisterTrace");
    if (!uf_RegisterTraceFile())
        return 0;
    return 1;
}
bool UEtw::uf_close(const bool flag)
{
    // 停止Etw_Session
    StopTrace(m_hFileSession, SESSION_NAME_FILE, (PEVENT_TRACE_PROPERTIES)(g_pTraceConfig + 8));
    ControlTrace(m_hFileSession, SESSION_NAME_FILE, (PEVENT_TRACE_PROPERTIES)(g_pTraceConfig + 8), EVENT_TRACE_CONTROL_STOP);

    g_th.Lock();
    for (size_t i = 0; i < g_thrhandle.size(); ++i)
    {
        WaitForSingleObject(g_thrhandle[i], 1000);
        CloseHandle(g_thrhandle[i]);
    }
    g_thrhandle.clear();
    g_th.Unlock();
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