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

#include "sync.h"
#include "uetw.h"

#pragma comment(lib,"psapi.lib")
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Tdh.lib")

using namespace std;

// Process Event_Notify
static std::function<void(const PROCESSINFO&)> on_processinfo_ = nullptr;

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

// SystemCall ProcessInfo
static std::map<UINT64, UINT64> g_etwThrPidToStartAddrLimt;
static std::map<UINT64, std::queue<std::string>> g_etwSystemCallToPid;

// Etw Event Manage
// Session - Guid - tracconfig
typedef struct _TracGuidNode
{
    DWORD                        event_tracid;
    EVENT_TRACE_PROPERTIES*      bufconfig;
}TracGuidNode, *PTracGuidNode;
static AutoCriticalSection              g_ms;
static map<TRACEHANDLE, TracGuidNode>   g_tracMap;
static AutoCriticalSection              g_th;
static vector<HANDLE>                   g_thrhandle;

// Grpc task Queue_buffer ptr
static std::queue<UPubNode*>*         g_EtwQueue_Ptr = NULL;
static std::mutex*                    g_EtwQueueCs_Ptr = NULL;
static HANDLE                         g_jobQueue_Event = NULL;
static bool                           g_etwevent_exit = false;
static TRACEHANDLE                    g_processTracehandle;

// Buf_lens
static int etw_networklens = 0;
static int etw_processinfolens = 0;
static int etw_threadinfolens = 0;
static int etw_imageinfolens = 0;
static int etw_regtabinfolens = 0;
static int etw_fileioinfolens = 0;

// [ALL]
void Wchar_tToString(std::string& szDst, const wchar_t* wchar)
{
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

UEtw::UEtw()
{
    etw_networklens = sizeof(UPubNode) + sizeof(UEtwNetWork);
    etw_processinfolens = sizeof(UPubNode) + sizeof(UEtwProcessInfo);
    etw_threadinfolens = sizeof(UPubNode) + sizeof(UEtwThreadInfo);
    etw_imageinfolens = sizeof(UPubNode) + sizeof(UEtwImageInfo);
    etw_regtabinfolens = sizeof(UPubNode) + sizeof(UEtwRegisterTabInfo);
    etw_fileioinfolens = sizeof(UPubNode) + sizeof(UEtwFileIoTabInfo);
    g_etwevent_exit = false;
}
UEtw::~UEtw()
{
}

// [ALL] public interface set queue pointer 
// 消费者：订阅队列队指针初始化
void UEtw::uf_setqueuetaskptr(std::queue<UPubNode*>& qptr) { g_EtwQueue_Ptr = &qptr; }
void UEtw::uf_setqueuelockptr(std::mutex& qptrcs) { g_EtwQueueCs_Ptr = &qptrcs; }
void UEtw::uf_setqueueeventptr(HANDLE& eventptr) { g_jobQueue_Event = eventptr; }

// [ALL] Pid Get ProcessPath
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
void WINAPI ProcessEventFileLogInfo(PEVENT_RECORD EventRecord)
{
    const int EventProcesId = EventRecord->EventHeader.EventDescriptor.Id;
    if ((EventProcesId == 1) || (EventProcesId == 2))
    {
        try
        {
            PROCESSINFO processinfo_data = { 0, };
            if (1 == EventProcesId)
            {
                std::wstring processPath = wstring((wchar_t*)(((PUCHAR)EventRecord->UserData) + 60));
                size_t found = 0;
                if (!processPath.empty())
                    found = processPath.find_last_of(L"/\\");
                processinfo_data.endprocess = true;
                processinfo_data.pid = *(ULONG*)(((PUCHAR)EventRecord->UserData) + 0);
                //Name: wstring((wchar_t*)(((PUCHAR)EventRecord->UserData) + 84));
                //if ((found > 0) && (found < MAX_PATH))
                //    processinfo_data.processpath = processPath.substr(found + 1);
                //else
                //    processinfo_data.processName = L"";
                //processinfo_data.commandLine = processPath.c_str();
            }
            else if (2 == EventProcesId)
            {
                /*
                    processinfo_data.processStatus = false;
                    processinfo_data.processsid = *(ULONG*)(((PUCHAR)EventRecord->UserData) + 0);
                    processinfo_data.processName = L"";
                */
            }
            //OutputDebugString((L"[UetwMM Process] Pid: " + to_wstring(processinfo_data.processsid) + L" Status" + to_wstring(processinfo_data.processStatus) + L" Path: " + processinfo_data.processName).c_str());
            on_processinfo_(processinfo_data);
        }
        catch (const std::exception&)
        {
            OutputDebugString(L"[UetwMM] Uetw Error");
        }
    }
}
void WINAPI FileEventFileLogInfo(PEVENT_RECORD rec)
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

// 生产者：Etw事件回调 - 数据推送至订阅消息队列(消费者)
// [NT Kernel Logger] PEVENT_RECORD回调
// 优化：new换智能指针 or 引入内存池(最优)
void WINAPI NetWorkEventInfo(PEVENT_RECORD rec, PTRACE_EVENT_INFO info) {
    // TCPIP or UDPIP
     if (!info->TaskNameOffset)
         return;

    const wstring taskName = (PCWSTR)((BYTE*)info + info->TaskNameOffset);
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

    // properties data length and pointer
    auto userlen = rec->UserDataLength;
    auto data = (PBYTE)rec->UserData;
    auto pointerSize = (rec->EventHeader.Flags & EVENT_HEADER_FLAG_32_BIT_HEADER) ? 4 : 8;

    ULONG len; WCHAR value[512];
    string  tmpstr; wstring propName; DWORD nCode = 0;
    wchar_t cProcessPath[MAX_PATH] = { 0 };
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


            userlen -= (USHORT)len;
            data += len;


            // 保存数据
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

    UPubNode* const EtwData = (UPubNode*)new char[etw_networklens];
    if (!EtwData)
        return;
    RtlZeroMemory(EtwData, etw_networklens);
    EtwData->taskid = UF_ETW_NETWORK;
    RtlCopyMemory(&EtwData->data[0], &etwNetInfo, sizeof(UEtwNetWork));

    if (g_EtwQueue_Ptr && g_EtwQueueCs_Ptr && g_jobQueue_Event)
    {
        std::unique_lock<std::mutex> lock(*g_EtwQueueCs_Ptr);
        g_EtwQueue_Ptr->push(EtwData);
        SetEvent(g_jobQueue_Event);
    }
}
void WINAPI ProcessEventInfo(PEVENT_RECORD rec, PTRACE_EVENT_INFO info)
{
    if (!info->TaskNameOffset)
        return;

    // properties data length and pointer
    auto userlen = rec->UserDataLength;
    auto data = (PBYTE)rec->UserData;
    auto pointerSize = (rec->EventHeader.Flags & EVENT_HEADER_FLAG_32_BIT_HEADER) ? 4 : 8;

    ULONG len = 0; WCHAR value[512] = { 0, };
    wstring  tmpstr = L""; wstring propName = L"";
    UEtwProcessInfo process_info;
    process_info.clear();
    wchar_t* end = nullptr;

    if (info->OpcodeNameOffset)
    {
        const wstring EventName = (PCWSTR)((BYTE*)info + info->OpcodeNameOffset);
        if (!EventName.empty())
            wcscpy_s(process_info.EventName, EventName.c_str());
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
            const long pid = wcstol(value, &end, 16);
            process_info.processId = pid;
        }
        else if (0 == lstrcmpW(L"ParentId", propName.c_str()))
        {
            const long pid = wcstol(value, &end, 16);
            process_info.parentId = pid;
        }
        else if (0 == lstrcmpW(L"ExitStatus", propName.c_str()))
        {
            if (0 >= _wtoi(value))
                process_info.processStatus = false;
            else
                process_info.processStatus = true;
        }
        else if (0 == lstrcmpW(L"CommandLine", propName.c_str()))
        {
            wcscpy_s(process_info.processPath, value);
        }
        else if (0 == lstrcmpW(L"ImageFileName", propName.c_str()))
        {
            wcscpy_s(process_info.processName, value);
        }
    }

    UPubNode* const EtwData = (UPubNode*)new char[etw_processinfolens];
    if (!EtwData)
        return;
    RtlZeroMemory(EtwData, etw_processinfolens);
    EtwData->taskid = UF_ETW_PROCESSINFO;
    RtlCopyMemory(&EtwData->data[0], &process_info, sizeof(UEtwProcessInfo));

    if (g_EtwQueue_Ptr && g_EtwQueueCs_Ptr && g_jobQueue_Event)
    {
        std::unique_lock<std::mutex> lock(*g_EtwQueueCs_Ptr);
        g_EtwQueue_Ptr->push(EtwData);
        SetEvent(g_jobQueue_Event);
    }
}
void WINAPI ThreadEventInfo(PEVENT_RECORD rec, PTRACE_EVENT_INFO info)
{
    if (!info->TaskNameOffset)
        return;

    // properties data length and pointer
    auto userlen = rec->UserDataLength;
    auto data = (PBYTE)rec->UserData;
    auto pointerSize = (rec->EventHeader.Flags & EVENT_HEADER_FLAG_32_BIT_HEADER) ? 4 : 8;

    ULONG len = 0; WCHAR value[512] = { 0, };
    wstring  tmpstr = L""; wstring propName = L"";
    UEtwThreadInfo thread_info;
    thread_info.clear();
    wchar_t* end = nullptr;

    if (info->OpcodeNameOffset)
    {
        const wstring EventName = (PCWSTR)((BYTE*)info + info->OpcodeNameOffset);
        if (!EventName.empty())
            wcscpy_s(thread_info.EventName, EventName.c_str());
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

        if (0 == lstrcmpW(propName.c_str(), L"ProcessId")){
            thread_info.processId = wcstol(value, &end, 16);
        }
        else if (0 == lstrcmpW(propName.c_str(), L"TThreadId")){
            thread_info.threadId = wcstol(value, &end, 16);
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
            thread_info.Win32StartAddr = _wcstoui64(value, &end, 16);
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
            thread_info.ThreadFlags = _wtoi(value);
        }
    }

    if (thread_info.processId && thread_info.threadId)
    {
        UPubNode* const EtwData = (UPubNode*)new char[etw_threadinfolens];
        if (!EtwData)
            return;
        RtlZeroMemory(EtwData, etw_threadinfolens);
        EtwData->taskid = UF_ETW_THREADINFO;
        RtlCopyMemory(&EtwData->data[0], &thread_info, sizeof(UEtwThreadInfo));
        if (g_EtwQueue_Ptr && g_EtwQueueCs_Ptr && g_jobQueue_Event)
        {
            std::unique_lock<std::mutex> lock(*g_EtwQueueCs_Ptr);
            g_EtwQueue_Ptr->push(EtwData);
            SetEvent(g_jobQueue_Event);
        }
    }
}
void WINAPI FileEventInfo(PEVENT_RECORD rec, PTRACE_EVENT_INFO info)
{
    if (!info->TaskNameOffset)
        return;

    // properties data length and pointer
    auto userlen = rec->UserDataLength;
    auto data = (PBYTE)rec->UserData;
    const auto pointerSize = (rec->EventHeader.Flags & EVENT_HEADER_FLAG_32_BIT_HEADER) ? 4 : 8;

    ULONG len = 0; WCHAR value[512] = { 0, };
    wstring  tmpstr = L""; wstring propName = L"";
    UEtwFileIoTabInfo fileio_info;
    fileio_info.clear();
    wchar_t* end = nullptr;

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
            wcscpy_s(fileio_info.EventName, EventName.c_str());
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
            fileio_info.TTID = _wtoi(value);
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
            fileio_info.IrpPtr = _wcstoui64(value, &end, 16);
        }
        else if (0 == lstrcmpW(propName.c_str(), L"FileObject")) {
            fileio_info.FileObject = _wcstoui64(value, &end, 16);
        }
        else if (0 == lstrcmpW(propName.c_str(), L"FileKey")) {
            fileio_info.FileKey = _wcstoui64(value, &end, 16);
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
            wcscpy_s(fileio_info.FilePath, value);
        }
        else if (0 == lstrcmpW(propName.c_str(), L"CreateOptions")) {
            fileio_info.CreateOptions = _wtoi(value);
        }
        else if (0 == lstrcmpW(propName.c_str(), L"ShareAccess")) {
            fileio_info.ShareAccess = _wtoi(value);
        }
        else if (0 == lstrcmpW(propName.c_str(), L"FileAttributes")) {
            fileio_info.FileAttributes = _wtoi(value);
        }
        /*
        * FileIo_Name
        */
        else if (0 == lstrcmpW(propName.c_str(), L"FileName")) {
            wcscpy_s(fileio_info.FileName, value);
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
            fileio_info.Offset = _wtoi(value);
        }
    }

    // Filter
    if (0 == lstrcmpW(fileio_info.EventName, L"Read")) {
        std::unique_lock<std::mutex> lock(g_FileReadLock);
        if (g_etwFileReadFilter.end() == g_etwFileReadFilter.find(fileio_info.FileKey)) {
            g_etwFileReadFilter[fileio_info.FileKey] = 0;
        }
        else {
            return;
        }
    }
    else if (0 == lstrcmpW(fileio_info.EventName, L"Write")) {
        std::unique_lock<std::mutex> lock(g_FileWriteLock);
        if (g_etwFileWriteilter.end() == g_etwFileWriteilter.find(fileio_info.FileKey)) {
            g_etwFileWriteilter[fileio_info.FileKey] = 0;
        }
        else {
            return;
        }
    }
    else if (0 == lstrcmpW(fileio_info.EventName, L"DirEnum")) {
        std::unique_lock<std::mutex> lock(g_FileDirEnumLock);
        if (g_etwFileDirEnumFilter.end() == g_etwFileDirEnumFilter.find(fileio_info.FileKey)) {
            g_etwFileDirEnumFilter[fileio_info.FileKey] = 0;
        }
        else {
            return;
        }
    }
    else if (0 == lstrcmpW(fileio_info.EventName, L"Close")) {
        {
            std::unique_lock<std::mutex> lock(g_FileReadLock);
            const auto& iter = g_etwFileReadFilter.find(fileio_info.FileKey);
            if (iter != g_etwFileReadFilter.end())
                g_etwFileReadFilter.erase(iter);
        }
        {
            std::unique_lock<std::mutex> lock(g_FileWriteLock);
            const auto& iter = g_etwFileWriteilter.find(fileio_info.FileKey);
            if (iter != g_etwFileWriteilter.end())
                g_etwFileWriteilter.erase(iter);
        }
        {
            std::unique_lock<std::mutex> lock(g_FileDirEnumLock);
            const auto& iter = g_etwFileDirEnumFilter.find(fileio_info.FileKey);
            if (iter != g_etwFileDirEnumFilter.end())
                g_etwFileDirEnumFilter.erase(iter);
        }
    }

    UPubNode* const EtwData = (UPubNode*)new char[etw_fileioinfolens];
    if (!EtwData)
        return;
    RtlSecureZeroMemory(EtwData, etw_fileioinfolens);
    EtwData->taskid = UF_ETW_FILEIO;
    RtlCopyMemory(&EtwData->data[0], &fileio_info, sizeof(UEtwFileIoTabInfo));

    if (g_EtwQueue_Ptr && g_EtwQueueCs_Ptr && g_jobQueue_Event)
    {
        std::unique_lock<std::mutex> lock(*g_EtwQueueCs_Ptr);
        g_EtwQueue_Ptr->push(EtwData);
        SetEvent(g_jobQueue_Event);
    }
}
void WINAPI RegisterTabEventInfo(PEVENT_RECORD rec, PTRACE_EVENT_INFO info)
{
    if (!info->TaskNameOffset)
        return;

    // properties data length and pointer
    auto userlen = rec->UserDataLength;
    auto data = (PBYTE)rec->UserData;
    const auto pointerSize = (rec->EventHeader.Flags & EVENT_HEADER_FLAG_32_BIT_HEADER) ? 4 : 8;

    ULONG len = 0; WCHAR value[512] = { 0, };
    wstring  tmpstr = L""; wstring propName = L"";
    UEtwRegisterTabInfo regtab_info;
    regtab_info.clear();
    wchar_t* end = nullptr;

    if (info->OpcodeNameOffset)
    {
        const wstring EventName = (PCWSTR)((BYTE*)info + info->OpcodeNameOffset);
        if (!EventName.empty())
            wcscpy_s(regtab_info.EventName, EventName.c_str());
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
        
        if (0 == lstrcmpW(propName.c_str(), L"InitialTime")) {
            regtab_info.InitialTime = wcstoll(value, &end, 10);
        }
        else if (0 == lstrcmpW(propName.c_str(), L"Status")) {
            regtab_info.Status = _wtoi(value);
        }
        else if (0 == lstrcmpW(propName.c_str(), L"Index")) {
            regtab_info.Index = _wtoi(value);
        }
        else if (0 == lstrcmpW(propName.c_str(), L"KeyHandle")) {
            regtab_info.KeyHandle = _wcstoui64(value, &end, 16);
        }
        else if (0 == lstrcmpW(propName.c_str(), L"KeyName")) {
            lstrcpynW(regtab_info.KeyName, value, MAX_PATH);
        }
    }

    UPubNode* const pEtwData = (UPubNode*)new char[etw_regtabinfolens];
    if (!pEtwData)
        return;
    RtlZeroMemory(pEtwData, etw_regtabinfolens);
    pEtwData->taskid = UF_ETW_REGISTERTAB;
    RtlCopyMemory(&pEtwData->data[0], &regtab_info, sizeof(UEtwRegisterTabInfo));

    if (g_EtwQueue_Ptr && g_EtwQueueCs_Ptr && g_jobQueue_Event)
    {
        std::unique_lock<std::mutex> lock(*g_EtwQueueCs_Ptr);
        g_EtwQueue_Ptr->push(pEtwData);
        SetEvent(g_jobQueue_Event);
    }
}
void WINAPI ImageModEventInfo(PEVENT_RECORD rec, PTRACE_EVENT_INFO info)
{
    if (!info->TaskNameOffset)
        return;

    ULONG len = 0; WCHAR value[512] = { 0, };
    wstring  tmpstr = L""; wstring propName = L"";
    UEtwImageInfo etwimagemod_info;
    etwimagemod_info.clear();
    wchar_t* end = nullptr;

    if (info->OpcodeNameOffset)
    {
        const wstring EventName = (PCWSTR)((BYTE*)info + info->OpcodeNameOffset);
        if (EventName == L"DCStart")
            return;
        if (!EventName.empty())
            wcscpy_s(etwimagemod_info.EventName, EventName.c_str());
    }

    // properties data length and pointer
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

        if (0 == lstrcmpW(propName.c_str(), L"ImageBase")) {
            etwimagemod_info.ImageBase = _wcstoui64(value, &end, 16);
        }
        else if (0 == lstrcmpW(propName.c_str(), L"ImageSize")) {
            etwimagemod_info.ImageSize = _wcstoui64(value, &end, 16);
        }
        else if (0 == lstrcmpW(propName.c_str(), L"ProcessId")) {
            etwimagemod_info.ProcessId = _wtoi(value);
            if (etwimagemod_info.ProcessId <= 4)
                return;
        }
        else if (0 == lstrcmpW(propName.c_str(), L"ImageChecksum")) {
            etwimagemod_info.ImageChecksum = _wtoi(value);
        }
        else if (0 == lstrcmpW(propName.c_str(), L"TimeDateStamp")) {
            etwimagemod_info.TimeDateStamp = _wtoi(value);
        }
        else if (0 == lstrcmpW(propName.c_str(), L"SignatureLevel")) {
            etwimagemod_info.SignatureLevel = _wtoi(value);
        }
        else if (0 == lstrcmpW(propName.c_str(), L"SignatureType")) {
            etwimagemod_info.SignatureType = _wtoi(value);
        }
        else if (0 == lstrcmpW(propName.c_str(), L"Reserved0")) {
        }
        else if (0 == lstrcmpW(propName.c_str(), L"DefaultBase")) {
            etwimagemod_info.DefaultBase = _wcstoui64(value, &end, 16);
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
            lstrcpynW(etwimagemod_info.FileName, value, MAX_PATH);
        }
    }

    UPubNode* const pEtwData = (UPubNode*)new char[etw_imageinfolens];
    if (!pEtwData)
        return;
    RtlZeroMemory(pEtwData, etw_imageinfolens);
    pEtwData->taskid = UF_ETW_IMAGEMOD;
    RtlCopyMemory(&pEtwData->data[0], &etwimagemod_info, sizeof(UEtwImageInfo));

    if (g_EtwQueue_Ptr && g_EtwQueueCs_Ptr && g_jobQueue_Event)
    {
        std::unique_lock<std::mutex> lock(*g_EtwQueueCs_Ptr);
        g_EtwQueue_Ptr->push(pEtwData);
        SetEvent(g_jobQueue_Event);
    }
}
void WINAPI SystemCallEventInfo(PEVENT_RECORD rec, PTRACE_EVENT_INFO info)
{
    if (!info->TaskNameOffset)
        return;

    // properties data length and pointer
    auto userlen = rec->UserDataLength;
    auto data = (PBYTE)rec->UserData;
    auto pointerSize = (rec->EventHeader.Flags & EVENT_HEADER_FLAG_32_BIT_HEADER) ? 4 : 8;

    ULONG len = 0; WCHAR value[512] = { 0, };
    wstring  tmpstr = L""; wstring propName = L"";
    wchar_t* end = nullptr;

    if (info->OpcodeNameOffset)
    {
        const wstring EventName = (PCWSTR)((BYTE*)info + info->OpcodeNameOffset);
        if (EventName != L"SysClEnter")
            return;
        if (!EventName.empty());
            //wcscpy_s(thread_info.EventName, EventName.c_str());
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

        if (0 == lstrcmpW(propName.c_str(), L"SysCallAddress")) {
            //thread_info.processId = wcstol(value, &end, 16);
        }
    }
}
void WINAPI DispatchEventHandle(PEVENT_RECORD pEvent)
{
    if (true == g_etwevent_exit)
    {
        if (g_processTracehandle)
            CloseTrace(g_processTracehandle);
        return;
    }
    WCHAR sGuid[64] = { 0, };
    const auto& header = pEvent->EventHeader;
    ::StringFromGUID2(header.ProviderId, sGuid, _countof(sGuid));

    ULONG size = 0;
    auto nStatus = ::TdhGetEventInformation(pEvent, 0, nullptr, nullptr, &size);
    if (size <= 0)
        return;

    const auto buffer = std::make_unique<BYTE[]>(size);
    if (!buffer) {
        OutputDebugString(L"buffer Error Exit Etw Monitor");
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

// [NT Kernel Logger] Session注册启动/跟踪/回调
static DWORD WINAPI tracDispaththread(LPVOID param)
{
    g_etwevent_exit = false;
    EVENT_TRACE_LOGFILE trace;
    memset(&trace, 0, sizeof(trace));
    trace.LoggerName = const_cast<wchar_t*>(KERNEL_LOGGER_NAME);
    trace.LogFileName = NULL;
    trace.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    trace.Context = NULL;
    trace.IsKernelTrace = true;
    // 缺陷：EventRecordCallback这种方式如果多个Event，处理单回不同的事件调触发很慢
    // 速度(自测评估): ImageLoad & Process & Thread >= RegisterTab & FileIO >= Network 
    trace.EventRecordCallback = DispatchEventHandle;

    g_processTracehandle = OpenTrace(&trace);
    if (g_processTracehandle == (TRACEHANDLE)INVALID_HANDLE_VALUE)
        return 0;
    OutputDebugString(L"ProcessTrace Start");
    ProcessTrace(&g_processTracehandle, 1, 0, 0);
    CloseTrace(g_processTracehandle);
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
    // 使用 NT Kernel Logger + SystemTraceControlGuid
    // See Msdn: https://docs.microsoft.com/en-us/windows/win32/etw/nt-kernel-logger-constants
    m_traceconfig->Wnode.Guid = SystemTraceControlGuid;
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
    trace.EventRecordCallback = ProcessEventFileLogInfo;// ProcessEventFileLogInfo;

    g_processTracehandle = OpenTrace(&trace);
    if (g_processTracehandle == (TRACEHANDLE)INVALID_HANDLE_VALUE)
        return 0;
    OutputDebugString(L"[UetwMM] ProcessTrace Start");
    ProcessTrace(&g_processTracehandle, 1, 0, 0);
    return 0;
}
bool UEtw::uf_RegisterTraceFile()
{//目前只有ProcessEvent
    OutputDebugString(L"[UetwMM] uf_RegisterTraceFile");

    ULONG status = 0;
    const UCHAR _Flag[] = { 173, 74, 129, 158, 4, 50, 210, 17, 154, 130, 0, 96, 8, 168, 105, 57 };
    char m_File[256] = { 0, };
    _getcwd(m_File, sizeof(m_File));
    strcat_s(m_File, "\\HadesHidsWinEtwFile.etl");

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

    RtlMoveMemory(g_pTraceConfig + 8, &g_traceconfig, 120);
    RtlCopyMemory(g_pTraceConfig + 128, SESSION_NAME_FILE, sizeof(SESSION_NAME_FILE));
    RtlCopyMemory(g_pTraceConfig + 128 + sizeof(SESSION_NAME_FILE), m_File, strlen(m_File));
    RtlCopyMemory(g_pTraceConfig + 28, _Flag, sizeof(_Flag));

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

    // PsProvGuid
    const UCHAR m_ProcessGUID[] = { 214, 44, 251, 34, 123, 14, 43, 66, 160, 199, 47, 173, 31, 208, 231, 22 };
    EnableTraceEx((LPCGUID)(m_ProcessGUID), 0, m_hFileSession, 1, 0, 16, 0, 0, 0);

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
    OutputDebugString(L"Etw nf_init - uf_RegisterTrace");
    bool test = false;
    if (!test && !uf_RegisterTrace(
        EVENT_TRACE_FLAG_NETWORK_TCPIP | \
        EVENT_TRACE_FLAG_PROCESS | \
        EVENT_TRACE_FLAG_THREAD | \
        /*EVENT_TRACE_FLAG_IMAGE_LOAD | \
        EVENT_TRACE_FLAG_REGISTRY | \*/
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
    if (g_etwevent_exit)
        return false;
    try
    {
        // 问题：ControlTrace停止后，ProcessTrace仍会阻塞，通过logman -ets query "NT Kernel Logger"查询是已经关闭状态
        // 解决办法：ProcessTrace回调函数做退出标志位，从Event里面关闭ProcessTrace即可.
        g_etwevent_exit = true;
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
    if (!on_processinfo_)
        return 0;
    OutputDebugString(L"[UetwMM] File Etw nf_init - uf_RegisterTrace");
#ifdef _DEBUG
    if (!uf_RegisterTraceFile())
        return 0;
    return 1;
#else
    if (!uf_RegisterTraceFile())
        return 0;
    return 1;
#endif
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

// [ALL] 设置回调
void UEtw::set_on_processMonitor(const std::function<void(const PROCESSINFO&)>& on_processinfo_data)
{
    on_processinfo_ = on_processinfo_data;
}

// [NT Kernel Logger] 设置状态
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