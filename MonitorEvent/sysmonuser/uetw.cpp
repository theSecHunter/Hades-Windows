#include <winsock2.h>
#include <Windows.h>
#include <memory>
#include <Psapi.h>

#define INITGUID
#include <evntrace.h>
#include <evntcons.h>
#include <tdh.h>
#include <in6addr.h>

#include "sysinfo.h"
#include "sync.h"
#include "uetw.h"

#include <map>
#include <mutex>
#include <vector>
#include <string>
#include <wchar.h>

#pragma comment(lib,"psapi.lib")
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Tdh.lib")

using namespace std;

//  映射ProcessInfo 和 NetWork 关系
//  如果都在数据库做分析，这里可以不适用这套方案。
static mutex g_mutx;
static map<DWORD64, NF_CALLOUT_FLOWESTABLISHED_INFO> flowestablished_map;
static mutex g_mutx_pidpath;
static map<int, PROCESS_INFO> mutxpidpath_map;

// Session - Guid - tracconfig
typedef struct _TracGuidNode
{
    DWORD                         event_tracid;
    EVENT_TRACE_PROPERTIES*       bufconfig;
}TracGuidNode, *PTracGuidNode;
static AutoCriticalSection g_ms;
static map<TRACEHANDLE, TracGuidNode> g_tracMap;
static AutoCriticalSection g_th;
static vector<HANDLE> g_thrhandle;

UEtw::UEtw()
{
}
UEtw::~UEtw()
{
}

void Wchar_tToString(std::string& szDst, wchar_t* wchar)
{
    wchar_t* wText = wchar;
    DWORD dwNum = WideCharToMultiByte(CP_OEMCP, NULL, wText, -1, NULL, 0, NULL, FALSE);
    char* psText;
    psText = new char[dwNum];
    WideCharToMultiByte(CP_OEMCP, NULL, wText, -1, psText, dwNum, NULL, FALSE);
    szDst = psText;
    delete[] psText;
}

// Pid Get ProcessPath
DWORD GetPathByProcessId(wchar_t* path, const  DWORD dwPid)
{
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPid);
    if (hProcess == NULL)
        return false;
    return GetModuleFileNameEx(hProcess, NULL, path, MAX_PATH);
}
DWORD uf_GetNetWrokEventStr(wstring& propName)
{
    DWORD Code = 0;

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

    return Code;
}

///////////////////////////////////////////////////
// Network Event_callback
void NetWorkEventInfo(PEVENT_RECORD rec, PTRACE_EVENT_INFO info) {

    NF_CALLOUT_FLOWESTABLISHED_INFO flowestablished_processinfo;
    RtlZeroMemory(&flowestablished_processinfo, sizeof(NF_CALLOUT_FLOWESTABLISHED_INFO));

    // TCPIP or UDPIP
    wstring taskName;
    if (info->TaskNameOffset)
    {
        taskName = (PCWSTR)((BYTE*)info + info->TaskNameOffset);
    }
    else
        return;

    size_t task_tcplen = taskName.find(L"TcpIp");
    size_t task_udplen = taskName.find(L"UdpIp");
    if (task_tcplen >= 0 && task_tcplen <= 100)
    {
        flowestablished_processinfo.protocol = IPPROTO_TCP;
    }
    else if (task_udplen >= 0 && task_udplen <= 100)
    {
        flowestablished_processinfo.protocol = IPPROTO_UDP;
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
    map<int, PROCESS_INFO>::iterator iter;
    PROCESS_INFO process_info = { 0, };
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
                    flowestablished_processinfo.processId = _wtoi(value);
                    iter = mutxpidpath_map.find(flowestablished_processinfo.processId);
                    if (iter != mutxpidpath_map.end())
                    {
                        process_info = iter->second;
                        RtlCopyMemory(flowestablished_processinfo.processPath, process_info.processPath, MAX_PATH);
                    }
                    else
                    {
                        flowestablished_processinfo.processPathSize = GetPathByProcessId(cProcessPath, flowestablished_processinfo.processId);
                        if (flowestablished_processinfo.processPathSize)
                            RtlCopyMemory(flowestablished_processinfo.processPath, cProcessPath, MAX_PATH);
                    }
                }
                break;
                case 3: // daddr
                    Wchar_tToString(tmpstr, value);
                    flowestablished_processinfo.ipv4toRemoteAddr = inet_addr(tmpstr.c_str());
                    break;
                case 4: // saddr
                    Wchar_tToString(tmpstr, value);
                    flowestablished_processinfo.ipv4LocalAddr = inet_addr(tmpstr.c_str());
                    break;
                case 5: // dport
                    flowestablished_processinfo.toRemotePort = _wtoi(value);
                    break;
                case 6: // sport
                    flowestablished_processinfo.toLocalPort = _wtoi(value);
                    break;
                }
            }

        }
    }

    // 映射
    DWORD64 keyLocalPort = flowestablished_processinfo.toLocalPort;
    switch (flowestablished_processinfo.protocol)
    {
    case IPPROTO_TCP:
        keyLocalPort += 1000000;
        break;
    case IPPROTO_UDP:
        keyLocalPort += 2000000;
        break;
    }

    if (lstrlenW(flowestablished_processinfo.processPath))
    {
        g_mutx.lock();
        flowestablished_map[keyLocalPort] = flowestablished_processinfo;
        g_mutx.unlock();
    }

    //WCHAR outputinfo[MAX_PATH] = { 0, };
    //swprintf(outputinfo, MAX_PATH, L"[PushKey] PortKey %d", keyLocalPort);
    //OutputDebugString(outputinfo);
}
void ProcessEventInfo(PEVENT_RECORD rec, PTRACE_EVENT_INFO info)
{
    wstring taskName;
    if (info->TaskNameOffset)
    {
        taskName = (PCWSTR)((BYTE*)info + info->TaskNameOffset);
    }
    else
        return;

    // properties data length and pointer
    auto userlen = rec->UserDataLength;
    auto data = (PBYTE)rec->UserData;
    auto pointerSize = (rec->EventHeader.Flags & EVENT_HEADER_FLAG_32_BIT_HEADER) ? 4 : 8;

    ULONG len; WCHAR value[512];
    wstring  tmpstr; wstring propName;
    PROCESS_INFO process_info = { 0, };
    wchar_t* end;

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
            process_info.processId = wcstol(value, &end, 16);
        }
        else if (0 == lstrcmpW(L"ExitStatus", propName.c_str()))
        {
            // 进程 Exit 不关注
            if (0 >= _wtoi(value))
                return;
        }
        else if (0 == lstrcmpW(L"CommandLine", propName.c_str()))
        {
            if (0 >= lstrlenW(value))
                return;
            // 以' '截取[0].Str();
            if (0 >= lstrlenW(value))
                return;
            tmpstr = value;
            auto nums = tmpstr.find(L".exe");
            tmpstr = tmpstr.substr(0, nums + 4);
            if (0 >= tmpstr.size())
                return;
            lstrcpyW(process_info.processPath, tmpstr.c_str());
        }
    }

    if (0 >= lstrlenW(process_info.processPath))
        return;
    g_mutx_pidpath.lock();
    mutxpidpath_map[process_info.processId] = process_info;
    g_mutx_pidpath.unlock();
}
void ThreadEventInfo(PEVENT_RECORD rec, PTRACE_EVENT_INFO info)
{
    wstring taskName;
    if (info->TaskNameOffset)
    {
        taskName = (PCWSTR)((BYTE*)info + info->TaskNameOffset);
    }
    else
        return;

    // properties data length and pointer
    auto userlen = rec->UserDataLength;
    auto data = (PBYTE)rec->UserData;
    auto pointerSize = (rec->EventHeader.Flags & EVENT_HEADER_FLAG_32_BIT_HEADER) ? 4 : 8;

    ULONG len; WCHAR value[512];
    wstring  tmpstr; wstring propName;
    PROCESS_INFO process_info = { 0, };

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
        }
        else if (0 == lstrcmpW(propName.c_str(), L"TThreadId")){
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
        }
    }

}
void FileEventInfo(PEVENT_RECORD rec, PTRACE_EVENT_INFO info)
{
    wstring taskName;
    if (info->TaskNameOffset)
    {
        taskName = (PCWSTR)((BYTE*)info + info->TaskNameOffset);
    }
    else
        return;

    // properties data length and pointer
    auto userlen = rec->UserDataLength;
    auto data = (PBYTE)rec->UserData;
    auto pointerSize = (rec->EventHeader.Flags & EVENT_HEADER_FLAG_32_BIT_HEADER) ? 4 : 8;

    ULONG len; WCHAR value[512];
    wstring  tmpstr; wstring propName;
    PROCESS_INFO process_info = { 0, };

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

        if (0 == lstrcmpW(propName.c_str(), L"Offset")) {
        }
        else if (0 == lstrcmpW(propName.c_str(), L"IrpPtr")) {
        }
        else if (0 == lstrcmpW(propName.c_str(), L"FileObject")) {
        }
        else if (0 == lstrcmpW(propName.c_str(), L"FileKey")) {
        }
        else if (0 == lstrcmpW(propName.c_str(), L"TTID")) {
        }
        else if (0 == lstrcmpW(propName.c_str(), L"IoSize")) {
        }
        else if (0 == lstrcmpW(propName.c_str(), L"IoFlags")) {
        }
    }
}
void RegisterTabEventInfo(PEVENT_RECORD rec, PTRACE_EVENT_INFO info)
{
    wstring taskName;
    if (info->TaskNameOffset)
    {
        taskName = (PCWSTR)((BYTE*)info + info->TaskNameOffset);
    }
    else
        return;

    // properties data length and pointer
    auto userlen = rec->UserDataLength;
    auto data = (PBYTE)rec->UserData;
    auto pointerSize = (rec->EventHeader.Flags & EVENT_HEADER_FLAG_32_BIT_HEADER) ? 4 : 8;

    ULONG len; WCHAR value[512];
    wstring  tmpstr; wstring propName;
    PROCESS_INFO process_info = { 0, };

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
        }
        else if (0 == lstrcmpW(propName.c_str(), L"Status")) {
        }
        else if (0 == lstrcmpW(propName.c_str(), L"Index")) {
        }
        else if (0 == lstrcmpW(propName.c_str(), L"KeyHandle")) {
        }
        else if (0 == lstrcmpW(propName.c_str(), L"KeyName")) {
        }
    }

}
void ImageModEventInfo(PEVENT_RECORD rec, PTRACE_EVENT_INFO info)
{
    wstring taskName;
    if (info->TaskNameOffset)
    {
        taskName = (PCWSTR)((BYTE*)info + info->TaskNameOffset);
    }
    else
        return;

    // properties data length and pointer
    auto userlen = rec->UserDataLength;
    auto data = (PBYTE)rec->UserData;
    auto pointerSize = (rec->EventHeader.Flags & EVENT_HEADER_FLAG_32_BIT_HEADER) ? 4 : 8;

    ULONG len; WCHAR value[512];
    wstring  tmpstr; wstring propName;
    PROCESS_INFO process_info = { 0, };

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
        }
        else if (0 == lstrcmpW(propName.c_str(), L"ImageSize")) {
        }
        else if (0 == lstrcmpW(propName.c_str(), L"ProcessId")) {
        }
        else if (0 == lstrcmpW(propName.c_str(), L"ImageChecksum")) {
        }
        else if (0 == lstrcmpW(propName.c_str(), L"TimeDateStamp")) {
        }
        else if (0 == lstrcmpW(propName.c_str(), L"SignatureLevel")) {
        }
        else if (0 == lstrcmpW(propName.c_str(), L"SignatureType")) {
        }
        else if (0 == lstrcmpW(propName.c_str(), L"Reserved0")) {
        }
        else if (0 == lstrcmpW(propName.c_str(), L"DefaultBase")) {
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
        }
    }
}
void WINAPI DispatchEventHandle(PEVENT_RECORD pEvent)
{
    WCHAR sguid[64];
    auto& header = pEvent->EventHeader;
    ::StringFromGUID2(header.ProviderId, sguid, _countof(sguid));

    ULONG size = 0;
    auto status = ::TdhGetEventInformation(pEvent, 0, nullptr, nullptr, &size);
    if (size <= 0)
        return;

    auto buffer = std::make_unique<BYTE[]>(size);
    if (!buffer) {
        OutputDebugString(L"buffer Error Exit Etw Monitor");
        ::ExitProcess(1);
    }

    auto info = reinterpret_cast<PTRACE_EVENT_INFO>(buffer.get());
    status = ::TdhGetEventInformation(pEvent, 0, nullptr, info, &size);
    if (status != ERROR_SUCCESS)
        return;

    if (0 == lstrcmpW(L"{9A280AC0-C8E0-11D1-84E2-00C04FB998A2}", sguid) || \
        0 == lstrcmpW(L"{BF3A50C5-A9C9-4988-A005-2DF0B7C80F80}", sguid))
        NetWorkEventInfo(pEvent, info);
    else if (0 == lstrcmpW(L"{3D6FA8D1-FE05-11D0-9DDA-00C04FD7BA7C}", sguid))
        ThreadEventInfo(pEvent, info);
    else if (0 == lstrcmpW(L"{3D6FA8D0-FE05-11D0-9DDA-00C04FD7BA7C}", sguid))
        ProcessEventInfo(pEvent, info);
    else if (0 == lstrcmpW(L"{90CBDC39-4A3E-11D1-84F4-0000F80464E3}", sguid))
        FileEventInfo(pEvent, info);
    else if (0 == lstrcmpW(L"{AE53722E-C863-11D2-8659-00C04FA321A1}", sguid))
        RegisterTabEventInfo(pEvent, info);
    else if (0 == lstrcmpW(L"{2CB15D1D-5FC1-11D2-ABE1-00A0C911F518}", sguid))
        ImageModEventInfo(pEvent, info);
}

///////////////////////////////////
// Session注册启动/跟踪/回调
static DWORD WINAPI tracDispaththread(LPVOID param)
{
    EVENT_TRACE_LOGFILE trace;
    memset(&trace, 0, sizeof(trace));
    trace.LoggerName = const_cast<wchar_t*>(KERNEL_LOGGER_NAME);
    trace.LogFileName = NULL;
    trace.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    trace.Context = NULL;
    trace.EventRecordCallback = DispatchEventHandle;

    TRACEHANDLE handle = OpenTrace(&trace);
    if (handle == (TRACEHANDLE)INVALID_HANDLE_VALUE)
        return 0;
    OutputDebugString(L"ProcessTrace Start");
    ProcessTrace(&handle, 1, 0, 0);
    CloseTrace(handle);
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

    /// NT Kernel Logger
    status = StartTrace(&hSession, KERNEL_LOGGER_NAME, m_traceconfig);
    if (ERROR_SUCCESS != status)
    {
        /// 已经存在 Stop
        if (ERROR_ALREADY_EXISTS == status)
        {
            status = ControlTrace(NULL, KERNEL_LOGGER_NAME, m_traceconfig, EVENT_TRACE_CONTROL_STOP);
            if (SUCCEEDED(status))
            {
                status = StartTrace(&hSession, KERNEL_LOGGER_NAME, m_traceconfig);
                if (ERROR_SUCCESS != status)
                {
                    if (m_traceconfig)
                        delete[] m_traceconfig;
                    return false;
                }
            }
        }
        else
        {
            if (m_traceconfig)
                delete[] m_traceconfig;
            return false;
        }
    }

    DWORD ThreadID;
    //初始化临界区
    g_th.Lock();
    HANDLE hThread = CreateThread(NULL, 0, tracDispaththread, (PVOID)dwEnableFlags, 0, &ThreadID);
    g_thrhandle.push_back(hThread);
    g_th.Unlock();

    TracGuidNode tracinfo = { 0, };
    tracinfo.bufconfig = m_traceconfig;
    tracinfo.event_tracid = dwEnableFlags;
    g_ms.Lock();
    g_tracMap[hSession] = tracinfo;
    g_ms.Unlock();

    OutputDebugString(L"Register TracGuid Success");
    return true;
}
bool UEtw::uf_init()
{
    OutputDebugString(L"Etw nf_init - uf_RegisterTrace");
#ifdef _DEBUG
    // EVENT_TRACE_FLAG_NETWORK_TCPIP EVENT_TRACE_FLAG_THREAD
    uf_RegisterTrace(EVENT_TRACE_FLAG_PROCESS | EVENT_TRACE_FLAG_NETWORK_TCPIP);
    return 1;
#else
    // 目前使用用一个Session: 优点不用管理，缺点没办法单独监控某个事件。
    // 如果单独监控，创建多个Session来管理，注册多个uf_RegisterTrace即可。
    // EVENT_TRACE_FLAG_SYSTEMCALL
    return uf_RegisterTrace(
        EVENT_TRACE_FLAG_NETWORK_TCPIP | \
        EVENT_TRACE_FLAG_PROCESS | \
        EVENT_TRACE_FLAG_THREAD | \
        EVENT_TRACE_FLAG_IMAGE_LOAD | \
        EVENT_TRACE_FLAG_FILE_IO | EVENT_TRACE_FLAG_FILE_IO_INIT | \
        EVENT_TRACE_FLAG_REGISTRY
    );
#endif
}
bool UEtw::uf_close()
{
    map<TRACEHANDLE, TracGuidNode>::iterator  iter;

    for (iter = g_tracMap.begin(); iter != g_tracMap.end();)
    {

        if (iter->first && iter->second.bufconfig)
            ControlTrace(iter->first, KERNEL_LOGGER_NAME, iter->second.bufconfig, EVENT_TRACE_CONTROL_STOP);

        if (iter->second.bufconfig)
        {
            delete[] iter->second.bufconfig;
            iter->second.bufconfig = NULL;
        }

        g_ms.Lock();
        g_tracMap.erase(iter++);
        g_ms.Unlock();
    }

    size_t  i = 0;

    g_th.Lock();
    for (i = 0; i < g_thrhandle.size(); ++i)
    {
        WaitForSingleObject(g_thrhandle[i], 2000);
        CloseHandle(g_thrhandle[i]);
    }
    g_thrhandle.clear();
    g_th.Unlock();

    return true;
}

/// <summary>
/// 设置某事件状态
/// </summary>
/// <param name="hSession"></param>
/// <param name="m_traceconfig"></param>
/// <param name="ioct"></param>
/// <returns></returns>
unsigned long UEtw::uf_setmonitor(
    unsigned __int64 hSession,
    PVOID64 m_traceconfig,
    const int ioct
)
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