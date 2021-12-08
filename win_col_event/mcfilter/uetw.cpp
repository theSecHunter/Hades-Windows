#include <stdio.h>
#include <stdint.h>
#include <Windows.h>
#include <memory>

#define INITGUID
#include <evntrace.h>
#include <evntcons.h>
#include <tdh.h>
#include <in6addr.h>

#include "uetw.h"
#include "sync.h"

#include <map>
#include <vector>

using namespace std;

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

////////////////////////////////////
// CallBack
// 回调可以使用同一个函数，这里是不通模块做测试
void WINAPI ProcessEvent(PEVENT_RECORD pEvent);
void WINAPI ThreadEvent(PEVENT_RECORD pEvent);
void WINAPI ImageEvent(PEVENT_RECORD pEvent);
void WINAPI TcpIpEvent(PEVENT_RECORD pEvent);
void WINAPI RegisterEvent(PEVENT_RECORD pEvent);
void WINAPI FileEvent(PEVENT_RECORD pEvent);
void WINAPI SystemInfoEvent(PEVENT_RECORD pEvent);

///////////////////////////////////
// Session回调启用跟踪
DWORD WINAPI tracDispaththread(LPVOID param)
{
    EVENT_TRACE_LOGFILE trace;
    memset(&trace, 0, sizeof(trace));
    trace.LoggerName = const_cast<wchar_t*>(KERNEL_LOGGER_NAME);
    trace.LogFileName = NULL;
    trace.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    trace.Context = NULL;

    if (!param)
        return 0;
    switch ((int)param)
    {
    case EVENT_TRACE_FLAG_PROCESS:
        trace.EventRecordCallback = ProcessEvent;
        break;
    case EVENT_TRACE_FLAG_THREAD:
        trace.EventRecordCallback = ThreadEvent;
        break;
    case EVENT_TRACE_FLAG_IMAGE_LOAD:
        trace.EventRecordCallback = ImageEvent;
        break;
    case EVENT_TRACE_FLAG_FILE_IO_INIT:
        trace.EventRecordCallback = FileEvent;
        break;
    case EVENT_TRACE_FLAG_NETWORK_TCPIP:
        trace.EventRecordCallback = TcpIpEvent;
        break;
    default:
        return 0;
    }

    TRACEHANDLE handle = OpenTrace(&trace);
    if (handle == (TRACEHANDLE)INVALID_HANDLE_VALUE)
        return 0;
    ProcessTrace(&handle, 1, 0, 0);
    CloseTrace(handle);
    return 0;
}

UEtw::UEtw()
{
}
UEtw::~UEtw()
{
}

/*
    只开放了一个网络进行测试 - 其余自行开启测试
    目前该功能只是单独代码测试，未grpc联调
*/
bool UEtw::uf_init()
{
    //// process
    // this->uf_RegisterTrace(EVENT_TRACE_FLAG_PROCESS);
    //// thread
    //this->uf_RegisterTrace(EVENT_TRACE_FLAG_THREAD);
    //// image
    //this->uf_RegisterTrace(EVENT_TRACE_FLAG_IMAGE_LOAD);
    //// file
    //this->uf_RegisterTrace(EVENT_TRACE_FLAG_FILE_IO | EVENT_TRACE_FLAG_FILE_IO_INIT);
    // disk EVENT_TRACE_FLAG_DISK_IO | EVENT_TRACE_FLAG_DISK_IO_INIT | EVENT_TRACE_FLAG_DISK_FILE_IO
    // network
    this->uf_RegisterTrace(EVENT_TRACE_FLAG_NETWORK_TCPIP);
    //// register
    // this->uf_RegisterTrace(EVENT_TRACE_FLAG_REGISTRY);
    //// syscall
    // this->uf_RegisterTrace(EVENT_TRACE_FLAG_SYSTEMCALL);
    return true;
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

///////////////////////////////////
// 注册ETW事件
bool UEtw::uf_RegisterTrace(
    const int dwEnableFlags
)
{
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
    printf("Trac Guid: 0x%u - Register TracGuid Success\n", dwEnableFlags);

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


/// <summary>
/// 事件分发处理
/// </summary>
/// <param name="rec"></param>
/// <param name="info"></param>
/// 引用：https://github.com/zodiacon/Win10SysProgBookSamples/blob/3e7a7e4d4898ec1c197421127b652737164a668f/Chapter20/KernelETW/KernelETW.cpp
void DisplayEventInfo(PEVENT_RECORD rec, PTRACE_EVENT_INFO info) {
    if (info->KeywordsNameOffset)
        printf("Keywords: %ws ", (PCWSTR)((BYTE*)info + info->KeywordsNameOffset));
    if (info->OpcodeNameOffset)
        printf("Opcode: %ws ", (PCWSTR)((BYTE*)info + info->OpcodeNameOffset));
    if (info->LevelNameOffset)
        printf("Level: %ws ", (PCWSTR)((BYTE*)info + info->LevelNameOffset));
    if (info->TaskNameOffset)
        printf("Task: %ws ", (PCWSTR)((BYTE*)info + info->TaskNameOffset));
    if (info->EventMessageOffset)
        printf("\nMessage: %ws", (PCWSTR)((BYTE*)info + info->EventMessageOffset));

    printf("\nProperties: %u\n", info->TopLevelPropertyCount);

    // properties data length and pointer
    auto userlen = rec->UserDataLength;
    auto data = (PBYTE)rec->UserData;

    auto pointerSize = (rec->EventHeader.Flags & EVENT_HEADER_FLAG_32_BIT_HEADER) ? 4 : 8;
    ULONG len;
    WCHAR value[512];

    for (DWORD i = 0; i < info->TopLevelPropertyCount; i++) {
        auto& pi = info->EventPropertyInfoArray[i];
        auto propName = (PCWSTR)((BYTE*)info + pi.NameOffset);
        printf(" Name: %ws ", propName);

        len = pi.length;
        if ((pi.Flags & (PropertyStruct | PropertyParamCount)) == 0) {
            //
            // deal with simple properties only
            //
            PEVENT_MAP_INFO mapInfo = nullptr;
            std::unique_ptr<BYTE[]> mapBuffer;
            PWSTR mapName = nullptr;
            //
            // retrieve map information (if any)
            //
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
                printf("Value: %ws", value);
                len = consumed;
                if (mapName)
                    printf(" (%ws)", (PCWSTR)mapName);
                printf("\n");
            }
            else if (mapInfo) {
                error = ::TdhFormatProperty(info, nullptr, pointerSize,
                    pi.nonStructType.InType, pi.nonStructType.OutType,
                    (USHORT)len, userlen, data, &size, value, &consumed);
                if (ERROR_SUCCESS == error)
                    printf("Value: %ws\n", value);
            }
            if (ERROR_SUCCESS != error)
                printf("(failed to get value)\n");
        }
        else {
            printf("(not a simple property)\n");
        }
        userlen -= (USHORT)len;
        data += len;
    }

    printf("\n");
}
void DisplayGeneralEventInfo(PEVENT_RECORD rec) {
    WCHAR sguid[64];
    auto& header = rec->EventHeader;
    ::StringFromGUID2(header.ProviderId, sguid, _countof(sguid));
    //printf("Provider: %ws Time: %ws PID: %u TID: %u\n",
    //    sguid, (PCWSTR)CTime(*(FILETIME*)&header.TimeStamp).Format(L"%c"),
    //    header.ProcessId, header.ThreadId);
}

///////////////////////////////////////////////////
// ProcessEvent_callback
void WINAPI ProcessEvent(PEVENT_RECORD pEvent)
{
    DisplayGeneralEventInfo(pEvent);

    ULONG size = 0;
    // 检索元数据 - 拿大小
    auto status = ::TdhGetEventInformation(pEvent, 0, nullptr, nullptr, &size);
    if (size <= 0)
        return;

    auto buffer = std::make_unique<BYTE[]>(size);
    if (!buffer) {
        ::ExitProcess(1);
    }

    // 拿数据
    auto info = reinterpret_cast<PTRACE_EVENT_INFO>(buffer.get());
    status = ::TdhGetEventInformation(pEvent, 0, nullptr, info, &size);
    if (status != ERROR_SUCCESS)
        return;

    // 分发处理
    DisplayEventInfo(pEvent, info);
}
void WINAPI ThreadEvent(PEVENT_RECORD pEvent)
{
}
void WINAPI ImageEvent(PEVENT_RECORD pEvent)
{
}
void WINAPI TcpIpEvent(PEVENT_RECORD pEvent)
{
    DisplayGeneralEventInfo(pEvent);

    ULONG size = 0;
    // 检索元数据 - 拿大小
    auto status = ::TdhGetEventInformation(pEvent, 0, nullptr, nullptr, &size);
    if (size <= 0)
        return;

    auto buffer = std::make_unique<BYTE[]>(size);
    if (!buffer) {
        ::ExitProcess(1);
    }

    // 拿数据
    auto info = reinterpret_cast<PTRACE_EVENT_INFO>(buffer.get());
    status = ::TdhGetEventInformation(pEvent, 0, nullptr, info, &size);
    if (status != ERROR_SUCCESS)
        return;

    // 分发处理
    DisplayEventInfo(pEvent, info);
}
void WINAPI RegisterEvent(PEVENT_RECORD pEvent) 
{
}
void WINAPI FileEvent(PEVENT_RECORD pEvent)
{
}
void WINAPI SystemInfoEvent(PEVENT_RECORD pEvent)
{
}