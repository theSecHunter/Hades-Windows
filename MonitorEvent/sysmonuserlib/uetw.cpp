#include <combaseapi.h>
#include <tdh.h>
#include <memory>
#include <map>
#include <mutex>
#include <vector>
#include <queue>
#include <string>
#include <wchar.h>
#include <direct.h>
#include <in6addr.h>
#include <Psapi.h>
#include "uetw.h"

#pragma comment(lib,"psapi.lib")
#pragma comment(lib, "Ole32.lib")
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Tdh.lib")

using namespace std;
static std::mutex g_proceseventLock;

// [Guid File Logger] Event File Logger
static const wchar_t SESSION_NAME_FILE[] = L"PAitEtwTrace";
static EVENT_TRACE_PROPERTIES g_traceconfig;
static UCHAR g_pTraceConfig[2048] = { 0, };

// 进程Event_Notify
std::function<void(const PROCESSINFO&)> on_processinfo_;

// Etw Event Manage
// Session - Guid - tracconfig
typedef struct _TracGuidNode
{
    DWORD                        event_tracid;
    EVENT_TRACE_PROPERTIES*      bufconfig;
}TracGuidNode, *PTracGuidNode;

static map<TRACEHANDLE, TracGuidNode>   g_tracMap;
static vector<HANDLE>					g_thrhandle;
static bool								g_etwevent_exit = false;
static mutex							g_ms, g_th;
static TRACEHANDLE						g_processTracehandle;

// [ALL]
void Wchar_tToString(std::string& szDst, wchar_t* wchar)
{
    if (lstrlenW(wchar) <= 0)
    {
        szDst = " ";
        return;
    }
    wchar_t* wText = wchar;
    DWORD dwNum = WideCharToMultiByte(CP_ACP, 0, wText, -1, NULL, 0, NULL, FALSE);
    if (dwNum <= 0)
    {
        szDst = " ";
        return;
    }
    char* psText;
    psText = new char[dwNum + 1];
    WideCharToMultiByte(CP_ACP, 0, wText, -1, psText, dwNum, NULL, FALSE);
    psText[dwNum - 1] = 0;
    szDst = psText;
    delete[] psText;
}

UEtw::UEtw()
{
    g_etwevent_exit = false;
}
UEtw::~UEtw()
{
}

// [ALL] Pid Get ProcessPath
DWORD GetPathByProcessId(wchar_t* path, const  DWORD dwPid)
{
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPid);
    if (hProcess == NULL)
        return false;
	return GetModuleFileNameExW(hProcess, NULL, path, MAX_PATH);
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
                if(!processPath.empty())
                    found = processPath.find_last_of(L"/\\");
                processinfo_data.processStatus = true;
                processinfo_data.processsid = *(ULONG*)(((PUCHAR)EventRecord->UserData) + 0);
                //Name: wstring((wchar_t*)(((PUCHAR)EventRecord->UserData) + 84));
                if ((found > 0) && (found < MAX_PATH))
                    processinfo_data.processName = processPath.substr(found + 1);
                else
                    processinfo_data.processName = L"";
                processinfo_data.processCommLine = processPath.c_str();
            }
            else if (2 == EventProcesId)
            {
                processinfo_data.processStatus = false;
                processinfo_data.processsid = *(ULONG*)(((PUCHAR)EventRecord->UserData) + 0);
                processinfo_data.processName = L"";
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

// [NT Kernel Logger] Kernel Log Evnet
void WINAPI ProcessEventInfo(PEVENT_RECORD rec, PTRACE_EVENT_INFO info)
{
    try
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
        wchar_t* end = nullptr;

        PROCESSINFO processinfo_data = { 0, };
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
                const int pid = wcstol(value, &end, 16);
                processinfo_data.processsid = pid;
            }
            else if (0 == lstrcmpW(L"ExitStatus", propName.c_str()))
            {
                if (0 >= _wtoi(value))
                    processinfo_data.processStatus = false;
                else
                    processinfo_data.processStatus = true;
            }
            else if (0 == lstrcmpW(L"CommandLine", propName.c_str()))
            {
                processinfo_data.processCommLine = value;
            }
            else if (0 == lstrcmpW(L"ImageFileName", propName.c_str()))
            {
                processinfo_data.processName = value;
            }
        }
        on_processinfo_(processinfo_data);
    }
    catch (const std::exception&)
    {
        OutputDebugString(L"[LoadMM] Uetw Error");
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
    try
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
        if (0 == lstrcmpW(L"{3D6FA8D0-FE05-11D0-9DDA-00C04FD7BA7C}", sguid))
        {
            g_proceseventLock.lock();
            ProcessEventInfo(pEvent, info);
            g_proceseventLock.unlock();
        }
    }
    catch (const std::exception&)
    {
        OutputDebugString(L"[LoadMM Error] DispatchEventHandle Error");
    }

		
}

// [NT Kernel Logger] Session注册启动/跟踪/回调
static DWORD WINAPI tracDispaththread(LPVOID param)
{
    g_etwevent_exit = false;
    EVENT_TRACE_LOGFILE trace;
    memset(&trace, 0, sizeof(trace));
    trace.LoggerName = const_cast<LPWSTR>(KERNEL_LOGGER_NAME);
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

    g_ms.lock();
    g_tracMap[hSession] = tracinfo;
    g_ms.unlock();

    DWORD ThreadID = 0;
    //初始化临界区
    g_th.lock();
    HANDLE hThread = CreateThread(NULL, 0, tracDispaththread, (PVOID)dwEnableFlags, 0, &ThreadID);
    g_thrhandle.push_back(hThread);
    g_th.unlock();

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
    strcat(m_File, "\\ProcesAitFile.etl");

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
    g_th.lock();
    HANDLE hThread = CreateThread(NULL, 0, tracDispaththreadFile, NULL, 0, &ThreadID);
    g_thrhandle.push_back(hThread);
    g_th.unlock();

    OutputDebugString(L"[UetwMM] Register TracGuid Success");
    return true;
}

// [NT Kernel Logger]
bool UEtw::uf_init()
{
	if (!on_processinfo_)
		return 0;
    OutputDebugString(L"Etw nf_init - uf_RegisterTrace");
#ifdef _DEBUG
	if (!uf_RegisterTrace(EVENT_TRACE_FLAG_PROCESS))
        return 0;
    return 1;
#else
	if (!uf_RegisterTrace(EVENT_TRACE_FLAG_PROCESS))
		return 0;
    return 1;
#endif
}
bool UEtw::uf_close()
{
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

        g_ms.lock();
        g_tracMap.erase(iter++);
        g_ms.unlock();
    }

    g_th.lock();
    for (size_t i = 0; i < g_thrhandle.size(); ++i)
    {
        WaitForSingleObject(g_thrhandle[i], 1000);
        CloseHandle(g_thrhandle[i]);
    }
    g_thrhandle.clear();
    g_th.unlock();
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

    g_th.lock();
    for (size_t i = 0; i < g_thrhandle.size(); ++i)
    {
        WaitForSingleObject(g_thrhandle[i], 1000);
        CloseHandle(g_thrhandle[i]);
    }
    g_thrhandle.clear();
    g_th.unlock();
    return true;
}

// [ALL] 设置回调
void UEtw::set_on_processMonitor(const std::function<void(const PROCESSINFO&)>& on_processinfo_data)
{
	on_processinfo_ = on_processinfo_data;
}

// [NT Kernel Logger] 设置状态
unsigned long UEtw::uf_setmonitor(unsigned __int64 hSession,PVOID64 m_traceconfig,const int ioct)
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