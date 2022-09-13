#include "umsginterface.h"
#include "kmsginterface.h"
#include "NamedPipe.h"
#include "AnonymousPipe.h"

#include <sysinfo.h>
#include <winsock.h>
#include <map>
#include <queue>
#include <mutex>
#include <iostream>
#include <memory>
#include <string>
#include <vector>
#include <time.h>
#include <functional>

#include "DataHandler.h"

static bool                         g_shutdown = false;
static bool                         g_etwdis = false;
static bool                         g_kerneldis = false;

static LPVOID                       g_user_interface = nullptr;
static LPVOID                       g_kern_interface = nullptr;

// gloable UserSubQueue
static std::queue<std::shared_ptr<USubNode>>    g_Etw_SubQueue_Ptr;
static std::mutex                               g_Etw_QueueCs_Ptr;
static HANDLE                                   g_Etw_Queue_Event = nullptr;

// gloable KernSubQueue
static std::queue<std::shared_ptr<USubNode>>    g_Ker_SubQueue_Ptr;
static std::mutex                               g_Ker_QueueCs_Ptr;
static HANDLE                                   g_Ker_Queue_Event = nullptr;

const std::wstring PIPE_HADESWIN_NAME = L"\\\\.\\Pipe\\HadesPipe";
std::shared_ptr<NamedPipe> g_namedpipe = nullptr;
std::shared_ptr<AnonymousPipe> g_anonymouspipe = nullptr;


DataHandler::DataHandler()
{
}
DataHandler::~DataHandler() 
{
}

// Task Handler
DWORD WINAPI DataHandler::PTaskHandlerNotify(LPVOID lpThreadParameter)
{
    if (!lpThreadParameter)
        return 0;

    size_t coutwrite = 0, idx = 0;
    static std::vector<std::string> task_array_data;
    task_array_data.clear();
    if (g_shutdown)
        return 0;

    const int taskid = (DWORD)lpThreadParameter;
    if ((taskid >= 100) && (taskid < 200))
        ((kMsgInterface*)g_kern_interface)->kMsg_taskPush(taskid, task_array_data);
    else if ((taskid >= 200) && (taskid < 300))
        ((uMsgInterface*)g_user_interface)->uMsg_taskPush(taskid, task_array_data);
    else if (401 == taskid)
    {//用户态开关
        auto g_ulib = ((uMsgInterface*)g_user_interface);
        if (!g_ulib)
            return 0;
        task_array_data.clear();
        auto uStatus = g_ulib->GetEtwMonStatus();
        if (false == uStatus)
        {
            g_ulib->uMsg_EtwInit();
            task_array_data[0] = "User_Etw MonitorControl Enable";
        }
        else
            task_array_data[0] = "User_Etw MonitorControl Runing";
    }
    else if (402 == taskid) {
        auto g_ulib = ((uMsgInterface*)g_user_interface);
        if (!g_ulib)
            return 0;
        task_array_data.clear();
        auto uStatus = g_ulib->GetEtwMonStatus();
        if (true == uStatus)
        {
            task_array_data[0] = "User_Etw MonitorControl Disable";
            g_ulib->uMsg_EtwClose();
        }
        else
            task_array_data[0] = "User_Etw MonitorControl NotActivated";
    }
    else if (403 == taskid) {
        auto g_klib = ((kMsgInterface*)g_kern_interface);
        if (!g_klib)
            return 0;
        task_array_data.clear();
        if (false == g_klib->GetKerInitStatus())
            g_klib->DriverInit(false);
        const bool kStatus = g_klib->GetKerMonStatus();
        if (false == kStatus)
            g_klib->StartReadFileThread();//如果不需要初始化，行为拦截正在工作 - 只启动线程
        if (false == kStatus)
        {
            OutputDebugString(L"[HadesSvc] GetKerMonStatus Send Enable KernelMonitor Command");
            g_klib->OnMonitor();

            task_array_data[0] = "Kernel MonitorControl Enable";
        }
        else
            task_array_data[0] = "Kernel MonitorControl Runing";
    }
    else if (404 == taskid)
    {//内核态开关
        auto g_klib = ((kMsgInterface*)g_kern_interface);
        if (!g_klib)
            return 0;
        task_array_data.clear();
        if (false == g_klib->GetKerInitStatus())
            g_klib->DriverInit(false);
        auto kStatus = g_klib->GetKerMonStatus();
        OutputDebugString(L"[HadesSvc] GetKerMonStatus Send Disable KernelMonitor Command");
        g_klib->OffMonitor();
        OutputDebugString(L"[HadesSvc] GetKerMonStatus Disable KernelMonitor Success");
        if ((true == g_klib->GetKerInitStatus()) && (false == g_klib->GetKerBeSnipingStatus()))
            g_klib->DriverFree();
        else
            g_klib->StopReadFileThread(); // 开启行为拦截状态下，关闭线程 - 防止下发I/O
    }
    else
        return 0;

    // Write Pip

    return 0;
}
// Recv Task
void DataHandler::OnPipMessageNotify(const std::shared_ptr<uint8_t>& data, size_t size)
{
    QueueUserWorkItem(DataHandler::PTaskHandlerNotify, NULL, WT_EXECUTEDEFAULT);
}

// 内核数据ConSumer
void DataHandler::KerSublthreadProc()
{

    WaitForSingleObject(g_Ker_Queue_Event, INFINITE);

    //if (g_shutdown || g_kerneldis)
    //    break;

    //do {
    //    g_Ker_QueueCs_Ptr.lock();
    //    if (g_Ker_GrpcSubQueue_Ptr.empty())
    //    {
    //        g_Ker_QueueCs_Ptr.unlock();
    //        break;
    //    }
    //    subwrite = g_Ker_GrpcSubQueue_Ptr.front();
    //    g_Ker_GrpcSubQueue_Ptr.pop();
    //    g_Ker_QueueCs_Ptr.unlock();

    //    ggrpc_writecs.lock();
    //    record->set_datatype(subwrite->taskid);
    //    record->set_timestamp(GetCurrentTime());
    //    (*MapMessage)["data_type"] = to_string(subwrite->taskid);
    //    (*MapMessage)["udata"] = subwrite->data->c_str(); // json
    //    Grpc_writeEx(rawData);
    //    ggrpc_writecs.unlock();
    //    MapMessage->clear();

    //} while (!g_shutdown);
}
// Etw数据ConSumer
void DataHandler::EtwSublthreadProc()
{
    do {
        WaitForSingleObject(g_Etw_Queue_Event, INFINITE);

        if (g_shutdown || g_etwdis)
            break;
        std::shared_ptr<USubNode> subwrite;
        g_Etw_QueueCs_Ptr.lock();
        if (g_Etw_SubQueue_Ptr.empty())
        {
            g_Etw_QueueCs_Ptr.unlock();
            break;
        }
        subwrite = g_Etw_SubQueue_Ptr.front();
        g_Etw_SubQueue_Ptr.pop();
        g_Etw_QueueCs_Ptr.unlock();

        // WirtePip
        const int datasize = subwrite->data->size();
        std::shared_ptr<uint8_t> data{ new uint8_t[datasize] };
        ::memcpy(data.get(), subwrite->data->c_str(), datasize);
        this->PipWriteAnonymous(data, datasize);

    } while (!g_shutdown);
}
static unsigned WINAPI _KerSubthreadProc(void* pData)
{
    (reinterpret_cast<DataHandler*>(pData))->KerSublthreadProc();
    return 0;
}
static unsigned WINAPI _EtwSubthreadProc(void* pData)
{
    (reinterpret_cast<DataHandler*>(pData))->EtwSublthreadProc();
    return 0;
}

// 初始化Pip
bool DataHandler::PipInit()
{
    g_namedpipe = std::make_shared<NamedPipe>();
    g_namedpipe->set_on_read(std::bind(&DataHandler::OnPipMessageNotify, this, std::placeholders::_1, std::placeholders::_2));
    if (!g_namedpipe->init(PIPE_HADESWIN_NAME))
        return false;
    return true;
}
void DataHandler::PipFree()
{
    if (g_namedpipe)
        g_namedpipe->uninit();
}
bool DataHandler::PipInitAnonymous()
{
    g_anonymouspipe = std::make_shared<AnonymousPipe>();
    g_anonymouspipe->set_on_read(std::bind(&DataHandler::OnPipMessageNotify, this, std::placeholders::_1, std::placeholders::_2));
    if (!g_anonymouspipe->initPip())
        return false;
    return true;
}
void DataHandler::PipFreeAnonymous()
{
    if (g_anonymouspipe)
        g_anonymouspipe->uninPip();
}
bool DataHandler::PipWriteAnonymous(const std::shared_ptr<uint8_t>& data, size_t size)
{
    if (g_anonymouspipe)
        g_anonymouspipe->write(data, size);
    return true;
}


// 初始化Lib库指针
bool DataHandler::SetUMontiorLibPtr(void* ulibptr)
{
    g_user_interface = ulibptr;
    return g_user_interface ? true : false;
}
bool DataHandler::SetKMontiorLibPtr(void* klibptr)
{
    g_kern_interface = (kMsgInterface*)klibptr;
    return g_kern_interface ? true : false;
}

// 设置ConSumer订阅,初始化队列线程
bool DataHandler::ThreadPool_Init()
{
    g_Ker_Queue_Event = CreateEvent(NULL, FALSE, FALSE, NULL);
    g_Etw_Queue_Event = CreateEvent(NULL, FALSE, FALSE, NULL);
    this->m_jobAvailableEvnet_WriteTask = CreateEvent(NULL, FALSE, FALSE, NULL);
    if (!g_Etw_Queue_Event || !g_Ker_Queue_Event || !m_jobAvailableEvnet_WriteTask)
        return false;

    ((uMsgInterface*)g_user_interface)->uMsg_SetSubEventPtr(g_Etw_Queue_Event);
    ((uMsgInterface*)g_user_interface)->uMsg_SetSubQueueLockPtr(g_Etw_QueueCs_Ptr);
    ((uMsgInterface*)g_user_interface)->uMsg_SetSubQueuePtr(g_Etw_SubQueue_Ptr);

    ((kMsgInterface*)g_kern_interface)->kMsg_SetSubEventPtr(g_Ker_Queue_Event);
    ((kMsgInterface*)g_kern_interface)->kMsg_SetSubQueueLockPtr(g_Ker_QueueCs_Ptr);
    ((kMsgInterface*)g_kern_interface)->kMsg_SetSubQueuePtr(g_Ker_SubQueue_Ptr);

    int i = 0;
    HANDLE hThread;
    unsigned threadId;

    SYSTEM_INFO sysinfo;
    GetSystemInfo(&sysinfo);

    DWORD threadCount = sysinfo.dwNumberOfProcessors;
    if (threadCount == 0)
    {
        threadCount = 4;
    }

    // 处理Kernel上抛
    for (i = 0; i < threadCount; i++)
    {
        hThread = (HANDLE)_beginthreadex(0, 0,
            _KerSubthreadProc,
            (LPVOID)this,
            0,
            &threadId);

        if (hThread != 0 && hThread != (HANDLE)(-1L))
        {
            m_ker_subthreads.push_back(hThread);
        }
    }

    // 处理Uetw上抛
    for (i = 0; i < threadCount; i++)
    {
        hThread = (HANDLE)_beginthreadex(0, 0,
            _EtwSubthreadProc,
            (LPVOID)this,
            0,
            &threadId);

        if (hThread != 0 && hThread != (HANDLE)(-1L))
        {
            m_etw_subthreads.push_back(hThread);
        }
    }

    return true;
}
bool DataHandler::ThreadPool_Free()
{
    // 设置标志
    g_shutdown = true;
    Sleep(100);

    // 循环关闭句柄
    for (tThreads::iterator it = m_ker_subthreads.begin();
        it != m_ker_subthreads.end();
        it++)
    {
        SetEvent(g_Ker_Queue_Event);
        WaitForSingleObject(*it, 1000);
        CloseHandle(*it);
    }


    if (g_Ker_Queue_Event != INVALID_HANDLE_VALUE)
    {
        ::CloseHandle(g_Ker_Queue_Event);
        g_Ker_Queue_Event = INVALID_HANDLE_VALUE;
    }

    for (tThreads::iterator it = m_etw_subthreads.begin();
        it != m_etw_subthreads.end();
        it++)
    {
        SetEvent(g_Etw_Queue_Event);
        WaitForSingleObject(*it, 1000);
        CloseHandle(*it);
    }

    if (g_Etw_Queue_Event != INVALID_HANDLE_VALUE)
    {
        ::CloseHandle(g_Etw_Queue_Event);
        g_Etw_Queue_Event = INVALID_HANDLE_VALUE;
    }

    for (tThreads::iterator it = m_threads_write.begin();
        it != m_threads_write.end();
        it++)
    {
        SetEvent(m_jobAvailableEvnet_WriteTask);
        WaitForSingleObject(*it, 1000);
        CloseHandle(*it);
    }

    if (m_jobAvailableEvnet_WriteTask != INVALID_HANDLE_VALUE)
    {
        ::CloseHandle(m_jobAvailableEvnet_WriteTask);
        m_jobAvailableEvnet_WriteTask = INVALID_HANDLE_VALUE;
    }

    m_ker_subthreads.clear();
    m_etw_subthreads.clear();
    m_threads_write.clear();

    return true;
}