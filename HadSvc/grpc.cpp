#include "grpc.h"
#include "umsginterface.h"
#include "kmsginterface.h"

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

static bool                         g_shutdown = false;
static bool                         g_taskdis = false;
static bool                         g_etwdis = false;
static bool                         g_kerneldis = false;

static queue<int>                   ggrpc_taskid;
static std::mutex                   ggrpc_taskcs;

static std::mutex                   ggrpc_writecs;

static LPVOID                       g_user_interface = nullptr;
static LPVOID                       g_kern_interface = nullptr;

// gloable UserSubQueue
static std::queue<std::shared_ptr<USubNode>>    g_Etw_GrpcSubQueue_Ptr;
static std::mutex                               g_Etw_GrpcQueueCs_Ptr;
static HANDLE                                   g_Etw_GrpcQueue_Event = nullptr;

// gloable KernSubQueue
static std::queue<std::shared_ptr<USubNode>>    g_Ker_GrpcSubQueue_Ptr;
static std::mutex                               g_Ker_GrpcQueueCs_Ptr;
static HANDLE                                   g_Ker_GrpcQueue_Event = nullptr;

// Grpc双向steam接口
bool Grpc::Grpc_Transfer(RawData rawData)
{
    bool nRet = false;
    ggrpc_writecs.lock();
    if(Grpc_Getstream())
        nRet = m_stream->Write(rawData);
    ggrpc_writecs.unlock();
    if (false == nRet)
    {
        cout << "Write Buffer Error" << endl;
        return false;
    }

    return true;
}
inline void Grpc::Grpc_writeEx(RawData& raw)
{
    if (Grpc_Getstream())
        m_stream->Write(raw);
}

// TaskId任务完成，数据序列化完成反馈
void Grpc::Grpc_taskwrite()
{
    int taskid = 0;
    size_t coutwrite = 0, idx = 0;
    ::proto::RawData rawData;
    ::proto::Record* pkg = rawData.add_pkg();
    if (!pkg)
        return;
    auto MapMessage = pkg->mutable_message();
    if (!MapMessage)
        return;

    std::vector<std::string> task_array_data;
    for (;;)
    {
        WaitForSingleObject(
            this->m_jobAvailableEvnet_WriteTask,
            INFINITE
        );

        if (g_shutdown || g_taskdis)
            break;

        if (!pkg || !MapMessage)
            break;;

        do {
            MapMessage->clear();

            ggrpc_taskcs.lock();
            if (!ggrpc_taskid.size())
            {
                ggrpc_taskcs.unlock();
                break;
            }
            taskid = ggrpc_taskid.front();
            ggrpc_taskid.pop();
            ggrpc_taskcs.unlock();

            task_array_data.clear();
            if ((taskid >= 100) && (taskid < 200))
                ((kMsgInterface*)g_kern_interface)->kMsg_taskPush(taskid, task_array_data);
            else if ((taskid >= 200) && (taskid < 300))
                ((uMsgInterface*)g_user_interface)->uMsg_taskPush(taskid, task_array_data);
            else
                return;

            coutwrite = task_array_data.size();
            for (idx = 0; idx < coutwrite; ++idx)
            {
                (*MapMessage)["data_type"] = to_string(taskid);
                if (task_array_data[idx].size())
                    (*MapMessage)["udata"] = task_array_data[idx]; // json
                else
                    (*MapMessage)["udata"] = "error";
                ggrpc_writecs.lock();
                Grpc_writeEx(rawData);
                ggrpc_writecs.unlock();
            }
        } while (true);
    }
}
// TaskId任务处理线程
static unsigned WINAPI _QueueTaskthreadProc(void* pData)
{
    (reinterpret_cast<Grpc*>(pData))->Grpc_taskwrite();
    return 0;
}
// TaskId入消息队列处理
void Grpc::Grpc_ReadDispatchHandle(Command& command)
{
    const int taskid = command.agentctrl();
    if (taskid < 100 || taskid > 400)
        return;
    ggrpc_taskcs.lock();
    ggrpc_taskid.push(taskid);
    ggrpc_taskcs.unlock();
    SetEvent(m_jobAvailableEvnet_WriteTask);
}
// Saas_Server下发TaskId任务
void Grpc::Grpc_ReadC2Thread(LPVOID lpThreadParameter)
{
    // Read Server Msg
    if (!m_stream)
        return;
    Command command;
    while (true)
    {
        if (!m_stream || g_shutdown)
            break;
        m_stream->Read(&command);
        Grpc_ReadDispatchHandle(command);
    }
}

// Kernel_Sub订阅消息处理
void Grpc::KerSublthreadProc()
{
    ::proto::RawData rawData;
    char* ptr_Getbuffer;
    ::proto::Record* pkg = rawData.add_pkg();
    if (!pkg)
        return;
    auto MapMessage = pkg->mutable_message();
    if (!MapMessage)
        return;

    std::shared_ptr<USubNode> subwrite;
    for (;;)
    {

        WaitForSingleObject(g_Ker_GrpcQueue_Event, INFINITE);

        if (g_shutdown || g_kerneldis)
            break;

        if (!pkg || !MapMessage)
            break;

        do {
            MapMessage->clear();

            g_Ker_GrpcQueueCs_Ptr.lock();
            if (g_Ker_GrpcSubQueue_Ptr.empty())
            {
                g_Ker_GrpcQueueCs_Ptr.unlock();
                break;
            }
            subwrite = g_Ker_GrpcSubQueue_Ptr.front();
            g_Ker_GrpcSubQueue_Ptr.pop();
            g_Ker_GrpcQueueCs_Ptr.unlock();

            (*MapMessage)["data_type"] = to_string(subwrite->taskid);
            (*MapMessage)["udata"] = subwrite->data->c_str(); // json
            ggrpc_writecs.lock();
            Grpc_writeEx(rawData);
            ggrpc_writecs.unlock();

        } while (true);
    }
}
static unsigned WINAPI _KerSubthreadProc(void* pData)
{
    (reinterpret_cast<Grpc*>(pData))->KerSublthreadProc();
    return 0;
}
// Etw_Sub订阅消息处理
void Grpc::EtwSublthreadProc()
{
    ::proto::RawData rawData;
    char* ptr_Getbuffer;
    ::proto::Record* pkg = rawData.add_pkg();
    if (!pkg)
        return;
    auto MapMessage = pkg->mutable_message();
    if (!MapMessage)
        return;

    std::shared_ptr<USubNode> subwrite;

    for (;;)
    {

        WaitForSingleObject(g_Etw_GrpcQueue_Event, INFINITE);

        if (g_shutdown || g_etwdis)
            break;

        if (!pkg || !MapMessage)
            break;

        do {
            MapMessage->clear();

            g_Etw_GrpcQueueCs_Ptr.lock();
            if (g_Etw_GrpcSubQueue_Ptr.empty())
            {
                g_Etw_GrpcQueueCs_Ptr.unlock();
                break;
            }
            subwrite =  g_Etw_GrpcSubQueue_Ptr.front();
            g_Etw_GrpcSubQueue_Ptr.pop();
            g_Etw_GrpcQueueCs_Ptr.unlock();

            (*MapMessage)["data_type"] = to_string(subwrite->taskid);
            (*MapMessage)["udata"] = subwrite->data->c_str(); // json
            ggrpc_writecs.lock();
            Grpc_writeEx(rawData);
            ggrpc_writecs.unlock();

        } while (true);
    }
}
static unsigned WINAPI _EtwSubthreadProc(void* pData)
{
    (reinterpret_cast<Grpc*>(pData))->EtwSublthreadProc();
    return 0;
}

// 初始化Lib库指针
bool Grpc::SetUMontiorLibPtr(LPVOID ulibptr)
{
    g_user_interface = ulibptr;
    return g_user_interface ? true : false;
}
bool Grpc::SetKMontiorLibPtr(LPVOID klibptr)
{
    g_kern_interface = (kMsgInterface*)klibptr;
    return g_kern_interface ? true : false;
}

//设置Grpc订阅,初始化队列线程
bool Grpc::ThreadPool_Init()
{
    g_Ker_GrpcQueue_Event = CreateEvent(NULL, FALSE, FALSE, NULL);
    g_Etw_GrpcQueue_Event = CreateEvent(NULL, FALSE, FALSE, NULL);
    this->m_jobAvailableEvnet_WriteTask = CreateEvent(NULL, FALSE, FALSE, NULL);
    if (!g_Etw_GrpcQueue_Event || !g_Ker_GrpcQueue_Event || !m_jobAvailableEvnet_WriteTask)
        return false;

    ((uMsgInterface*)g_user_interface)->uMsg_SetSubEventPtr(g_Etw_GrpcQueue_Event);
    ((uMsgInterface*)g_user_interface)->uMsg_SetSubQueueLockPtr(g_Etw_GrpcQueueCs_Ptr);
    ((uMsgInterface*)g_user_interface)->uMsg_SetSubQueuePtr(g_Etw_GrpcSubQueue_Ptr);

    ((kMsgInterface*)g_kern_interface)->kMsg_SetSubEventPtr(g_Ker_GrpcQueue_Event);
    ((kMsgInterface*)g_kern_interface)->kMsg_SetSubQueueLockPtr(g_Ker_GrpcQueueCs_Ptr);
    ((kMsgInterface*)g_kern_interface)->kMsg_SetSubQueuePtr(g_Ker_GrpcSubQueue_Ptr);
    
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

    // 处理指令下发任务 Max 4
    for (i = 0; i < 4; i++)
    {
        hThread = (HANDLE)_beginthreadex(0, 0,
            _QueueTaskthreadProc,
            (LPVOID)this,
            0,
            &threadId);

        if (hThread != 0 && hThread != (HANDLE)(-1L))
        {
            m_threads_write.push_back(hThread);
        }
    }

    return true;
}
bool Grpc::ThreadPool_Free()
{
    // 设置标志
    g_shutdown = true;

    // 循环关闭句柄
    for (tThreads::iterator it = m_ker_subthreads.begin();
        it != m_ker_subthreads.end();
        it++)
    {
        SetEvent(g_Ker_GrpcQueue_Event);
        WaitForSingleObject(*it, 1000);
        CloseHandle(*it);
    }


    if (g_Ker_GrpcQueue_Event != INVALID_HANDLE_VALUE)
    {
        ::CloseHandle(g_Ker_GrpcQueue_Event);
        g_Ker_GrpcQueue_Event = INVALID_HANDLE_VALUE;
    }

    for (tThreads::iterator it = m_etw_subthreads.begin();
        it != m_etw_subthreads.end();
        it++)
    {
        SetEvent(g_Etw_GrpcQueue_Event);
        WaitForSingleObject(*it, 1000);
        CloseHandle(*it);
    }

    if (g_Etw_GrpcQueue_Event != INVALID_HANDLE_VALUE)
    {
        ::CloseHandle(g_Etw_GrpcQueue_Event);
        g_Etw_GrpcQueue_Event = INVALID_HANDLE_VALUE;
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