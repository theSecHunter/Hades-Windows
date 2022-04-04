#include "grpc.h"
#include "sysinfo.h"
#include <time.h>
#include <winsock.h>
#include <map>
#include <queue>
#include <mutex>
#include "umsginterface.h"
#include "kmsginterface.h"

using namespace std;

static bool                 g_shutdown = false;
static uMsgInterface        g_user_interface;
static kMsgInterface        g_kern_interface;

typedef struct _NodeQueue
{
    int code;
    int packlen;
    char* packbuf;
}NodeQueue, *PNodeQueue;

static queue<NodeQueue>             ggrpc_queue;
static std::mutex                   ggrpc_queuecs;

static queue<int>                   ggrpc_taskid;
static std::mutex                   ggrpc_taskcs;

static std::mutex                   ggrpc_writecs;

// Grpc双向steam接口
bool Grpc::Grpc_Transfer(RawData rawData)
{
    bool nRet = false;
    ggrpc_writecs.lock();
    if(Grpc_Getstream())
        nRet = m_stream->Write(rawData);
    ggrpc_writecs.lock();
    if (false == nRet)
    {
        cout << "Write Buffer Error" << endl;
        return false;
    }

    return true;
}

// Saas平台下发指令：rootkit/User采集
inline void Grpc::Grpc_writeEx(RawData& raw)
{
    if (Grpc_Getstream())
        m_stream->Write(raw);
}
void Grpc::Grpc_write()
{
    int taskid = 0;
    if (!ggrpc_taskid.empty())
        taskid = ggrpc_taskid.front();
    else
        return;
    ggrpc_taskcs.lock();
    ggrpc_taskid.pop();
    ggrpc_taskcs.unlock();
    // task_id
    std::vector<std::string> task_array_data;
    task_array_data.clear();
    if ((taskid >= 100) && (taskid < 200))
        g_kern_interface.kMsg_taskPush(taskid, task_array_data);
    else if ((taskid >= 200) && (taskid < 300))
        g_user_interface.uMsg_taskPush(taskid, task_array_data);   
    else
        return;
    ::proto::RawData rawData;
    ::proto::Record* pkg = rawData.add_pkg();
    if (!pkg)
        return;
    auto MapMessage = pkg->mutable_message();
    if (!MapMessage)
        return;

    size_t coutwrite = task_array_data.size();
    for (size_t idx = 0; idx < coutwrite; ++idx)
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
}
inline DWORD WINAPI QueueTaskThread(LPVOID lpThreadParameter)
{
    ((Grpc*)lpThreadParameter)->Grpc_write();
    return 0;
}
void Grpc::Grpc_ReadDispatchHandle(Command& command)
{
    const int taskid = command.agentctrl();
    if (100 < taskid && taskid > 300)
        return;
    ggrpc_taskcs.lock();
    ggrpc_taskid.push(taskid);
    ggrpc_taskcs.unlock();
    QueueUserWorkItem(QueueTaskThread, this, WT_EXECUTEDEFAULT);
}
void Grpc::Grpc_ReadC2Thread(LPVOID lpThreadParameter)
{
    // Read Server Msg
    if (!m_stream)
        return;
    Command command;
    while (true)
    {
        m_stream->Read(&command);
        Grpc_ReadDispatchHandle(command);
    }
}

// 被动:Kernel/Etw上抛
void Choose_session(string& events, const int code)
{
    switch (code)
    {
    case IoSessionStateCreated:
    {
        events = "Session Create";
    }
    break;
    case IoSessionStateConnected:
    {
        events = "Session Connect, But User NotLogin";
    }
    break;
    case IoSessionStateLoggedOn:
    {
        events = "Session Login";
    }
    break;
    case IoSessionStateLoggedOff:
    {
        events = "Session ExitLogin";
    }
    break;
    }
}
void Choose_register(string & opearestring, const int code)
{
    switch (code)
    {
        // 创建Key
    case RegNtPreCreateKey:
    {
        opearestring = "Register - RegNtPreCreateKey";
    }
    break;
    // 打开Key
    case RegNtPreOpenKey:
    {
        opearestring = "Register - RegNtPreOpenKey";
    }
    break;

    // 修改Key
    case RegNtSetValueKey:
    {
        opearestring = "Register - RegNtSetValueKey";
    }
    // 删除Key
    case RegNtPreDeleteKey:
    {
        opearestring = "Register - RegNtPreDeleteKey";
    }
    break;

    // 枚举Key
    case RegNtEnumerateKey:
    {
        opearestring = "Register - RegNtEnumerateKey";
    }
    break;

    // 重命名注册表
    case RegNtPostRenameKey:
    {
        opearestring = "Register - RegNtPostRenameKey";
    }
    break;
    }
}
void Grpc::threadProc()
{
    ::proto::RawData rawData;
    char* ptr_Getbuffer;
    ::proto::Record* pkg = rawData.add_pkg();
    if (!pkg)
        return;

    static  int             g_indexlock = 0;
    static  string          tmpstr;
    static  PROCESSINFO     processinfo;
    static  THREADINFO      threadinfo;
    static  IMAGEMODINFO    imageinfo;
    static  REGISTERINFO    registerinfo;
    static  FILEINFO        fileinfo;
    static  SESSIONINFO     sessioninfo;
    static  IO_SESSION_STATE_INFORMATION iosession;


    for (;;)
    {
        WaitForSingleObject(
            this->m_jobAvailableEvent,
            INFINITE
        );

        if (g_shutdown)
            break;

        if (!pkg)
            continue;

        ggrpc_queuecs.lock();
        
        pkg->Clear();
        auto MapMessage = pkg->mutable_message();
        if (!MapMessage)
        {
            ggrpc_queuecs.unlock();
            // 防止因msg一直失败 - 导致一直continue
            if (g_indexlock++ > 1000)
                break;
            continue;
        }

        auto queue_node = ggrpc_queue.front();
        (*MapMessage)["data_type"] = to_string(queue_node.code);
        switch (queue_node.code)
        {
        case NF_PROCESS_INFO:
        {
            RtlSecureZeroMemory(&processinfo, sizeof(PROCESSINFO));
            RtlCopyMemory(&processinfo, queue_node.packbuf, queue_node.packlen);

            (*MapMessage)["win_sysmonitor_process_pid"] = to_string(processinfo.processid);
            (*MapMessage)["win_sysmonitor_process_endprocess"] = to_string(processinfo.endprocess);
            if (processinfo.endprocess)
            {
                tmpstr.clear();
                Wchar_tToString(tmpstr, processinfo.queryprocesspath);
                (*MapMessage)["win_sysmonitor_process_queryprocesspath"] = tmpstr;
                tmpstr.clear();
                Wchar_tToString(tmpstr, processinfo.processpath);
                (*MapMessage)["win_sysmonitor_process_processpath"] = tmpstr;
                tmpstr.clear();
                Wchar_tToString(tmpstr, processinfo.commandLine);
                (*MapMessage)["win_sysmonitor_process_commandLine"] = tmpstr;
            }
            else
            {
                tmpstr.clear();
                Wchar_tToString(tmpstr, processinfo.queryprocesspath);
                (*MapMessage)["win_sysmonitor_process_queryprocesspath"] = tmpstr;
            }
        }
        break;
        case NF_THREAD_INFO:
        {
            RtlSecureZeroMemory(&threadinfo, sizeof(THREADINFO));
            RtlCopyMemory(&threadinfo, queue_node.packbuf, queue_node.packlen);

            (*MapMessage)["win_sysmonitor_thread_pid"] = to_string(threadinfo.processid);
            (*MapMessage)["win_sysmonitor_thread_id"] = to_string(threadinfo.threadid);
            (*MapMessage)["win_sysmonitor_thread_status"] = to_string(threadinfo.createid);
        }
        break;
        case NF_IMAGEGMOD_INFO:
        {
            RtlSecureZeroMemory(&imageinfo, sizeof(IMAGEMODINFO));
            RtlCopyMemory(&imageinfo, queue_node.packbuf, queue_node.packlen);

            (*MapMessage)["win_sysmonitor_mod_pid"] = to_string(imageinfo.processid);
            (*MapMessage)["win_sysmonitor_mod_base"] = to_string(imageinfo.imagebase);
            (*MapMessage)["win_sysmonitor_mod_size"] = to_string(imageinfo.imagesize);
            tmpstr.clear();
            Wchar_tToString(tmpstr, imageinfo.imagename);
            (*MapMessage)["win_sysmonitor_mod_path"] = tmpstr;
            (*MapMessage)["win_sysmonitor_mod_sysimage"] = to_string(imageinfo.systemmodeimage);
        }
        break;
        case NF_REGISTERTAB_INFO:
        {
            RtlSecureZeroMemory(&registerinfo, sizeof(REGISTERINFO));
            RtlCopyMemory(&registerinfo, queue_node.packbuf, queue_node.packlen);
            tmpstr.clear();
            Choose_register(tmpstr, registerinfo.opeararg);
            if (tmpstr.size())
            {
                (*MapMessage)["win_sysmonitor_regtab_pid"] = to_string(registerinfo.processid);
                (*MapMessage)["win_sysmonitor_regtab_tpid"] = to_string(registerinfo.threadid);
                (*MapMessage)["win_sysmonitor_regtab_opeares"] = tmpstr;
            }
            else
            {
                // server 会丢弃该包 - 不关心的操作
                (*MapMessage)["win_sysmonitor_regtab_pid"] = to_string(2);
                (*MapMessage)["win_sysmonitor_regtab_pid"] = to_string(2);
            }
        }
        break;
        case NF_FILE_INFO:
        {
            RtlSecureZeroMemory(&fileinfo, sizeof(FILEINFO));
            RtlCopyMemory(&fileinfo, queue_node.packbuf, queue_node.packlen);
            (*MapMessage)["win_sysmonitor_file_pid"] = to_string(fileinfo.processid);
            (*MapMessage)["win_sysmonitor_file_tpid"] = to_string(fileinfo.threadid);
            tmpstr.clear();
            Wchar_tToString(tmpstr, fileinfo.DosName);
            (*MapMessage)["win_sysmonitor_file_dosname"] = tmpstr;
            tmpstr.clear();
            Wchar_tToString(tmpstr, fileinfo.FileName);
            (*MapMessage)["win_sysmonitor_file_name"] = tmpstr;

            //file attir
            (*MapMessage)["win_sysmonitor_file_LockOperation"] = to_string(fileinfo.LockOperation);
            (*MapMessage)["win_sysmonitor_file_DeletePending"] = to_string(fileinfo.DeletePending);
            (*MapMessage)["win_sysmonitor_file_ReadAccess"] = to_string(fileinfo.ReadAccess);
            (*MapMessage)["win_sysmonitor_file_WriteAccess"] = to_string(fileinfo.WriteAccess);
            (*MapMessage)["win_sysmonitor_file_DeleteAccess"] = to_string(fileinfo.DeleteAccess);
            (*MapMessage)["win_sysmonitor_file_SharedRead"] = to_string(fileinfo.SharedRead);
            (*MapMessage)["win_sysmonitor_file_SharedWrite"] = to_string(fileinfo.SharedWrite);
            (*MapMessage)["win_sysmonitor_file_SharedDelete"] = to_string(fileinfo.SharedDelete);
            (*MapMessage)["win_sysmonitor_file_flag"] = to_string(fileinfo.flag);
        }
        break;
        case NF_SESSION_INFO:
        {
            RtlSecureZeroMemory(&sessioninfo, sizeof(SESSIONINFO));
            RtlCopyMemory(&sessioninfo, queue_node.packbuf, queue_node.packlen);
            RtlSecureZeroMemory(&iosession, sizeof(IO_SESSION_STATE_INFORMATION));
            RtlCopyMemory(&iosession, sessioninfo.iosessioninfo, sizeof(IO_SESSION_STATE_INFORMATION));

            tmpstr.clear();
            Choose_session(tmpstr, sessioninfo.evens);

            if (iosession.LocalSession)
                tmpstr += " - User Local Login";
            else
                tmpstr += " - User Remote Login";

            (*MapMessage)["win_sysmonitor_session_pid"] = to_string(sessioninfo.processid);
            (*MapMessage)["win_sysmonitor_session_tpid"] = to_string(sessioninfo.threadid);
            (*MapMessage)["win_sysmonitor_session_event"] = tmpstr;
            (*MapMessage)["win_sysmonitor_session_sessionid"] = to_string(iosession.SessionId);
            
        }
        break;
        default:
            break;
        }
        
        ggrpc_writecs.lock();
        if (Grpc_Getstream())
            m_stream->Write(rawData);
        ggrpc_writecs.unlock();

        free(queue_node.packbuf);
        queue_node.packbuf = nullptr;
        ggrpc_queue.pop();

        ggrpc_queuecs.unlock();
    }

}
static unsigned WINAPI _threadProc(void* pData)
{
    (reinterpret_cast<Grpc*>(pData))->threadProc();
    return 0;
}
bool Grpc::ThreadPool_Init()
{
    this->m_jobAvailableEvent = CreateEvent(NULL, FALSE, FALSE, NULL);

    if (!m_jobAvailableEvent)
        return false;

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

    for (i = 0; i < threadCount; i++)
    {
        hThread = (HANDLE)_beginthreadex(0, 0,
            _threadProc,
            (LPVOID)this,
            0,
            &threadId);

        if (hThread != 0 && hThread != (HANDLE)(-1L))
        {
            m_threads.push_back(hThread);
        }
    }
    return true;
}
bool Grpc::ThreadPool_Free()
{
    // 设置标志
    g_shutdown = true;
    SetEvent(m_jobAvailableEvent);
    if (m_jobAvailableEvent != INVALID_HANDLE_VALUE)
    {
        ::CloseHandle(m_jobAvailableEvent);
        m_jobAvailableEvent = INVALID_HANDLE_VALUE;
    }

    // 循环关闭句柄
    for (tThreads::iterator it = m_threads.begin();
        it != m_threads.end();
        it++)
    {
        WaitForSingleObject(*it, INFINITE);
        CloseHandle(*it);
    }

    m_threads.clear();

    return true;
}
bool Grpc::Grpc_pushQueue(const int code, const char* buf, int len)
{
    if (code < 150 || code > 200)
        return false;

    char* pack = (char*)malloc(len + 1);
    if (!pack && !len)
        return false;

    RtlSecureZeroMemory(pack, len + 1);
    RtlCopyMemory(pack, buf, len);
    NodeQueue tmpqueue;
    RtlSecureZeroMemory(&tmpqueue, sizeof(NodeQueue));
    tmpqueue.code = code;
    tmpqueue.packbuf = pack; // 保存指针
    tmpqueue.packlen = len;

    ggrpc_queuecs.lock();
    ggrpc_queue.push(tmpqueue);
    ggrpc_queuecs.unlock();

    // 处理pack
    SetEvent(this->m_jobAvailableEvent);

    return true;
}