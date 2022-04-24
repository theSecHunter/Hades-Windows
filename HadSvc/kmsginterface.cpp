#include "msgassist.h"
#include "kmsginterface.h"

#include "ArkSsdt.h"
#include "ArkIdt.h"
#include "ArkDpcTimer.h"
#include "ArkFsd.h"
#include "ArkMouseKeyBoard.h"
#include "ArkNetwork.h"
#include "ArkProcessInfo.h"
#include "AkrSysDriverDevInfo.h"
#include "drvlib.h"

//rapidjson
#include <rapidjson/rapidjson.h>
#include <rapidjson/document.h>
#include <rapidjson/stringbuffer.h>
#include <rapidjson/writer.h>

//nlohmannjson
#include <json.hpp>
using json_t = nlohmann::json;

// 生产者对象
static ArkSsdt		        g_kernel_ssdtobj;
static ArkIdt				g_kernel_idtobj;
static ArkDpcTimer		    g_kernel_dpcobj;
static ArkFsd				g_kernel_fsdobj;
static ArkMouseKeyBoard	    g_kernel_mousekeyboardobj;
static ArkNetwork			g_kernel_networkobj;
static ArkProcessInfo		g_kernel_processinfo;
static AkrSysDriverDevInfo	g_kernel_sysmodinfo;
static DevctrlIoct          g_kernel_Ioct;
static bool                 g_exit = false;
const char devSyLinkName[] = "\\??\\Sysmondrv_hades";

// 设置Grpc消费者指针(被消费者调用)
static std::queue<std::shared_ptr<USubNode>>*       g_GrpcQueue_Ptr = NULL;
static std::mutex*                                  g_GrpcQueueCs_Ptr = NULL;
static HANDLE                                       g_GrpcQueue_Event = NULL;
void kMsgInterface::kMsg_SetSubQueuePtr(std::queue<std::shared_ptr<USubNode>>& qptr) { g_GrpcQueue_Ptr = &qptr; }
void kMsgInterface::kMsg_SetSubQueueLockPtr(std::mutex& qptrcs) { g_GrpcQueueCs_Ptr = &qptrcs; }
void kMsgInterface::kMsg_SetSubEventPtr(HANDLE& eventptr) { g_GrpcQueue_Event = eventptr; }

static std::queue<UPubNode*>    g_kerdata_queue;
static std::mutex               g_kerdata_cs;
static HANDLE                   g_kjobAvailableEvent = nullptr;
inline void kMsgInterface::kMsg_SetTopicQueuePtr() { g_kernel_Ioct.kf_setqueuetaskptr(g_kerdata_queue); }
inline void kMsgInterface::kMsg_SetTopicQueueLockPtr() { g_kernel_Ioct.kf_setqueuelockptr(g_kerdata_cs); }
inline void kMsgInterface::kMsg_SetTopicEventPtr() { g_kernel_Ioct.kf_setqueueeventptr(g_kjobAvailableEvent); }

kMsgInterface::kMsgInterface()
{
}
kMsgInterface::~kMsgInterface()
{
}

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
void Choose_register(string& opearestring, const int code)
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
void kMsgInterface::kMsgNotifyRouteDataHandlerEx()
{
    static json_t j;
    UPubNode* pubnode = nullptr;
    static std::string tmpstr;

    g_kerdata_cs.lock();
    for (;;)
    {
        Sleep(10);
        if (g_kerdata_queue.empty())
        {
            g_kerdata_cs.unlock();
            return;
        }
        pubnode = g_kerdata_queue.front();
        g_kerdata_queue.pop();  
        if (!pubnode)
        {
            g_kerdata_cs.unlock();
            return;
        }
        const int taskid = pubnode->taskid;
        switch (taskid)
        {
        case NF_PROCESS_INFO:
        {
            PROCESSINFO* processinfo = (PROCESSINFO*)pubnode->data;
            j["win_sysmonitor_process_pid"] = to_string(processinfo->processid);
            j["win_sysmonitor_process_endprocess"] = to_string(processinfo->endprocess);
            if (processinfo->endprocess)
            {
                tmpstr.clear();
                Wchar_tToString(tmpstr, processinfo->queryprocesspath);
                tmpstr = String_ToUtf8(tmpstr);
                j["win_sysmonitor_process_queryprocesspath"] = tmpstr.c_str();
                tmpstr.clear();
                Wchar_tToString(tmpstr, processinfo->processpath);
                tmpstr = String_ToUtf8(tmpstr);
                j["win_sysmonitor_process_processpath"] = tmpstr.c_str();
                tmpstr.clear();
                Wchar_tToString(tmpstr, processinfo->commandLine);
                tmpstr = String_ToUtf8(tmpstr);
                j["win_sysmonitor_process_commandLine"] = tmpstr.c_str();
            }
            else
            {
                tmpstr.clear();
                Wchar_tToString(tmpstr, processinfo->queryprocesspath);
                tmpstr = String_ToUtf8(tmpstr);
                j["win_sysmonitor_process_queryprocesspath"] = tmpstr.c_str();
            }
        }
        break;
        case NF_THREAD_INFO:
        {
            THREADINFO* threadinfo = (THREADINFO*)pubnode->data;
            j["win_sysmonitor_thread_pid"] = to_string(threadinfo->processid);
            j["win_sysmonitor_thread_id"] = to_string(threadinfo->threadid);
            j["win_sysmonitor_thread_status"] = to_string(threadinfo->createid);
        }
        break;
        case NF_IMAGEGMOD_INFO:
        {
            IMAGEMODINFO* imageinfo = (IMAGEMODINFO*)pubnode->data;
            j["win_sysmonitor_mod_pid"] = to_string(imageinfo->processid);
            j["win_sysmonitor_mod_base"] = to_string(imageinfo->imagebase);
            j["win_sysmonitor_mod_size"] = to_string(imageinfo->imagesize);
            tmpstr.clear();
            Wchar_tToString(tmpstr, imageinfo->imagename);
            tmpstr = String_ToUtf8(tmpstr);
            j["win_sysmonitor_mod_path"] = tmpstr.c_str();
            j["win_sysmonitor_mod_sysimage"] = to_string(imageinfo->systemmodeimage);
        }
        break;
        case NF_REGISTERTAB_INFO:
        {
            REGISTERINFO* registerinfo = (REGISTERINFO*)pubnode->data;
            tmpstr.clear();
            Choose_register(tmpstr, registerinfo->opeararg);
            if (tmpstr.size())
            {
                j["win_sysmonitor_regtab_pid"] = to_string(registerinfo->processid);
                j["win_sysmonitor_regtab_tpid"] = to_string(registerinfo->threadid);
                j["win_sysmonitor_regtab_opeares"] = tmpstr.c_str();
            }
            else
            {
                // server 会丢弃该包 - 不关心的操作
                j["win_sysmonitor_regtab_pid"] = to_string(2);
                j["win_sysmonitor_regtab_pid"] = to_string(2);
            }
        }
        break;
        case NF_FILE_INFO:
        {
            FILEINFO* fileinfo = (FILEINFO*)pubnode->data;
            j["win_sysmonitor_file_pid"] = to_string(fileinfo->processid);
            j["win_sysmonitor_file_tpid"] = to_string(fileinfo->threadid);
            tmpstr.clear();
            Wchar_tToString(tmpstr, fileinfo->DosName);
            tmpstr = String_ToUtf8(tmpstr);
            j["win_sysmonitor_file_dosname"] = tmpstr.c_str();
            tmpstr.clear();
            Wchar_tToString(tmpstr, fileinfo->FileName);
            tmpstr = String_ToUtf8(tmpstr);
            j["win_sysmonitor_file_name"] = tmpstr.c_str();

            //file attir
            j["win_sysmonitor_file_LockOperation"] = to_string(fileinfo->LockOperation);
            j["win_sysmonitor_file_DeletePending"] = to_string(fileinfo->DeletePending);
            j["win_sysmonitor_file_ReadAccess"] = to_string(fileinfo->ReadAccess);
            j["win_sysmonitor_file_WriteAccess"] = to_string(fileinfo->WriteAccess);
            j["win_sysmonitor_file_DeleteAccess"] = to_string(fileinfo->DeleteAccess);
            j["win_sysmonitor_file_SharedRead"] = to_string(fileinfo->SharedRead);
            j["win_sysmonitor_file_SharedWrite"] = to_string(fileinfo->SharedWrite);
            j["win_sysmonitor_file_SharedDelete"] = to_string(fileinfo->SharedDelete);
            j["win_sysmonitor_file_flag"] = to_string(fileinfo->flag);
        }
        break;
        case NF_SESSION_INFO:
        {
            SESSIONINFO* sessioninfo = (SESSIONINFO*)pubnode->data;;
            std::shared_ptr<IO_SESSION_STATE_INFORMATION> iosession;
            RtlSecureZeroMemory(&iosession, sizeof(IO_SESSION_STATE_INFORMATION));
            RtlCopyMemory(&iosession, sessioninfo->iosessioninfo, sizeof(IO_SESSION_STATE_INFORMATION));

            tmpstr.clear();
            Choose_session(tmpstr, sessioninfo->evens);

            if (iosession->LocalSession)
                tmpstr += " - User Local Login";
            else
                tmpstr += " - User Remote Login";

            j["win_sysmonitor_session_pid"] = to_string(sessioninfo->processid);
            j["win_sysmonitor_session_tpid"] = to_string(sessioninfo->threadid);
            j["win_sysmonitor_session_event"] = tmpstr.c_str();
            j["win_sysmonitor_session_sessionid"] = to_string(iosession->SessionId);
        
        }
        break;
        }

        // 注: Topic 释放 Pub的数据指针
        if (pubnode)
        {
            delete[] pubnode;
            pubnode = nullptr;
        }

        // 序列化
        std::shared_ptr<std::string> data;
        if (j.size())
            data = std::make_shared<std::string>(j.dump());
        else
            continue;

        if (!g_GrpcQueue_Ptr && !g_GrpcQueueCs_Ptr && !g_GrpcQueue_Event)
        {
            g_kerdata_cs.unlock();
            OutputDebugString(L"Grpc没设置订阅指针");
            return;
        }

        std::shared_ptr<USubNode> sub = std::make_shared<USubNode>();
        if (!sub || !data)
        {
            g_kerdata_cs.unlock();
            return;
        }
        sub->data = data;
        sub->taskid = taskid;
        g_GrpcQueueCs_Ptr->lock();
        g_GrpcQueue_Ptr->push(sub);
        g_GrpcQueueCs_Ptr->unlock();
        SetEvent(g_GrpcQueue_Event);

        j.clear();
        tmpstr.clear();
    }
    g_kerdata_cs.unlock();
}

void kMsgInterface::kMsg_taskPopNotifyRoutineLoop()
{
    try
    {
        if (!g_kjobAvailableEvent)
            return;
        do
        {
            WaitForSingleObject(
                g_kjobAvailableEvent,
                INFINITE
            );

            if (g_exit)
                break;

            kMsgNotifyRouteDataHandlerEx();

        } while (true);
    }
    catch (const std::exception&)
    {

    }
}
static unsigned WINAPI kMsg_taskPopThread(void* pData)
{
    (reinterpret_cast<kMsgInterface*>(pData))->kMsg_taskPopNotifyRoutineLoop();
    return 0;
}
void kMsgInterface::kMsg_taskPopInit()
{
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
        hThread = (HANDLE)_beginthreadex(0, 0, kMsg_taskPopThread, (LPVOID)this, 0, &threadId);
        if (hThread != 0 && hThread != (HANDLE)(-1L))
        {
            m_topicthread.push_back(hThread);
        }
    }
}

void kMsgInterface::kMsg_taskPush(const int taskcode, std::vector<std::string>& vec_task_string)
{
    map<int, wstring>::iterator iter;
    map<int, wstring> Process_list;
    std::string tmpstr; wstring catstr;
    int i = 0, index = 0;
    DWORD dwAllocateMemSize = 0;
    char* ptr_Getbuffer;
    bool nstatus = Choose_mem(ptr_Getbuffer, dwAllocateMemSize, taskcode);
    if (false == nstatus || nullptr == ptr_Getbuffer || dwAllocateMemSize == 0)
        return;

    json_t j;
    switch (taskcode)
    {
    case NF_SSDT_ID:
    {
        if (g_kernel_ssdtobj.nf_init())
        {
            if (false == g_kernel_ssdtobj.nf_GetSysCurrentSsdtData((LPVOID)ptr_Getbuffer, dwAllocateMemSize))
                break;
            SSDTINFO* ssdtinfo = (SSDTINFO*)ptr_Getbuffer;
            if (!ssdtinfo)
                break;

            for (i = 0; i < 0x200; ++i)
            {
                if (!ssdtinfo[i].sstd_memoffset)
                    continue;
                j["win_rootkit_ssdt_id"] = to_string(ssdtinfo[i].ssdt_id).c_str();
                j["win_rootkit_ssdt_offsetaddr"] = to_string(ssdtinfo[i].sstd_memoffset).c_str();
                vec_task_string.push_back(j.dump());
            }
            std::cout << "Grpc Ssdt Send Pkg Success" << std::endl;
            break;
        }
    }
    break;
    case NF_IDT_ID:
    {
        if (g_kernel_idtobj.nf_init())
        {
            if (!g_kernel_idtobj.nf_GetIdtData((LPVOID)ptr_Getbuffer, dwAllocateMemSize))
                break;
            IDTINFO* idtinfo = (IDTINFO*)ptr_Getbuffer;
            if (!idtinfo)
                break;

            for (i = 0; i < 0x100; ++i)
            {
                if (!idtinfo[i].idt_isrmemaddr)
                    continue;
                j["win_rootkit_idt_id"] = to_string(idtinfo[i].idt_id).c_str();
                j["win_rootkit_idt_offsetaddr"] = to_string(idtinfo[i].idt_isrmemaddr).c_str();
                vec_task_string.push_back(j.dump());
            }
            std::cout << "Grpc Ssdt Send Pkg Success" << std::endl;
        }
    }
    break;
    case NF_DPC_ID:
    {
        if (false == g_kernel_dpcobj.nf_GetDpcTimerData((LPVOID)ptr_Getbuffer, dwAllocateMemSize))
            break;
        DPC_TIMERINFO* dpcinfo = (DPC_TIMERINFO*)ptr_Getbuffer;
        if (!dpcinfo)
            break;

        for (i = 0; i < 0x100; ++i)
        {
            if (!dpcinfo[i].dpc)
                continue;
            j["win_rootkit_dpc"] = to_string(dpcinfo[i].dpc).c_str();
            j["win_rootkit_dpc_timeobj"] = to_string(dpcinfo[i].timeroutine).c_str();
            j["win_rootkit_dpc_timeroutine"] = to_string(dpcinfo[i].timeroutine).c_str();
            j["win_rootkit_dpc_periodtime"] = to_string(dpcinfo[i].period).c_str();
            vec_task_string.push_back(j.dump());
        }
        std::cout << "Grpc Dpc Send Pkg Success" << std::endl;
    }
    break;
    case NF_FSD_ID:
    {
        if (false == g_kernel_fsdobj.nf_GetFsdInfo(ptr_Getbuffer, dwAllocateMemSize))
            break;

        ULONGLONG* MjAddrArry = (ULONGLONG*)ptr_Getbuffer;
        if (!MjAddrArry)
            break;

        j["win_rootkit_is_fsdmod"] = "1";
        for (i = 0; i < 0x1b; ++i)
        {
            j["win_rootkit_fsdfastfat_id"] = to_string(MjAddrArry[index]).c_str();
            j["win_rootkit_fsdfastfat_mjaddr"] = to_string(MjAddrArry[index]).c_str();
            vec_task_string.push_back(j.dump());
            index++;
        }
        std::cout << "FastFat MjFuction End" << std::endl;

        j.clear();
        j["win_rootkit_is_fsdmod"] = "2";
        for (i = 0; i < 0x1b; ++i)
        {
            j["win_rootkit_fsdntfs_id"] = to_string(MjAddrArry[index]).c_str();
            j["win_rootkit_fsdntfs_mjaddr"] = to_string(MjAddrArry[index]).c_str();
            vec_task_string.push_back(j.dump());
            index++;
        }
        std::cout << "Ntfs MjFuction End" << std::endl;
    }
    break;
    case NF_SYSCALLBACK_ID:
    {
    }
    break;
    case NF_MOUSEKEYBOARD_ID:
    {
        if (false == g_kernel_mousekeyboardobj.nf_GetMouseKeyInfoData(ptr_Getbuffer, dwAllocateMemSize))
            break;

        ULONGLONG* MjAddrArry = (ULONGLONG*)ptr_Getbuffer;
        if (!MjAddrArry)
            break;

        j["win_rootkit_is_mousekeymod"] = "1";
        for (i = 0; i < 0x1b; ++i)
        {
            j["win_rootkit_Mouse_id"] = to_string(MjAddrArry[index]).c_str();
            j["win_rootkit_Mouse_mjaddr"] = to_string(MjAddrArry[index]).c_str();
            vec_task_string.push_back(j.dump());
            index++;
        }
        std::cout << "Mouse MjFuction End" << std::endl;

        j.clear();
        j["win_rootkit_is_mousekeymod"] = "2";
        for (i = 0; i < 0x1b; ++i)
        {
            j["win_rootkit_i8042_id"] = to_string(MjAddrArry[index]).c_str();
            j["win_rootkit_i8042_mjaddr"] = to_string(MjAddrArry[index]).c_str();
            vec_task_string.push_back(j.dump());
            index++;
        }
        std::cout << "i8042 MjFuction End" << std::endl;

        j.clear();
        j["win_rootkit_is_mousekeymod"] = "3";
        for (i = 0; i < 0x1b; ++i)
        {
            j["win_rootkit_kbd_id"] = to_string(MjAddrArry[index]).c_str();
            j["win_rootkit_kbd_mjaddr"] = to_string(MjAddrArry[index]).c_str();
            vec_task_string.push_back(j.dump());
            index++;
        }
        std::cout << "kbd MjFuction End" << std::endl;
    }
    break;
    case NF_NETWORK_ID:
    {
        if (false == g_kernel_networkobj.nf_GetNteworkProcessInfo(ptr_Getbuffer, dwAllocateMemSize))
            break;

        PSYSNETWORKINFONODE networkinfo = (PSYSNETWORKINFONODE)ptr_Getbuffer;
        if (!networkinfo)
            break;

        
        // Tcp
        j["win_rootkit_is_mod"] = "1";
        for (i = 0; i < networkinfo->tcpcout; ++i)
        {
            j["win_rootkit_tcp_pid"] = to_string(networkinfo->systcpinfo[i].processinfo.dwTcpProId).c_str();
            j["win_rootkit_tcp_localIp_port"] = to_string(networkinfo->systcpinfo[i].TpcTable.localEntry.dwIP).c_str();
            j["win_rootkit_tcp_remoteIp_port"] = to_string(networkinfo->systcpinfo[i].TpcTable.remoteEntry.dwIP).c_str();
            j["win_rootkit_tcp_Status"] = to_string(networkinfo->systcpinfo[i].socketStatus.dwState).c_str();
            vec_task_string.push_back(j.dump());
        }
        std::cout << "Tpc Port Send Grpc Success" << std::endl;

        j.clear();
        j["win_rootkit_is_mod"] = "2";
        std::string udpipport;
        for (i = 0; i < networkinfo->udpcout; ++i)
        {
            udpipport = to_string(networkinfo->sysudpinfo[i].UdpTable.dwIP) + ":" + to_string(ntohs(networkinfo->sysudpinfo[i].UdpTable.Port));
            j["win_rootkit_udp_pid"] = to_string(networkinfo->sysudpinfo[i].processinfo.dwUdpProId).c_str();
            j["win_rootkit_udp_localIp_port"] = udpipport.c_str();
            vec_task_string.push_back(j.dump());
        }
        std::cout << "Udp Port Send Grpc Success" << std::endl;
    }
    break;
    case NF_PROCESS_ENUM:
    {
        if (false == g_kernel_processinfo.nf_EnumProcess(ptr_Getbuffer, dwAllocateMemSize))
            break;

        PHANDLE_INFO phandleinfo = (PHANDLE_INFO)ptr_Getbuffer;
        if (phandleinfo && phandleinfo[0].CountNum)
        {

            for (i = 0; i < phandleinfo[0].CountNum; ++i)
            {
                //wcout << "Pid: " << phandleinfo[i].ProcessId << " - Process: " << phandleinfo[i].ProcessPath << endl;// " - ProcessName: " << phandleinfo[i].ProcessName << endl;
                // 去重
                catstr = phandleinfo[i].ProcessPath;
                catstr += L" - ";
                catstr += phandleinfo[i].ProcessName;
                Process_list[phandleinfo[i].ProcessId] = catstr;
                catstr.clear();
            }


            for (iter = Process_list.begin(); iter != Process_list.end(); iter++)
            {
                j["win_rootkit_process_pid"] = to_string(iter->first).c_str();
                tmpstr.clear();
                Wchar_tToString(tmpstr, (wchar_t*)iter->second.data());
                tmpstr = String_ToUtf8(tmpstr);
                j["win_rootkit_process_info"] = tmpstr.c_str();
                vec_task_string.push_back(j.dump());
            }

            std::cout << "processinfo to server Success" << std::endl;
        }
    }
    break;
    case NF_PROCESS_MOD:
    {
        int Process_Pid = 4;
        cout << "Please Input Pid: 4";
        //scanf("%d", &Process_Pid);
        // 默认测试
        if (false == g_kernel_processinfo.nf_GetProcessMod(Process_Pid, ptr_Getbuffer, dwAllocateMemSize))
            break;

        PPROCESS_MOD modptr = (PPROCESS_MOD)ptr_Getbuffer;
        if (modptr)
        {
            j["win_rootkit_processmod_pid"] = to_string(Process_Pid).c_str();
            for (i = 0; i < 1024 * 2; ++i)
            {
                if (0 == modptr[i].EntryPoint && 0 == modptr[i].SizeOfImage && 0 == modptr[i].DllBase)
                    continue;
                j["win_rootkit_process_DllBase"] = to_string(modptr[i].DllBase).c_str();
                j["win_rootkit_process_SizeofImage"] = to_string(modptr[i].SizeOfImage).c_str();
                j["win_rootkit_process_EntryPoint"] = to_string(modptr[i].EntryPoint).c_str();
                tmpstr.clear();
                Wchar_tToString(tmpstr, modptr[i].BaseDllName);
                tmpstr = String_ToUtf8(tmpstr);
                j["win_rootkit_process_BaseDllName"] = tmpstr.c_str();
                tmpstr.clear();
                Wchar_tToString(tmpstr, modptr[i].FullDllName);
                tmpstr = String_ToUtf8(tmpstr);
                j["win_rootkit_process_FullDllName"] = tmpstr.c_str();
                vec_task_string.push_back(j.dump());
            }
        }
        std::cout << "Process Mod Success" << std::endl;
    }
    break;
    case NF_PROCESS_KILL:
    {
         g_kernel_processinfo.nf_KillProcess();
    }
    break;
    case NF_SYSMOD_ENUM:
    {
        if (false == g_kernel_sysmodinfo.nf_EnumSysMod(ptr_Getbuffer, dwAllocateMemSize))
            break;


        PPROCESS_MOD modptr = (PPROCESS_MOD)ptr_Getbuffer;
        if (modptr)
        {
            for (i = 0; i < 1024 * 2; ++i)
            {
                // Bug
                if (0 == modptr[i].EntryPoint && 0 == modptr[i].SizeOfImage && 0 == modptr[i].DllBase)
                    continue;
                j["win_rootkit_sys_DllBase"] = to_string(modptr[i].DllBase).c_str();
                j["win_rootkit_sys_SizeofImage"] = to_string(modptr[i].SizeOfImage).c_str();
                j["win_rootkit_sys_EntryPoint"] = to_string(modptr[i].EntryPoint).c_str();
                tmpstr.clear();
                Wchar_tToString(tmpstr, modptr[i].BaseDllName);
                tmpstr = String_ToUtf8(tmpstr);
                j["win_rootkit_sys_BaseDllName"] = tmpstr.c_str();
                tmpstr.clear();
                Wchar_tToString(tmpstr, modptr[i].FullDllName);
                tmpstr = String_ToUtf8(tmpstr);
                j["win_rootkit_sys_FullDllName"] = tmpstr.c_str();
                vec_task_string.push_back(j.dump());
            }
        }
        std::cout << "SystemDriver Enum Success" << std::endl;
    }
    break;

    default:
        break;
    }
}

void kMsgInterface::DriverInit()
{
    int status = 0;

    // Init devctrl
    status = g_kernel_Ioct.devctrl_init();
    if (0 > status)
    {
        cout << "devctrl_init error: main.c --> lines: 342" << endl;
        return;
    }

    do
    {
        // Open driver
        status = g_kernel_Ioct.devctrl_opendeviceSylink(devSyLinkName);
        if (0 > status)
        {
            cout << "devctrl_opendeviceSylink error: main.c --> lines: 352" << endl;
            break;
        }

        // Init share Mem
        status = g_kernel_Ioct.devctrl_InitshareMem();
        if (0 > status)
        {
            cout << "devctrl_InitshareMem error: main.c --> lines: 360" << endl;
            break;
        }

        // ReadFile I/O Thread
        status = g_kernel_Ioct.devctrl_workthread(NULL);
        if (0 > status)
        {
            cout << "devctrl_workthread error: main.c --> lines: 367" << endl;
            break;
        }

        // Enable Event --> 内核提取出来数据以后处理类
        //g_kernel_Ioct.nf_setEventHandler((PVOID)&eventobj);

        status = 1;
    } while (false);

    if (!status)
    {
        OutputDebugString(L"Init Driver Failuer");
        return;
    }

    kInitStatus = true;
}
void kMsgInterface::DriverFree()
{
    g_kernel_Ioct.devctrl_free();
    kInitStatus = false;
}
void kMsgInterface::OnMonitor()
{
    int status = 0;
    // Off/Enable try Network packte Monitor
    status = g_kernel_Ioct.devctrl_OnMonitor();
    if (0 > status)
    {
        cout << "devctrl_InitshareMem error: main.c --> lines: 375" << endl;
    }
    kerMonStatus = true;
    return;
}
void kMsgInterface::OffMonitor()
{
    int status = 0;
    // Off/Enable try Network packte Monitor
    status = g_kernel_Ioct.devctrl_OffMonitor();
    Sleep(100);
    if (0 > status)
    {
        cout << "devctrl_InitshareMem error: main.c --> lines: 375" << endl;
    }
    kerMonStatus = false;
    return;
    
}
void kMsgInterface::OnBeSnipingMonitor()
{
    kBesnipingStatus = true;
}
void kMsgInterface::OffBeSnipingMonitor()
{
    kBesnipingStatus = false;
}
bool kMsgInterface::GetKerMonStatus()
{
    return kerMonStatus;
}
bool kMsgInterface::GetKerInitStatus()
{
    return kInitStatus;
}
bool kMsgInterface::GetKerBeSnipingStatus()
{
    return kBesnipingStatus;
}

void kMsgInterface::kMsg_Init() {
    // 初始化Topic
    g_kjobAvailableEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
    this->kMsg_SetTopicQueuePtr();
    this->kMsg_SetTopicQueueLockPtr();
    this->kMsg_SetTopicEventPtr();
    // 最后调用
    this->kMsg_taskPopInit();
};
void kMsgInterface::kMsg_Free()
{
    g_exit = true;
    for (size_t idx = 0; idx < m_topicthread.size(); ++idx)
    {
        SetEvent(g_kjobAvailableEvent);
        WaitForSingleObject(m_topicthread[idx], 1000);
        CloseHandle(m_topicthread[idx]);
    }

    if (g_kjobAvailableEvent != INVALID_HANDLE_VALUE)
    {
        ::CloseHandle(g_kjobAvailableEvent);
        g_kjobAvailableEvent = INVALID_HANDLE_VALUE;
    }
    m_topicthread.clear();
}