#include "msgassist.h"
#include "kmsginterface.h"
#include "kinterface.h"

#include <ProcessRuleAssist.h>
#include <RegisterRuleAssist.h>
#include <DirectoryRuleAssist.h>
#include <ThreadRuleAssist.h>

//rapidjson
#include <rapidjson/rapidjson.h>
#include <rapidjson/document.h>
#include <rapidjson/stringbuffer.h>
#include <rapidjson/writer.h>

//nlohmannjson
#include <json.hpp>
using json_t = nlohmann::json;

static DevctrlIoct          g_kernel_Ioct;

static bool                 g_exit = false;
const char devSyLinkName[] = "\\??\\Sysmondrv_hades";

static std::queue<UPubNode*>    g_RecvDataQueue;
static std::mutex               g_RecvDataQueueCs;
static HANDLE                   g_kjobAvailableEvent = nullptr;
inline void kMsgInterface::kMsg_SetTopicQueuePtr() { SingletonKDrvManage::instance()->kf_setqueuetaskptr(g_RecvDataQueue); }
inline void kMsgInterface::kMsg_SetTopicQueueLockPtr() { SingletonKDrvManage::instance()->kf_setqueuelockptr(g_RecvDataQueueCs); }
inline void kMsgInterface::kMsg_SetTopicEventPtr() { SingletonKDrvManage::instance()->kf_setqueueeventptr(g_kjobAvailableEvent); }

// 设置Grpc消费者指针(被消费者调用)
static std::queue<std::shared_ptr<USubNode>>*       g_SendQueueData_Ptr = NULL;
static std::mutex*                                  g_SendQueueCs_Ptr = NULL;
static HANDLE                                       g_SendQueue_Event = NULL;
void kMsgInterface::kMsg_SetSubQueuePtr(std::queue<std::shared_ptr<USubNode>>& qptr) { g_SendQueueData_Ptr = &qptr; }
void kMsgInterface::kMsg_SetSubQueueLockPtr(std::mutex& qptrcs) { g_SendQueueCs_Ptr = &qptrcs; }
void kMsgInterface::kMsg_SetSubEventPtr(HANDLE& eventptr) { g_SendQueue_Event = eventptr; }

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
    case RegNtPreCreateKey:
    {
        opearestring = "RegNtPreCreateKey";
    }
    break;
    case RegNtPreOpenKey:
    {
        opearestring = "RegNtPreOpenKey";
    }
    break;
    case RegNtPreCreateKeyEx:
    {
        opearestring = "RegNtPreCreateKeyEx";
    }
    break;
    case RegNtPreOpenKeyEx:
    {
        opearestring = "RegNtPreOpenKeyEx";
    }
    break;
    case RegNtPostCreateKey:
    {
        opearestring = "RegNtPostCreateKey";
    }
    break;
    case RegNtPostOpenKey:
    {
        opearestring = "RegNtPostOpenKey";
    }
    break;
    case RegNtPostCreateKeyEx:
    {
        opearestring = "RegNtPostCreateKeyEx";
    }
    break;
    case RegNtPostOpenKeyEx:
    {
        opearestring = "RegNtPostOpenKeyEx";
    }
    break;
    case RegNtQueryValueKey:
    {
        opearestring = "RegNtQueryValueKey";
    }
    break;
    // 修改Key
    case RegNtSetValueKey:
    {
        opearestring = "RegNtSetValueKey";
    }
    // 删除Key
    case RegNtPreDeleteKey:
    {
        opearestring = "RegNtPreDeleteKey";
    }
    break;
    // 枚举Key
    case RegNtEnumerateKey:
    {
        opearestring = "RegNtEnumerateKey";
    }
    break;

    // 重命名注册表
    case RegNtPostRenameKey:
    {
        opearestring = "RegNtPostRenameKey";
    }
    break;
    default:
        opearestring = "";
        break;
    }
}
void kMsgInterface::kMsgNotifyRouteDataHandlerEx()
{
    std::unique_lock<std::mutex> lock(g_RecvDataQueueCs);

    try
    {
        json_t j;
        std::string tmpstr = "";
        UPubNode* pubNode = nullptr;

        for (;;)
        {
            Sleep(1);
            if (g_RecvDataQueue.empty())
                return;
            pubNode = g_RecvDataQueue.front();
            g_RecvDataQueue.pop();
            if (!pubNode)
                return;
            const int taskid = pubNode->taskid;
            switch (taskid)
            {
            case NF_PROCESS_INFO:
            {
                const PROCESSINFO* pProcessInfo = (PROCESSINFO*)pubNode->data;
                if (!pProcessInfo)
                    break;
                j["win_sysmonitor_process_parentpid"] = to_string(pProcessInfo->parentprocessid);
                j["win_sysmonitor_process_pid"] = to_string(pProcessInfo->pid);
                j["win_sysmonitor_process_endprocess"] = to_string(pProcessInfo->endprocess);
                if (pProcessInfo->endprocess)
                {
                    tmpstr.clear();
                    Wchar_tToString(tmpstr, pProcessInfo->queryprocesspath);
                    tmpstr = String_ToUtf8(tmpstr);
                    j["win_sysmonitor_process_queryprocesspath"] = tmpstr.c_str();
                    tmpstr.clear();
                    Wchar_tToString(tmpstr, pProcessInfo->processpath);
                    tmpstr = String_ToUtf8(tmpstr);
                    j["win_sysmonitor_process_processpath"] = tmpstr.c_str();
                    tmpstr.clear();
                    Wchar_tToString(tmpstr, pProcessInfo->commandLine);
                    tmpstr = String_ToUtf8(tmpstr);
                    j["win_sysmonitor_process_commandLine"] = tmpstr.c_str();
                }
                else
                {
                    tmpstr.clear();
                    Wchar_tToString(tmpstr, pProcessInfo->queryprocesspath);
                    tmpstr = String_ToUtf8(tmpstr);
                    j["win_sysmonitor_process_queryprocesspath"] = tmpstr.c_str();
                }
            }
            break;
            case NF_THREAD_INFO:
            {
                const THREADINFO* pThredInfo = (THREADINFO*)pubNode->data;
                if (!pThredInfo)
                    break;
                j["win_sysmonitor_thread_pid"] = to_string(pThredInfo->processid);
                j["win_sysmonitor_thread_id"] = to_string(pThredInfo->threadid);
                j["win_sysmonitor_thread_status"] = to_string(pThredInfo->createid);
            }
            break;
            case NF_IMAGEGMOD_INFO:
            {
                const IMAGEMODINFO* pImageInfo = (IMAGEMODINFO*)pubNode->data;
                if (!pImageInfo)
                    break;
                j["win_sysmonitor_mod_pid"] = to_string(pImageInfo->processid);
                j["win_sysmonitor_mod_base"] = to_string(pImageInfo->imagebase);
                j["win_sysmonitor_mod_size"] = to_string(pImageInfo->imagesize);
                tmpstr.clear();
                Wchar_tToString(tmpstr, pImageInfo->imagename);
                tmpstr = String_ToUtf8(tmpstr);
                j["win_sysmonitor_mod_path"] = tmpstr.c_str();
                j["win_sysmonitor_mod_sysimage"] = to_string(pImageInfo->systemmodeimage);
            }
            break;
            case NF_REGISTERTAB_INFO:
            {
                const REGISTERINFO* pRegisterInfo = (REGISTERINFO*)pubNode->data;
                if (!pRegisterInfo)
                    break;
                tmpstr.clear();
                Choose_register(tmpstr, pRegisterInfo->opeararg);
                if (tmpstr.size())
                {
                    j["win_sysmonitor_regtab_pid"] = to_string(pRegisterInfo->processid);
                    j["win_sysmonitor_regtab_tpid"] = to_string(pRegisterInfo->threadid);
                    j["win_sysmonitor_regtab_opeares"] = tmpstr.c_str();
                    const std::wstring processPath = pRegisterInfo->ProcessPath;
                    if (!processPath.empty())
                    {
                        tmpstr.clear();
                        Wchar_tToString(tmpstr, processPath.c_str());
                        if (!tmpstr.empty())
                            tmpstr = String_ToUtf8(tmpstr);
                        if (!tmpstr.empty())
                            j["win_sysmonitor_regtab_processPath"] = tmpstr.c_str();
                    }
                }
                else
                {
                    // server 丢弃该包 - 不关心的操作
                    j["win_sysmonitor_regtab_pid"] = to_string(pRegisterInfo->processid);
                    j["win_sysmonitor_regtab_tpid"] = to_string(pRegisterInfo->threadid);
                    j["win_sysmonitor_regtab_opeares"] = to_string(0);
                    break;
                }
                j["win_sysmonitor_regtab_rootobject"] = to_string((DWORD64)pRegisterInfo->RootObject);
                j["win_sysmonitor_regtab_object"] = to_string((DWORD64)pRegisterInfo->Object);
                j["win_sysmonitor_regtab_type"] = to_string(pRegisterInfo->Type);
                j["win_sysmonitor_regtab_attributes"] = to_string(pRegisterInfo->Attributes);
                j["win_sysmonitor_regtab_desiredAccess"] = to_string(pRegisterInfo->DesiredAccess);
                j["win_sysmonitor_regtab_disposition"] = to_string((DWORD64)pRegisterInfo->Disposition);
                j["win_sysmonitor_regtab_grantedAccess"] = to_string(pRegisterInfo->GrantedAccess);
                j["win_sysmonitor_regtab_options"] = to_string(pRegisterInfo->Options);
                j["win_sysmonitor_regtab_wow64Flags"] = to_string(pRegisterInfo->Wow64Flags);
                j["win_sysmonitor_regtab_keyInformationClass"] = to_string(pRegisterInfo->KeyInformationClass);
                j["win_sysmonitor_regtab_index"] = to_string(pRegisterInfo->Index);
                const std::wstring CompleteName = pRegisterInfo->CompleteName;
                if (!CompleteName.empty())
                {
                    tmpstr.clear();
                    Wchar_tToString(tmpstr, CompleteName.c_str());
                    if(!tmpstr.empty())
                        tmpstr = String_ToUtf8(tmpstr);
                    if (!tmpstr.empty())
                        j["win_sysmonitor_regtab_completeName"] = tmpstr.c_str();
                }
            }
            break;
            case NF_FILE_INFO:
            {
                const FILEINFO* pFileInfo = (FILEINFO*)pubNode->data;
                if (!pFileInfo)
                    break;
                j["win_sysmonitor_file_pid"] = to_string(pFileInfo->processid);
                j["win_sysmonitor_file_tpid"] = to_string(pFileInfo->threadid);
                tmpstr.clear();
                Wchar_tToString(tmpstr, pFileInfo->DosName);
                tmpstr = String_ToUtf8(tmpstr);
                j["win_sysmonitor_file_dosname"] = tmpstr.c_str();
                tmpstr.clear();
                Wchar_tToString(tmpstr, pFileInfo->FileName);
                tmpstr = String_ToUtf8(tmpstr);
                j["win_sysmonitor_file_name"] = tmpstr.c_str();

                //file attir
                j["win_sysmonitor_file_LockOperation"] = to_string(pFileInfo->LockOperation);
                j["win_sysmonitor_file_DeletePending"] = to_string(pFileInfo->DeletePending);
                j["win_sysmonitor_file_ReadAccess"] = to_string(pFileInfo->ReadAccess);
                j["win_sysmonitor_file_WriteAccess"] = to_string(pFileInfo->WriteAccess);
                j["win_sysmonitor_file_DeleteAccess"] = to_string(pFileInfo->DeleteAccess);
                j["win_sysmonitor_file_SharedRead"] = to_string(pFileInfo->SharedRead);
                j["win_sysmonitor_file_SharedWrite"] = to_string(pFileInfo->SharedWrite);
                j["win_sysmonitor_file_SharedDelete"] = to_string(pFileInfo->SharedDelete);
                j["win_sysmonitor_file_flag"] = to_string(pFileInfo->flag);
            }
            break;
            case NF_SESSION_INFO:
            {
                const SESSIONINFO* pSessionInfo = (SESSIONINFO*)pubNode->data;
                if (!pSessionInfo)
                    break;
                std::shared_ptr<IO_SESSION_STATE_INFORMATION> iosession;
                RtlSecureZeroMemory(&iosession, sizeof(IO_SESSION_STATE_INFORMATION));
                RtlCopyMemory(&iosession, pSessionInfo->iosessioninfo, sizeof(IO_SESSION_STATE_INFORMATION));

                tmpstr.clear();
                Choose_session(tmpstr, pSessionInfo->evens);

                if (iosession->LocalSession)
                    tmpstr += " - User Local Login";
                else
                    tmpstr += " - User Remote Login";

                j["win_sysmonitor_session_pid"] = to_string(pSessionInfo->processid);
                j["win_sysmonitor_session_tpid"] = to_string(pSessionInfo->threadid);
                j["win_sysmonitor_session_event"] = tmpstr.c_str();
                j["win_sysmonitor_session_sessionid"] = to_string(iosession->SessionId);
            }
            break;
            case NF_INJECT_INFO:
            {
                const INJECTINFO* const pInjectinfo = (INJECTINFO*)pubNode->data;
                if (!pInjectinfo)
                    break;
                j["win_sysmonitor_inject_srcpid"] = to_string(pInjectinfo->srcPid);
                j["win_sysmonitor_inject_dstpid"] = to_string(pInjectinfo->dstPid);
                tmpstr.clear();
                Wchar_tToString(tmpstr, pInjectinfo->srcProcessPath);
                tmpstr = String_ToUtf8(tmpstr);
                j["win_sysmonitor_inject_srcPath"] = tmpstr.c_str();
                tmpstr.clear();
                Wchar_tToString(tmpstr, pInjectinfo->dstProcessPath);
                tmpstr = String_ToUtf8(tmpstr);
                j["win_sysmonitor_inject_dstPath"] = tmpstr.c_str();
            }
            break;
            }

            // 注: Topic 释放 Pub的数据指针
            if (pubNode)
            {
                delete[] pubNode;
                pubNode = nullptr;
            }

            // 序列化
            std::shared_ptr<std::string> data = nullptr;
            if (j.size())
                data = std::make_shared<std::string>(j.dump());
            else
            {
                j.clear();
                tmpstr.clear();
                continue;
            }

            if (!g_SendQueueData_Ptr && !g_SendQueueCs_Ptr && !g_SendQueue_Event)
            {
                OutputDebugString(L"Grpc没设置订阅指针");
                return;
            }

            const std::shared_ptr<USubNode> sub = std::make_shared<USubNode>();
            if (!sub || !data)
                return;
            sub->data = data;
            sub->taskid = taskid;
            {
                std::unique_lock<std::mutex> lock_(*g_SendQueueCs_Ptr);
                g_SendQueueData_Ptr->push(sub);
                SetEvent(g_SendQueue_Event);
            }
            j.clear();
            tmpstr.clear();
            data = nullptr;
        }
    }
    catch (const std::exception&)
    {
    }
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
    if (!pData)
        return 0;
    (reinterpret_cast<kMsgInterface*>(pData))->kMsg_taskPopNotifyRoutineLoop();
    return 0;
}
void kMsgInterface::kMsg_taskPopInit()
{
    size_t i = 0;
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
    size_t i = 0, index = 0;
    DWORD dwAllocateMemSize = 0;
    char* ptr_Getbuffer = nullptr;
    bool nstatus = Choose_mem(ptr_Getbuffer, dwAllocateMemSize, taskcode);
    if (false == nstatus || nullptr == ptr_Getbuffer || dwAllocateMemSize == 0)
        return;

    json_t j;
    switch (taskcode)
    {
    case NF_SSDT_ID:
    {
        if (SingletonKSSdt::instance()->nf_init())
        {
            if (false == SingletonKSSdt::instance()->nf_GetSysCurrentSsdtData((LPVOID)ptr_Getbuffer, dwAllocateMemSize))
                break;
            const SSDTINFO* pSSdtInfo = (SSDTINFO*)ptr_Getbuffer;
            if (!pSSdtInfo)
                break;

            for (i = 0; i < 0x200; ++i)
            {
                if (!pSSdtInfo[i].sstd_memoffset)
                    continue;
                j["win_rootkit_ssdt_id"] = to_string(pSSdtInfo[i].ssdt_id).c_str();
                j["win_rootkit_ssdt_offsetaddr"] = to_string(pSSdtInfo[i].sstd_memoffset).c_str();
                vec_task_string.push_back(j.dump());
            }
            OutputDebugString(L"Task Get SSDT Data Pkg Success");
        }
    }
    break;
    case NF_IDT_ID:
    {
        if (SingletonKIdt::instance()->nf_init())
        {
            if (!SingletonKIdt::instance()->nf_GetIdtData((LPVOID)ptr_Getbuffer, dwAllocateMemSize))
                break;
            const IDTINFO* pIdtInfo = (IDTINFO*)ptr_Getbuffer;
            if (!pIdtInfo)
                break;

            for (i = 0; i < 0x100; ++i)
            {
                if (!pIdtInfo[i].idt_isrmemaddr)
                    continue;
                j["win_rootkit_idt_id"] = to_string(pIdtInfo[i].idt_id).c_str();
                j["win_rootkit_idt_offsetaddr"] = to_string(pIdtInfo[i].idt_isrmemaddr).c_str();
                vec_task_string.push_back(j.dump());
            }
            OutputDebugString(L"Task Get IDT Data Pkg Success");
        }
    }
    break;
    case NF_DPC_ID:
    {
        if (false == SingletonKDpcTimer::instance()->nf_GetDpcTimerData((LPVOID)ptr_Getbuffer, dwAllocateMemSize))
            break;
        const DPC_TIMERINFO* pDpcInfo = (DPC_TIMERINFO*)ptr_Getbuffer;
        if (!pDpcInfo)
            break;

        for (i = 0; i < 0x100; ++i)
        {
            if (!pDpcInfo[i].dpc)
                continue;
            j["win_rootkit_dpc"] = to_string(pDpcInfo[i].dpc).c_str();
            j["win_rootkit_dpc_timeobj"] = to_string(pDpcInfo[i].timeroutine).c_str();
            j["win_rootkit_dpc_timeroutine"] = to_string(pDpcInfo[i].timeroutine).c_str();
            j["win_rootkit_dpc_periodtime"] = to_string(pDpcInfo[i].period).c_str();
            vec_task_string.push_back(j.dump());
        }
        OutputDebugString(L"Task Get Dpc Data Pkg Success");
    }
    break;
    case NF_FSD_ID:
    {
        if (false == SingletonKFsd::instance()->nf_GetFsdInfo(ptr_Getbuffer, dwAllocateMemSize))
            break;

        const ULONGLONG* pFsdMJAddrList = (ULONGLONG*)ptr_Getbuffer;
        if (!pFsdMJAddrList)
            break;

        j["win_rootkit_is_fsdmod"] = "1";
        for (i = 0; i < 0x1b; ++i)
        {
            j["win_rootkit_fsdfastfat_id"] = to_string(pFsdMJAddrList[index]).c_str();
            j["win_rootkit_fsdfastfat_mjaddr"] = to_string(pFsdMJAddrList[index]).c_str();
            vec_task_string.push_back(j.dump());
            index++;
        }
        OutputDebugString(L"Task Get FastFat MjFuction Data Pkg Success");

        j.clear();
        j["win_rootkit_is_fsdmod"] = "2";
        for (i = 0; i < 0x1b; ++i)
        {
            j["win_rootkit_fsdntfs_id"] = to_string(pFsdMJAddrList[index]).c_str();
            j["win_rootkit_fsdntfs_mjaddr"] = to_string(pFsdMJAddrList[index]).c_str();
            vec_task_string.push_back(j.dump());
            index++;
        }
        OutputDebugString(L"Task Get Ntfs MjFuction Data Pkg Success");
    }
    break;
    case NF_SYSCALLBACK_ID:
    {
    }
    break;
    case NF_MOUSEKEYBOARD_ID:
    {
        if (false == SingletonKMouseKeyBoard::instance()->nf_GetMouseKeyInfoData(ptr_Getbuffer, dwAllocateMemSize))
            break;

        const ULONGLONG* pMousKeyMJAddrList = (ULONGLONG*)ptr_Getbuffer;
        if (!pMousKeyMJAddrList)
            break;

        j["win_rootkit_is_mousekeymod"] = "1";
        for (i = 0; i < 0x1b; ++i)
        {
            j["win_rootkit_Mouse_id"] = to_string(pMousKeyMJAddrList[index]).c_str();
            j["win_rootkit_Mouse_mjaddr"] = to_string(pMousKeyMJAddrList[index]).c_str();
            vec_task_string.push_back(j.dump());
            index++;
        }
        OutputDebugString(L"Task Get Mouse MjFuction Data Pkg Success");

        j.clear();
        j["win_rootkit_is_mousekeymod"] = "2";
        for (i = 0; i < 0x1b; ++i)
        {
            j["win_rootkit_i8042_id"] = to_string(pMousKeyMJAddrList[index]).c_str();
            j["win_rootkit_i8042_mjaddr"] = to_string(pMousKeyMJAddrList[index]).c_str();
            vec_task_string.push_back(j.dump());
            index++;
        }
        OutputDebugString(L"Task Get i8042 MjFuction Data Pkg Success");

        j.clear();
        j["win_rootkit_is_mousekeymod"] = "3";
        for (i = 0; i < 0x1b; ++i)
        {
            j["win_rootkit_kbd_id"] = to_string(pMousKeyMJAddrList[index]).c_str();
            j["win_rootkit_kbd_mjaddr"] = to_string(pMousKeyMJAddrList[index]).c_str();
            vec_task_string.push_back(j.dump());
            index++;
        }
        OutputDebugString(L"Task Get kbd MjFuction Data Pkg Success");
    }
    break;
    case NF_NETWORK_ID:
    {
        if (false == SingletonKNetWork::instance()->nf_GetNteworkProcessInfo(ptr_Getbuffer, dwAllocateMemSize))
            break;

        const PSYSNETWORKINFONODE pNetworkInfo = (PSYSNETWORKINFONODE)ptr_Getbuffer;
        if (!pNetworkInfo)
            break;

        // Tcp
        j["win_rootkit_is_mod"] = "1";
        for (i = 0; i < pNetworkInfo->tcpcout; ++i)
        {
            j["win_rootkit_tcp_pid"] = to_string(pNetworkInfo->systcpinfo[i].processinfo.dwTcpProId).c_str();
            j["win_rootkit_tcp_localIp_port"] = to_string(pNetworkInfo->systcpinfo[i].TpcTable.localEntry.dwIP).c_str();
            j["win_rootkit_tcp_remoteIp_port"] = to_string(pNetworkInfo->systcpinfo[i].TpcTable.remoteEntry.dwIP).c_str();
            j["win_rootkit_tcp_Status"] = to_string(pNetworkInfo->systcpinfo[i].socketStatus.dwState).c_str();
            vec_task_string.push_back(j.dump());
        }
        OutputDebugString(L"Task Get NetWork Tcp Data Pkg Success");

        j.clear();
        j["win_rootkit_is_mod"] = "2";
        std::string udpipport;
        for (i = 0; i < pNetworkInfo->udpcout; ++i)
        {
            udpipport = to_string(pNetworkInfo->sysudpinfo[i].UdpTable.dwIP) + ":" + to_string(ntohs(pNetworkInfo->sysudpinfo[i].UdpTable.Port));
            j["win_rootkit_udp_pid"] = to_string(pNetworkInfo->sysudpinfo[i].processinfo.dwUdpProId).c_str();
            j["win_rootkit_udp_localIp_port"] = udpipport.c_str();
            vec_task_string.push_back(j.dump());
        }
        OutputDebugString(L"Task Get NetWork Udp Data Pkg Success");
    }
    break;
    case NF_PROCESS_ENUM:
    {
        if (false == SingletonKProcessInfo::instance()->nf_EnumProcess(ptr_Getbuffer, dwAllocateMemSize))
            break;

        const PHANDLE_INFO pPhandleInfo = (PHANDLE_INFO)ptr_Getbuffer;
        if (pPhandleInfo && pPhandleInfo[0].CountNum)
        {

            for (i = 0; i < pPhandleInfo[0].CountNum; ++i)
            {
                //wcout << "Pid: " << phandleinfo[i].ProcessId << " - Process: " << phandleinfo[i].ProcessPath << endl;// " - ProcessName: " << phandleinfo[i].ProcessName << endl;
                // 去重
                catstr = pPhandleInfo[i].ProcessPath;
                catstr += L" - ";
                catstr += pPhandleInfo[i].ProcessName;
                Process_list[pPhandleInfo[i].ProcessId] = catstr;
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

            OutputDebugString(L"Task Get Process to Server Data Pkg Success");
        }
    }
    break;
    case NF_PROCESS_MOD:
    {
        int Process_Pid = 4;
        cout << "Test Input Pid: 4";
        // 默认测试
        if (false == SingletonKProcessInfo::instance()->nf_GetProcessMod(Process_Pid, ptr_Getbuffer, dwAllocateMemSize))
            break;

        const PPROCESS_MOD pProcMod = (PPROCESS_MOD)ptr_Getbuffer;
        if (pProcMod)
        {
            j["win_rootkit_processmod_pid"] = to_string(Process_Pid).c_str();
            for (i = 0; i < 1024 * 2; ++i)
            {
                if ((0 == pProcMod[i].EntryPoint) && (0 == pProcMod[i].SizeOfImage) && (0 == pProcMod[i].DllBase))
                    continue;
                j["win_rootkit_process_DllBase"] = to_string(pProcMod[i].DllBase).c_str();
                j["win_rootkit_process_SizeofImage"] = to_string(pProcMod[i].SizeOfImage).c_str();
                j["win_rootkit_process_EntryPoint"] = to_string(pProcMod[i].EntryPoint).c_str();
                tmpstr.clear();
                Wchar_tToString(tmpstr, pProcMod[i].BaseDllName);
                tmpstr = String_ToUtf8(tmpstr);
                j["win_rootkit_process_BaseDllName"] = tmpstr.c_str();
                tmpstr.clear();
                Wchar_tToString(tmpstr, pProcMod[i].FullDllName);
                tmpstr = String_ToUtf8(tmpstr);
                j["win_rootkit_process_FullDllName"] = tmpstr.c_str();
                vec_task_string.push_back(j.dump());
            }
        }
        OutputDebugString(L"Task Get Process Mod Data Pkg Success");
    }
    break;
    case NF_PROCESS_KILL:
    {
         SingletonKProcessInfo::instance()->nf_KillProcess();
    }
    break;
    case NF_SYSMOD_ENUM:
    {
        if (false == SingletonKSysDriverDevInfo::instance()->nf_EnumSysMod(ptr_Getbuffer, dwAllocateMemSize))
            break;

        const PPROCESS_MOD pProcMod = (PPROCESS_MOD)ptr_Getbuffer;
        if (pProcMod)
        {
            for (i = 0; i < 1024 * 2; ++i)
            {
                // Bug
                if ((0 == pProcMod[i].EntryPoint) && (0 == pProcMod[i].SizeOfImage) && (0 == pProcMod[i].DllBase))
                    continue;
                j["win_rootkit_sys_DllBase"] = to_string(pProcMod[i].DllBase).c_str();
                j["win_rootkit_sys_SizeofImage"] = to_string(pProcMod[i].SizeOfImage).c_str();
                j["win_rootkit_sys_EntryPoint"] = to_string(pProcMod[i].EntryPoint).c_str();
                tmpstr.clear();
                Wchar_tToString(tmpstr, pProcMod[i].BaseDllName);
                tmpstr = String_ToUtf8(tmpstr);
                j["win_rootkit_sys_BaseDllName"] = tmpstr.c_str();
                tmpstr.clear();
                Wchar_tToString(tmpstr, pProcMod[i].FullDllName);
                tmpstr = String_ToUtf8(tmpstr);
                j["win_rootkit_sys_FullDllName"] = tmpstr.c_str();
                vec_task_string.push_back(j.dump());
            }
        }
        OutputDebugString(L"Task Get SystemDriver Enum Data Pkg Success");
    }
    break;

    default:
        break;
    }

    if (ptr_Getbuffer)
    {
        delete[] ptr_Getbuffer;
        ptr_Getbuffer = nullptr;
    }
}

void kMsgInterface::DriverInit(const int flag)
{
    int status = 0;

    // Init devctrl
    status = SingletonKDrvManage::instance()->devctrl_init();
    if (0 > status)
    {
        OutputDebugString(L"devctrl_init error: main.c --> lines: 678");
        return;
    }

    do
    {
        // Open driver
        status = SingletonKDrvManage::instance()->devctrl_opendeviceSylink(devSyLinkName);
        if (0 >= status)
        {
            OutputDebugString(L"devctrl_opendeviceSylink error: main.c --> lines: 688");
            break;
        }

        // Init share Mem
        status = SingletonKDrvManage::instance()->devctrl_InitshareMem();
        if (0 >= status)
        {
            OutputDebugString(L"devctrl_InitshareMem error: main.c --> lines: 690");
            break;
        }

        // Set Ips Process
        unsigned int dwMods = 0; std::string strProcessName;
        if (ConfigProcessJsonRuleParsing(dwMods, strProcessName) && !strProcessName.empty())
        {
            strProcessName.append("||");
            const std::wstring IpsProcessName = Str2WStr(strProcessName);
            OutputDebugString((L"[HadesSvc] devctrl_SetIpsProcessNameList: " + IpsProcessName).c_str());
            status = SingletonKDrvManage::instance()->devctrl_SetIpsProcessNameList(CTL_DEVCTRL_IPS_SETPROCESSNAME, IpsProcessName.c_str());
            OutputDebugString(L"[HadesSvc] devctrl_SetIpsProcessNameList Success");
            if (status)
            {
                status = SingletonKDrvManage::instance()->devctrl_SetIpsFilterMods(CTL_DEVCTRL_IPS_SETPROCESSFILTERMOD, dwMods);
                if(status)
                    OutputDebugString(L"[HadesSvc] Register devctrl_SetIpsMods");
                else
                    OutputDebugString(L"[HadesSvc] Register devctrl_SetIpsMods");
            }
            else
                OutputDebugString(L"[HadesSvc] Process devctrl_SetIpsProcessNameList");
        }

        // Set Ips Register
        std::string registerProcName;
        if (ConfigRegisterJsonRuleParsing(registerProcName))
        {
            registerProcName.append("||");
            const std::wstring IpsRegisterName = Str2WStr(registerProcName);
            OutputDebugString((L"[HadesSvc] devctrl_SetIpsProcessNameList: " + IpsRegisterName).c_str());
            status = SingletonKDrvManage::instance()->devctrl_SetIpsProcessNameList(CTL_DEVCTRL_IPS_SETREGISTERNAME, IpsRegisterName.c_str());
            OutputDebugString(L"[HadesSvc] devctrl_SetIpsProcessNameList Success");
            if (status)
                OutputDebugString(L"[HadesSvc] Register devctrl_SetIpsProcessNameList Success");
            else
                OutputDebugString(L"[HadesSvc] Register devctrl_SetIpsProcessNameList Fauiler");
        }

        // Set Ips Directory
        std::string whiteName, blackName, whiteDirectory, blackDirectory;
        if (ConfigDirectoryJsonRuleParsing(whiteName, blackName, whiteDirectory, blackDirectory))
        {
            whiteName.append("||"); blackName.append("||"); whiteDirectory.append("||"); blackDirectory.append("||");
            const std::wstring IpsDirWhiterName = Str2WStr(whiteName);
            const std::wstring IpsDirBlackName = Str2WStr(blackName);
            const std::wstring IpsDirWhiteDirPath = Str2WStr(whiteDirectory);
            const std::wstring IpsDirBlackDirPat = Str2WStr(blackDirectory);

            if (!IpsDirWhiterName.empty() && !IpsDirWhiteDirPath.empty())
            {
                OutputDebugString((L"[HadesSvc] devctrl_SetIpswhiteNameList: " + IpsDirWhiterName).c_str());
                status = SingletonKDrvManage::instance()->devctrl_SetIpsProcessNameList(CTL_DEVCTRL_IPS_SETDIRECTORYRULE, IpsDirWhiterName.c_str());
                OutputDebugString(L"[HadesSvc] devctrl_SetIpsProcessNameList Success");

                OutputDebugString((L"[HadesSvc] devctrl_SetIpswhiteDirectoryList: " + IpsDirWhiteDirPath).c_str());
                status = SingletonKDrvManage::instance()->devctrl_SetIpsProcessNameList(CTL_DEVCTRL_IPS_SETDIRECTORYRULE, IpsDirWhiteDirPath.c_str());
                OutputDebugString(L"[HadesSvc] devctrl_SetIpswhiteDirectoryList Success");
            }
            if (!IpsDirBlackName.empty() && !IpsDirBlackDirPat.empty())
            {
                OutputDebugString((L"[HadesSvc] devctrl_SetIpsblackNameList: " + IpsDirBlackName).c_str());
                status = SingletonKDrvManage::instance()->devctrl_SetIpsProcessNameList(CTL_DEVCTRL_IPS_SETDIRECTORYRULE, IpsDirBlackName.c_str());
                OutputDebugString(L"[HadesSvc] devctrl_SetIpsblackNameList Success");

                OutputDebugString((L"[HadesSvc] devctrl_SetIpsblackDirectoryList: " + IpsDirBlackDirPat).c_str());
                status = SingletonKDrvManage::instance()->devctrl_SetIpsProcessNameList(CTL_DEVCTRL_IPS_SETDIRECTORYRULE, IpsDirBlackDirPat.c_str());
                OutputDebugString(L"[HadesSvc] devctrl_SetIpsblackDirectoryList Success");
            }

            if (status)
                OutputDebugString(L"[HadesSvc] Directory devctrl_SetIpsDirectpry Success");
            else
                OutputDebugString(L"[HadesSvc] Directory devctrl_SetIpsDirectpry Fauiler");
        }

        // Set Ips InjectIpsProcessName
        std::string threadInjectProcName;
        if (ConfigThreadJsonRuleParsing(threadInjectProcName))
        {
            threadInjectProcName.append("||");
            const std::wstring IpsThreadName = Str2WStr(threadInjectProcName);
            OutputDebugString((L"[HadesSvc] devctrl_SetIpsProcessNameList: " + IpsThreadName).c_str());
            status = SingletonKDrvManage::instance()->devctrl_SetIpsProcessNameList(CTL_DEVCTRL_IPS_SETTHREADINJECTNAME, IpsThreadName.c_str());
            OutputDebugString(L"[HadesSvc] devctrl_SetIpsProcessNameList Success");
            if (status)
                OutputDebugString(L"[HadesSvc] ThreadInejctProc devctrl_SetIpsProcessNameList Success");
            else
                OutputDebugString(L"[HadesSvc] ThreadInejctProc devctrl_SetIpsProcessNameList Fauiler");
        }

        // Enable Event --> 内核提取出来数据以后处理类
        //SingletonKDrvManage::instance()->nf_setEventHandler((PVOID)&eventobj);

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
    SingletonKDrvManage::instance()->devctrl_free();
    kInitStatus = false;
}

// 读线程
void kMsgInterface::StopReadFileThread()
{
    SingletonKDrvManage::instance()->devctrl_stopthread();
}
void kMsgInterface::StartReadFileThread()
{
    SingletonKDrvManage::instance()->devctrl_startthread();
}

void kMsgInterface::OnMonitor()
{
    int status = 0;
    status = SingletonKDrvManage::instance()->devctrl_OnMonitor();
    if (0 > status)
    {
        cout << "OnMonitor error kmsginterface" << endl;
    }
    kerMonStatus = true;
    return;
}
void kMsgInterface::OffMonitor()
{
    int status = 0;
    status = SingletonKDrvManage::instance()->devctrl_OffMonitor();
    Sleep(100);
    if (0 > status)
    {
        cout << "OffMonitor error kmsginterface" << endl;
    }
    kerMonStatus = false;
    return;
    
}
void kMsgInterface::OnBeSnipingMonitor()
{
    int status = 0;
    status = SingletonKDrvManage::instance()->devctrl_OnIpsMonitor();
    Sleep(100);
    if (0 > status)
    {
        cout << "OnBeSnipingMonitor error kmsginterface" << endl;
    }
    kBesnipingStatus = true;
}
void kMsgInterface::OffBeSnipingMonitor()
{
    int status = 0;
    status = SingletonKDrvManage::instance()->devctrl_OffIpsMonitor();
    Sleep(100);
    if (0 > status)
    {
        cout << "OffBeSnipingMonitor error kmsginterface" << endl;
    }
    kBesnipingStatus = false;
}

// 引擎态
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

// 规则
bool kMsgInterface::ReLoadProcessRuleConfig()
{
    int status = 0;
    unsigned int dwMods = 0; std::string strProcessName;
    if (ConfigProcessJsonRuleParsing(dwMods, strProcessName) && !strProcessName.empty())
    {
        strProcessName.append("||");
        const std::wstring IpsProcessName = Str2WStr(strProcessName);
        if (!IpsProcessName.empty())
            status = SingletonKDrvManage::instance()->devctrl_SetIpsProcessNameList(CTL_DEVCTRL_IPS_SETPROCESSNAME, IpsProcessName.c_str());
        if (0 >= status)
        {
            OutputDebugString(L"[HadesSvc] Process devctrl_SetIpsProcessNameList");
            return false;
        }
        if (dwMods)
            status = SingletonKDrvManage::instance()->devctrl_SetIpsFilterMods(CTL_DEVCTRL_IPS_SETPROCESSFILTERMOD, dwMods);
        if (0 >= status)
        {
            OutputDebugString(L"[HadesSvc] Register devctrl_SetIpsMods");
            return false;
        }
        return true;
    }
    return false;
}
bool kMsgInterface::ReLoadRegisterRuleConfig()
{
    std::string registerProcName;
    if (ConfigRegisterJsonRuleParsing(registerProcName))
    {
        registerProcName.append("|");
        const std::wstring IpsRegisterName = Str2WStr(registerProcName);
        int status = 0;
        if (!IpsRegisterName.empty())
            status = SingletonKDrvManage::instance()->devctrl_SetIpsProcessNameList(CTL_DEVCTRL_IPS_SETREGISTERNAME, IpsRegisterName.c_str());
        if (0 >= status)
        {
            OutputDebugString(L"[HadesSvc] Register devctrl_SetIpsProcessNameList");
            return false;
        }
        return true;
    }
    return false;
}
bool kMsgInterface::ReLoadDirectoryRuleConfig()
{
    std::string whiteName, blackName, whiteDirectory, blackDirectory;
    if (ConfigDirectoryJsonRuleParsing(whiteName, blackName, whiteDirectory, blackDirectory))
    {
        whiteName.append("||"); blackName.append("||"); whiteDirectory.append("|"); blackDirectory.append("|");
        const std::wstring IpsDirWhiterName = Str2WStr(whiteName);
        const std::wstring IpsDirBlackName = Str2WStr(blackName);
        const std::wstring IpsDirWhiteDirPath = Str2WStr(whiteDirectory);
        const std::wstring IpsDirBlackDirPat = Str2WStr(blackDirectory);

        int status = 0;
        if (!IpsDirWhiterName.empty() && !IpsDirWhiteDirPath.empty())
        {
            OutputDebugString((L"[HadesSvc] devctrl_SetIpswhiteNameList: " + IpsDirWhiterName).c_str());
            status = SingletonKDrvManage::instance()->devctrl_SetIpsProcessNameList(CTL_DEVCTRL_IPS_SETDIRECTORYRULE, IpsDirWhiterName.c_str());
            OutputDebugString(L"[HadesSvc] devctrl_SetIpsProcessNameList Success");

            OutputDebugString((L"[HadesSvc] devctrl_SetIpswhiteDirectoryList: " + IpsDirWhiteDirPath).c_str());
            status = SingletonKDrvManage::instance()->devctrl_SetIpsProcessNameList(CTL_DEVCTRL_IPS_SETDIRECTORYRULE, IpsDirWhiteDirPath.c_str());
            OutputDebugString(L"[HadesSvc] devctrl_SetIpswhiteDirectoryList Success");
        }
        if (!IpsDirBlackName.empty() && !IpsDirBlackDirPat.empty())
        {
            OutputDebugString((L"[HadesSvc] devctrl_SetIpsblackNameList: " + IpsDirBlackName).c_str());
            status = SingletonKDrvManage::instance()->devctrl_SetIpsProcessNameList(CTL_DEVCTRL_IPS_SETDIRECTORYRULE, IpsDirBlackName.c_str());
            OutputDebugString(L"[HadesSvc] devctrl_SetIpsblackNameList Success");

            OutputDebugString((L"[HadesSvc] devctrl_SetIpsblackDirectoryList: " + IpsDirBlackDirPat).c_str());
            status = SingletonKDrvManage::instance()->devctrl_SetIpsProcessNameList(CTL_DEVCTRL_IPS_SETDIRECTORYRULE, IpsDirBlackDirPat.c_str());
            OutputDebugString(L"[HadesSvc] devctrl_SetIpsblackDirectoryList Success");
        }

        if (status)
            OutputDebugString(L"[HadesSvc] Directory devctrl_SetIpsDirectpry Success");
        else
            OutputDebugString(L"[HadesSvc] Directory devctrl_SetIpsDirectpry Fauiler");
        return true;
    }
    return false;
}
bool kMsgInterface::ReLoadThreadInjectRuleConfig()
{
    std::string threadInjectProcName;
    if (ConfigThreadJsonRuleParsing(threadInjectProcName))
    {
        threadInjectProcName.append("||");
        const std::wstring IpsThreadName = Str2WStr(threadInjectProcName);
        OutputDebugString((L"[HadesSvc] devctrl_SetIpsProcessNameList: " + IpsThreadName).c_str());
        const int status = SingletonKDrvManage::instance()->devctrl_SetIpsProcessNameList(CTL_DEVCTRL_IPS_SETTHREADINJECTNAME, IpsThreadName.c_str());
        OutputDebugString(L"[HadesSvc] devctrl_SetIpsProcessNameList Success");
        if (status)
            OutputDebugString(L"[HadesSvc] ThreadInejctProc devctrl_SetIpsProcessNameList Success");
        else
            OutputDebugString(L"[HadesSvc] ThreadInejctProc devctrl_SetIpsProcessNameList Fauiler");
        return true;
    }
    return false;
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

    // clear new memeory
    std::unique_lock<std::mutex> lock(g_RecvDataQueueCs);
    while (!g_RecvDataQueue.empty())
    {
        auto pKerTaskData = g_RecvDataQueue.front();
        g_RecvDataQueue.pop();
        if (pKerTaskData)
        {
            delete[] pKerTaskData;
            pKerTaskData = nullptr;
        }
    }
}