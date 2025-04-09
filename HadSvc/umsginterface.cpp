/*
* Topic Class
* Mod: Sub <--> Topic <--> Pub
    uMsginterface.cpp����SysMonUserLib��˵��������,����Grpc����Iocp���ϱ��ӿ���˵�������ߡ�
    �������·���Grpc --> ����taskId --> uMsginterface�·� --> SysMonUserLib(��������)
    ������������Grpc <-- ��ɷ���  <--  uMsginterface��ȡ/��� <-- SysMonUserLib(��������)
ע: ΪʲôACK���̲�����ʹ������ָ�룿
    Pub��Ϣ����ȷ�����Ľ�����Ϣ����,������(Pub)�ͷ�,�����ط���Ϣ��
    ����ָ��Ҳ���Ա����ò��ͷ�,���Ƿ�ֹ�����ܵ��������,����Լ�����
���ԭ��
    Pub to Topic �Լ�����ָ��
    Topic to Sub ����ָ��
���Ż�
    1.����ж������,�����Զ�����Topic�����������ָ��.
    2.Topic���������������Ч��,û��ACK����,Pub��������Sub,������Topic����Sub�Ƿ������õ���������,Sub��������Topic.
*/
#include "msgassist.h"
#include "umsginterface.h"

#include "uinterface.h"

//rapidjson
#include <rapidjson/rapidjson.h>
#include <rapidjson/document.h>
#include <rapidjson/stringbuffer.h>
#include <rapidjson/writer.h>

//nlohmannjson
#include <json.hpp>
using json_t = nlohmann::json;

#include <io.h>

// Topic�������ָ��1
static std::mutex               g_RecvQueueCs;
static std::queue<UPubNode*>    g_RecvQueueData;
static HANDLE                   g_jobAvailableEvent;
static bool                     g_exit = false;
// Topic�������ָ��1����,����Etw����������
inline void uMsgInterface::uMsg_SetTopicQueuePtr() { SingletonUEtw::instance()->uf_setqueuetaskptr(g_RecvQueueData); }
inline void uMsgInterface::uMsg_SetTopicQueueLockPtr() { SingletonUEtw::instance()->uf_setqueuelockptr(g_RecvQueueCs); }
inline void uMsgInterface::uMsg_SetTopicEventPtr() { SingletonUEtw::instance()->uf_setqueueeventptr(g_jobAvailableEvent); }

// ����������ָ��(�������ߵ���)
static std::queue<std::shared_ptr<USubNode>>*       g_SendQueueData_Ptr = NULL;
static std::mutex*                                  g_SendQueueCs_Ptr = NULL;
static HANDLE                                       g_SendQueue_Event = NULL;
void uMsgInterface::uMsg_SetSubQueuePtr(std::queue<std::shared_ptr<USubNode>>& qptr) { g_SendQueueData_Ptr = &qptr; }
void uMsgInterface::uMsg_SetSubQueueLockPtr(std::mutex& qptrcs) { g_SendQueueCs_Ptr = &qptrcs; }
void uMsgInterface::uMsg_SetSubEventPtr(HANDLE& eventptr) { g_SendQueue_Event = eventptr; }
const int EtwSubLens = sizeof(USubNode);

uMsgInterface::uMsgInterface()
{
}

uMsgInterface::~uMsgInterface()
{
}

// Topic���ݴ�������ͷ���Sub
void uMsgInterface::uMsgEtwDataHandlerEx()
{
    std::unique_lock<std::mutex> lock(g_RecvQueueCs);
    
    try
    {
        json_t j;
        std::string tmpstr = "";
        UPubNode* pEtwTaskData = nullptr;

        for (;;)
        {
            if (g_RecvQueueData.empty())
                return;

            pEtwTaskData = g_RecvQueueData.front();
            g_RecvQueueData.pop();
            if (!pEtwTaskData)
                return;

            const int taskid = pEtwTaskData->taskid;
            switch (taskid)
            {
            case UF_ETW_NETWORK:
            {
                const UEtwNetWork* pEtwNet = (UEtwNetWork*)&(pEtwTaskData->data[0]);
                if (!pEtwNet)
                    break;
                Wchar_tToString(tmpstr, pEtwNet->EventName);
                if (!tmpstr.empty())
                {
                    tmpstr = String_ToUtf8(tmpstr);
                    j["win_network_eventname"] = tmpstr.c_str();
                }
                else
                {
                    j["win_network_eventname"] = "";
                }
                j["win_network_addressfamily"] = to_string(pEtwNet->addressFamily);
                j["win_network_protocol"] = to_string(pEtwNet->protocol);
                j["win_network_processid"] = to_string(pEtwNet->processId);
                j["win_network_localaddr"] = to_string(pEtwNet->ipv4LocalAddr);
                j["win_network_toLocalport"] = to_string(pEtwNet->protocol);
                j["win_network_remoteaddr"] = to_string(pEtwNet->ipv4toRemoteAddr);
                j["win_network_toremoteport"] = to_string(pEtwNet->toRemotePort);
            }
            break;
            case UF_ETW_PROCESSINFO:
            {
                const UEtwProcessInfo* pEtwProcess = (UEtwProcessInfo*)&(pEtwTaskData->data[0]);
                if (!pEtwProcess)
                    break;
                Wchar_tToString(tmpstr, pEtwProcess->EventName);
                if (!tmpstr.empty())
                {
                    tmpstr = String_ToUtf8(tmpstr);
                    j["win_etw_processinfo_eventname"] = tmpstr.c_str();
                }
                else
                {
                    j["win_etw_processinfo_eventname"] = "";
                }
                j["win_etw_processinfo_parentid"] = to_string(pEtwProcess->parentId);
                j["win_etw_processinfo_pid"] = to_string(pEtwProcess->processId);
                j["win_etw_processinfo_status"] = to_string(pEtwProcess->processStatus);
                Wchar_tToString(tmpstr, pEtwProcess->processPath);
                if (!tmpstr.empty())
                {
                    tmpstr = String_ToUtf8(tmpstr);
                    j["win_etw_processinfo_path"] = tmpstr.c_str();
                }
                else
                    j["win_etw_processinfo_path"] = "";
            }
            break;
            case UF_ETW_THREADINFO:
            {
                const UEtwThreadInfo* pEtwThread = (UEtwThreadInfo*)&(pEtwTaskData->data[0]);
                if (!pEtwThread)
                    break;
                Wchar_tToString(tmpstr, pEtwThread->EventName);
                if (!tmpstr.empty())
                {
                    tmpstr = String_ToUtf8(tmpstr);
                    j["win_etw_threadinfo_eventname"] = tmpstr.c_str();
                }
                else
                {
                    j["win_etw_threadinfo_eventname"] = "";
                }
                j["win_etw_threadinfo_pid"] = to_string(pEtwThread->processId);
                j["win_etw_threadinfo_tid"] = to_string(pEtwThread->threadId);
                j["win_etw_threadinfo_win32startaddr"] = to_string(pEtwThread->Win32StartAddr);
                j["win_etw_threadinfo_flags"] = to_string(pEtwThread->ThreadFlags);
            }
            break;
            case UF_ETW_IMAGEMOD:
            {
                const UEtwImageInfo* pEtwProcMod = (UEtwImageInfo*)&(pEtwTaskData->data[0]);
                if (!pEtwProcMod)
                    break;
                Wchar_tToString(tmpstr, pEtwProcMod->EventName);
                if (!tmpstr.empty())
                {
                    tmpstr = String_ToUtf8(tmpstr);
                    j["win_etw_imageinfo_eventname"] = tmpstr.c_str();
                }
                else
                {
                    j["win_etw_imageinfo_eventname"] = "";
                }
                j["win_etw_imageinfo_processId"] = to_string(pEtwProcMod->ProcessId);
                j["win_etw_imageinfo_imageBase"] = to_string(pEtwProcMod->ImageBase);
                j["win_etw_imageinfo_imageSize"] = to_string(pEtwProcMod->ImageSize);
                j["win_etw_imageinfo_signatureLevel"] = to_string(pEtwProcMod->SignatureLevel);
                j["win_etw_imageinfo_signatureType"] = to_string(pEtwProcMod->SignatureType);
                j["win_etw_imageinfo_imageChecksum"] = to_string(pEtwProcMod->ImageChecksum);
                j["win_etw_imageinfo_timeDateStamp"] = to_string(123);
                j["win_etw_imageinfo_defaultBase"] = to_string(pEtwProcMod->DefaultBase);
                Wchar_tToString(tmpstr, pEtwProcMod->FileName);
                if (tmpstr.empty())
                    break;
                tmpstr = String_ToUtf8(tmpstr);
                j["win_etw_imageinfo_fileName"] = tmpstr.c_str();
            }
            break;
            case UF_ETW_REGISTERTAB:
            {
                const UEtwRegisterTabInfo* pEtwRegtab = (UEtwRegisterTabInfo*)&(pEtwTaskData->data[0]);
                if (!pEtwRegtab)
                    break;
                Wchar_tToString(tmpstr, pEtwRegtab->EventName);
                if (!tmpstr.empty())
                {
                    tmpstr = String_ToUtf8(tmpstr);
                    j["win_etw_regtab_eventname"] = tmpstr.c_str();
                }
                else
                {
                    j["win_etw_regtab_eventname"] = "";
                }
                j["win_etw_regtab_status"] = to_string(pEtwRegtab->Status);
                j["win_etw_regtab_index"] = to_string(pEtwRegtab->Index);
                j["win_etw_regtab_keyHandle"] = to_string(pEtwRegtab->KeyHandle);
                Wchar_tToString(tmpstr, pEtwRegtab->KeyName);
                tmpstr = String_ToUtf8(tmpstr);
                j["win_etw_regtab_keyName"] = tmpstr.c_str();
            }
            break;
            case UF_ETW_FILEIO:
            {
                const UEtwFileIoTabInfo* pEtwFileIo = (UEtwFileIoTabInfo*)&(pEtwTaskData->data[0]);
                if (!pEtwFileIo)
                    break;
                Wchar_tToString(tmpstr, pEtwFileIo->EventName);
                if (!tmpstr.empty())
                {
                    tmpstr = String_ToUtf8(tmpstr);
                    j["win_etw_fileio_eventname"] = tmpstr.c_str();
                }
                else
                {
                    j["win_etw_fileio_eventname"] = "";
                }

                // ���ﲻ����EventName������ Empty�¼���ͬ�յ�Ƶ�ʸ� 
                int lens = lstrlenW(pEtwFileIo->FilePath);
                if (lens > 0)
                {
                    Wchar_tToString(tmpstr, pEtwFileIo->FilePath);
                    if (!tmpstr.empty())
                    {
                        tmpstr = String_ToUtf8(tmpstr);
                        j["win_etw_fileio_FilePath"] = tmpstr.c_str();
                    }
                    else
                    {
                        j["win_etw_fileio_FilePath"] = "";
                    }
                }

                lens = lstrlenW(pEtwFileIo->FileName);
                if (lens > 0)
                {
                    Wchar_tToString(tmpstr, pEtwFileIo->FileName);
                    if (!tmpstr.empty())
                    {
                        tmpstr = String_ToUtf8(tmpstr);
                        j["win_etw_fileio_FileName"] = tmpstr.c_str();
                    }
                    else
                    {
                        j["win_etw_fileio_FileName"] = "";
                    }
                }

                //j["win_etw_fileio_Pid"] = to_string(pEtwFileIo->PID);
                j["win_etw_fileio_Tid"] = to_string(pEtwFileIo->TTID);
                j["win_etw_fileio_FileAttributes"] = to_string(pEtwFileIo->FileAttributes);
                j["win_etw_fileio_CreateOptions"] = to_string(pEtwFileIo->CreateOptions);
                j["win_etw_fileio_ShareAccess"] = to_string(pEtwFileIo->ShareAccess);
                j["win_etw_fileio_Offset"] = to_string(pEtwFileIo->Offset);
                j["win_etw_fileio_FileKey"] = to_string(pEtwFileIo->FileKey);
                j["win_etw_fileio_FileObject"] = to_string(pEtwFileIo->FileObject);
            }
            break;
            }

            // ע: Topic �ͷ� Pub������ָ��
            if (pEtwTaskData)
            {
                delete[] pEtwTaskData;
                pEtwTaskData = nullptr;
            }

            // ���л�
            std::shared_ptr<std::string> data = nullptr;
            if (j.size())
            {
                data = std::make_shared<std::string>(j.dump());
            }
            else
            {
                j.clear();
                tmpstr.clear();
                continue;
            }


            if (!g_SendQueueData_Ptr && !g_SendQueueCs_Ptr && !g_SendQueue_Event)
            {
                OutputDebugString(L"û���ö���ָ��Pip");
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
// Topic���,�첽�¼��ȴ�
void uMsgInterface::uMsg_taskPopEtwLoop()
{
    try
    {
        if (!g_jobAvailableEvent)
            return;
        do
        {
            WaitForSingleObject(
                g_jobAvailableEvent,
                INFINITE
            );

            if (g_exit)
                break;

            uMsgEtwDataHandlerEx();

        } while (true);
    }
    catch (const std::exception&)
    {

    }
}
static unsigned WINAPI uMsg_taskPopThread(void* pData)
{
    if (pData)
        (reinterpret_cast<uMsgInterface*>(pData))->uMsg_taskPopEtwLoop();
    return 0;
}
void uMsgInterface::uMsg_taskPopInit()
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
        hThread =(HANDLE)_beginthreadex(0, 0, uMsg_taskPopThread, (LPVOID)this, 0, &threadId);
        if (hThread != 0 && hThread != (HANDLE)(-1L))
        {
            m_topicthread.push_back(hThread);
        }
    }
}

// �ӿڣ��û�̬TaskId�·���ȡ����,ͬ������
void uMsgInterface::uMsg_taskPush(const int taskcode, const std::string& sData, std::vector<std::string>& vec_task_string)
{
    std::string tmpstr = "";
    std::wstring catstr = L"";
    size_t i = 0, index = 0;
    DWORD dwAllocateMemSize = 0;
    char* ptr_Getbuffer = nullptr;
    bool bStatus = Choose_mem(ptr_Getbuffer, dwAllocateMemSize, taskcode);
    if (false == bStatus || nullptr == ptr_Getbuffer || dwAllocateMemSize == 0)
        return;

    json_t j;
    try
    {
        // ptr_Getbuffer
        switch (taskcode)
        {
        case UF_PROCESS_ENUM:
        {
            if (false == SingletonUProcess::instance()->uf_EnumProcess(ptr_Getbuffer))
                break;
            const PUProcessNode procesNode = (PUProcessNode)ptr_Getbuffer;
            if (!procesNode)
                break;

            for (i = 0; i < procesNode->processcount; ++i)
            {
                tmpstr.clear();
                Wchar_tToString(tmpstr, procesNode->sysprocess[i].fullprocesspath);
                tmpstr = String_ToUtf8(tmpstr);
                j["win_user_process_Path"] = tmpstr.c_str();
                tmpstr.clear();
                Wchar_tToString(tmpstr, procesNode->sysprocess[i].szExeFile);
                tmpstr = String_ToUtf8(tmpstr);
                j["win_user_process_szExeFile"] = tmpstr.c_str();
                j["win_user_process_pid"] = to_string(procesNode->sysprocess[i].pid).c_str();
                tmpstr.clear();
                tmpstr = String_ToUtf8(procesNode->sysprocess[i].priclassbase);
                j["win_user_process_pribase"] = tmpstr.c_str();
                j["win_user_process_parenid"] = to_string(procesNode->sysprocess[i].th32ParentProcessID).c_str();
                j["win_user_process_thrcout"] = to_string(procesNode->sysprocess[i].threadcout).c_str();
                vec_task_string.emplace_back(j.dump());
            }
            OutputDebugString(L"[User] Process Enum Success");
            std::cout << "[User] Process Enum Success" << std::endl;
        }
        break;
        case UF_PROCESS_PID_TREE:
        {
            // Command - pid
            if (false == SingletonUProcess::instance()->uf_GetProcessInfo(4, ptr_Getbuffer))
                break;
        }
        break;
        case UF_SYSAUTO_START:
        {
            if (false == SingletonUAutoStart::instance()->uf_EnumAutoStartask(ptr_Getbuffer, dwAllocateMemSize))
                break;

            const PUAutoStartNode pAutorunnode = (PUAutoStartNode)ptr_Getbuffer;
            if (!pAutorunnode)
                break;


            j["win_user_autorun_flag"] = "1";
            for (i = 0; i < pAutorunnode->regnumber; ++i)
            {
                tmpstr.clear();
                tmpstr = String_ToUtf8(pAutorunnode->regrun[i].szValueName);
                j["win_user_autorun_regName"] = tmpstr.c_str();
                tmpstr.clear();
                tmpstr = String_ToUtf8(pAutorunnode->regrun[i].szValueKey);
                j["win_user_autorun_regKey"] = tmpstr.c_str();
                vec_task_string.emplace_back(j.dump());
            }

            j.clear();
            j["win_user_autorun_flag"] = "2";
            for (i = 0; i < pAutorunnode->taskrunnumber; ++i)
            {
                tmpstr.clear();
                Wchar_tToString(tmpstr, pAutorunnode->taskschrun[i].szValueName);
                tmpstr = String_ToUtf8(tmpstr);
                j["win_user_autorun_tschname"] = tmpstr.c_str();
                j["win_user_autorun_tscState"] = to_string(pAutorunnode->taskschrun[i].State).c_str();
                j["win_user_autorun_tscLastTime"] = to_string(pAutorunnode->taskschrun[i].LastTime).c_str();
                j["win_user_autorun_tscNextTime"] = to_string(pAutorunnode->taskschrun[i].NextTime).c_str();
                tmpstr.clear();
                Wchar_tToString(tmpstr, pAutorunnode->taskschrun[i].TaskCommand);
                tmpstr = String_ToUtf8(tmpstr);
                j["win_user_autorun_tscCommand"] = tmpstr.c_str();
                vec_task_string.emplace_back(j.dump());
            }
            OutputDebugString(L"[User] SystemAutoStartRun Enum Success");
            std::cout << "[User] SystemAutoStartRun Enum Success" << std::endl;
        }
        break;
        case UF_SYSNET_INFO:
        {
            if (false == SingletonUNetWork::instance()->uf_EnumNetwork(ptr_Getbuffer))
                break;

            const PUNetNode netnode = (PUNetNode)ptr_Getbuffer;
            if (!netnode)
                break;
            j["win_user_net_flag"] = "1";
            for (i = 0; i < netnode->tcpnumber; i++)
            {
                j["win_user_net_src"] = netnode->tcpnode[i].szlip;
                j["win_user_net_dst"] = netnode->tcpnode[i].szrip;
                j["win_user_net_status"] = netnode->tcpnode[i].TcpState;
                j["win_user_net_pid"] = netnode->tcpnode[i].PidString;
                vec_task_string.emplace_back(j.dump());
            }

            j.clear();
            j["win_user_net_flag"] = "2";
            for (i = 0; i < netnode->udpnumber; i++)
            {

                j["win_user_net_src"] = netnode->tcpnode[i].szlip;
                j["win_user_net_pid"] = netnode->tcpnode[i].PidString;
                vec_task_string.emplace_back(j.dump());
            }
            OutputDebugString(L"[User] EnumNetwork Enum Success");
            std::cout << "[User] EnumNetwork Enum Success" << std::endl;
        }
        break;
        case UF_SYSSESSION_INFO:
        {
        }
        break;
        case UF_SYSINFO_ID:
        {
        }
        break;
        case UF_SYSLOG_ID:
        {
        }
        break;
        case UF_SYSUSER_ID:
        {
            if (false == SingletonNSysUser::instance()->uf_EnumSysUser(ptr_Getbuffer))
                break;

            const PUUserNode pusernode = (PUUserNode)ptr_Getbuffer;
            if (!pusernode)
                break;

            for (i = 0; i < pusernode->usernumber; ++i)
            {
                tmpstr.clear();
                Wchar_tToString(tmpstr, pusernode->usernode[i].serveruser);
                tmpstr = String_ToUtf8(tmpstr);
                j["win_user_sysuser_user"] = tmpstr.c_str();
                tmpstr.clear();
                Wchar_tToString(tmpstr, pusernode->usernode[i].servername);
                tmpstr = String_ToUtf8(tmpstr);
                j["win_user_sysuser_name"] = tmpstr.c_str();
                j["win_user_sysuser_sid"] = to_string((ULONGLONG)pusernode->usernode[i].serverusid).c_str();
                j["win_user_sysuser_flag"] = to_string(pusernode->usernode[i].serveruflag).c_str();
                vec_task_string.emplace_back(j.dump());
            }
            OutputDebugString(L"[User] SysUser Enum Success");
            std::cout << "[User] SysUser Enum Success" << std::endl;
        }
        break;
        case UF_SYSSERVICE_SOFTWARE_ID:
        {
            if (false == SingletonUServerSoftware::instance()->uf_EnumAll(ptr_Getbuffer))
                break;

            const PUAllServerSoftware pNode = (PUAllServerSoftware)ptr_Getbuffer;
            if (!pNode)
                break;

            j["win_user_softwareserver_flag"] = "1";
            for (i = 0; i < pNode->servicenumber; ++i)
            {
                j.clear();
                tmpstr.clear();
                Wchar_tToString(tmpstr, pNode->uSericeinfo[i].lpServiceName);
                tmpstr = String_ToUtf8(tmpstr);
                j["win_user_server_lpsName"] = tmpstr.c_str();
                tmpstr.clear();
                Wchar_tToString(tmpstr, pNode->uSericeinfo[i].lpDisplayName);
                tmpstr = String_ToUtf8(tmpstr);
                j["win_user_server_lpdName"] = tmpstr.c_str();
                tmpstr.clear();
                Wchar_tToString(tmpstr, pNode->uSericeinfo[i].lpBinaryPathName);
                tmpstr = String_ToUtf8(tmpstr);
                j["win_user_server_lpPath"] = tmpstr.c_str();
                tmpstr.clear();
                Wchar_tToString(tmpstr, pNode->uSericeinfo[i].lpDescription);
                tmpstr = String_ToUtf8(tmpstr);
                j["win_user_server_lpDescr"] = tmpstr.c_str();
                j["win_user_server_status"] = pNode->uSericeinfo[i].dwCurrentState;
                vec_task_string.emplace_back(j.dump());
            }

            j.clear();
            j["win_user_softwareserver_flag"] = "2";
            for (i = 0; i < pNode->softwarenumber; ++i)
            {
                tmpstr.clear();
                Wchar_tToString(tmpstr, pNode->uUsoinfo[i].szSoftName);
                tmpstr = String_ToUtf8(tmpstr);
                j["win_user_software_lpsName"] = tmpstr.c_str();
                tmpstr.clear();
                Wchar_tToString(tmpstr, pNode->uUsoinfo[i].szSoftSize);
                tmpstr = String_ToUtf8(tmpstr);
                j["win_user_software_Size"] = tmpstr.c_str();
                tmpstr.clear();
                Wchar_tToString(tmpstr, pNode->uUsoinfo[i].szSoftVer);
                tmpstr = String_ToUtf8(tmpstr);
                j["win_user_software_Ver"] = tmpstr.c_str();
                tmpstr.clear();
                Wchar_tToString(tmpstr, pNode->uUsoinfo[i].strSoftInsPath);
                tmpstr = String_ToUtf8(tmpstr);
                j["win_user_software_installpath"] = tmpstr.c_str();
                tmpstr.clear();
                Wchar_tToString(tmpstr, pNode->uUsoinfo[i].strSoftUniPath);
                tmpstr = String_ToUtf8(tmpstr);
                j["win_user_software_uninstallpath"] = tmpstr.c_str();
                tmpstr.clear();
                Wchar_tToString(tmpstr, pNode->uUsoinfo[i].szSoftDate);
                tmpstr = String_ToUtf8(tmpstr);
                j["win_user_software_data"] = tmpstr.c_str();
                tmpstr.clear();
                Wchar_tToString(tmpstr, pNode->uUsoinfo[i].strSoftVenRel);
                tmpstr = String_ToUtf8(tmpstr);
                j["win_user_software_venrel"] = tmpstr.c_str();
                vec_task_string.emplace_back(j.dump());
            }
            OutputDebugString(L"[User] Software_Server Enum Success");
            std::cout << "[User] Software_Server Enum Success" << std::endl;
        }
        break;
        case UF_SYSFILE_ID:
        {
            if (sData.empty() || _access(sData.c_str(), 0) != 0)
                break;
            // Ŀ¼·��
            if (false == SingletonUFile::instance()->uf_GetDirectoryFile((char*)sData.c_str(), ptr_Getbuffer))
                break;

            const PUDriectInfo pDirectInfo = (PUDriectInfo)ptr_Getbuffer;
            if (!pDirectInfo)
                break;

            // �Ȼط���һ��cout����Ŀ¼��С
            j["win_user_driectinfo_flag"] = "1";
            j["win_user_driectinfo_filecout"] = to_string(pDirectInfo->FileNumber).c_str();
            j["win_user_driectinfo_size"] = to_string(pDirectInfo->DriectAllSize).c_str();
            vec_task_string.emplace_back(j.dump());


            // ö�ٵ��ļ�����
            j.clear();
            j["win_user_driectinfo_flag"] = "2";
            for (i = 0; i < pDirectInfo->FileNumber; ++i)
            {
                tmpstr.clear();
                Wchar_tToString(tmpstr, pDirectInfo->fileEntry[i].filename);
                tmpstr = String_ToUtf8(tmpstr);
                j["win_user_driectinfo_filename"] = tmpstr.c_str();
                tmpstr.clear();
                Wchar_tToString(tmpstr, pDirectInfo->fileEntry[i].filepath);
                tmpstr = String_ToUtf8(tmpstr);
                j["win_user_driectinfo_filePath"] = tmpstr.c_str();
                j["win_user_driectinfo_fileSize"] = to_string(pDirectInfo->fileEntry[i].filesize).c_str();
                vec_task_string.emplace_back(j.dump());
            }
            OutputDebugString(L"[User] GetDirectoryFile Enum Success");
            std::cout << "[User] GetDirectoryFile Enum Success" << std::endl;
        }
        break;
        case UF_FILE_INFO:
        {
            if (sData.empty() || _access(sData.c_str(), 0) != 0)
                break;
            //  �ļ�����·��
            if (false == SingletonUFile::instance()->uf_GetFileInfo((char*)sData.c_str(), ptr_Getbuffer))
                break;

            const PUFileInfo fileinfo = (PUFileInfo)ptr_Getbuffer;
            if (!fileinfo)
                break;

            tmpstr.clear();
            Wchar_tToString(tmpstr, fileinfo->cFileName);
            tmpstr = String_ToUtf8(tmpstr);
            j["win_user_fileinfo_filename"] = tmpstr.c_str();
            tmpstr.clear();
            Wchar_tToString(tmpstr, fileinfo->dwFileAttributes);
            tmpstr = String_ToUtf8(tmpstr);
            j["win_user_fileinfo_dwFileAttributes"] = tmpstr.c_str();
            tmpstr.clear();
            Wchar_tToString(tmpstr, fileinfo->dwFileAttributesHide);
            tmpstr = String_ToUtf8(tmpstr);
            j["win_user_fileinfo_dwFileAttributesHide"] = tmpstr.c_str();
            j["win_user_fileinfo_md5"] = fileinfo->md5;
            tmpstr.clear();
            Wchar_tToString(tmpstr, fileinfo->m_seFileSizeof);
            j["win_user_fileinfo_m_seFileSizeof"] = tmpstr.c_str();
            tmpstr.clear();
            Wchar_tToString(tmpstr, fileinfo->seFileAccess);
            tmpstr = String_ToUtf8(tmpstr);
            j["win_user_fileinfo_seFileAccess"] = tmpstr.c_str();
            tmpstr.clear();
            Wchar_tToString(tmpstr, fileinfo->seFileCreate);
            j["win_user_fileinfo_seFileCreate"] = tmpstr.c_str();
            tmpstr.clear();
            Wchar_tToString(tmpstr, fileinfo->seFileModify);
            j["win_user_fileinfo_seFileModify"] = tmpstr.c_str();
            vec_task_string.emplace_back(j.dump());
            OutputDebugString(L"[User] GetFIleInfo Success");
            std::cout << "[User] GetFIleInfo Success" << std::endl;
        }
        break;
        case UF_ROOTKIT_ID:
            break;
        default:
            break;
        }
    }
    catch (const std::exception&)
    {
    }

    if (ptr_Getbuffer)
    {
        delete[] ptr_Getbuffer;
        ptr_Getbuffer = nullptr;
    }

}

void uMsgInterface::uMsg_EtwInit()
{
    SingletonUEtw::instance()->uf_init();
    etwStatus = true;
}
void uMsgInterface::uMsg_EtwClose()
{
    SingletonUEtw::instance()->uf_close();
    etwStatus = false;
}
bool uMsgInterface::GetEtwMonStatus()
{
    return etwStatus;
}

void uMsgInterface::uMsg_Init() {
    // ��ʼ��Topic
    g_jobAvailableEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
    this->uMsg_SetTopicQueuePtr();
    this->uMsg_SetTopicQueueLockPtr();
    this->uMsg_SetTopicEventPtr();
    // ������
    this->uMsg_taskPopInit();
};
void uMsgInterface::uMsg_Free()
{
    g_exit = true;
    for (size_t idx = 0; idx < m_topicthread.size(); ++idx)
    {
        SetEvent(g_jobAvailableEvent);
        // setEvent ����һ��������߳�
        WaitForSingleObject(m_topicthread[idx], 500);
        CloseHandle(m_topicthread[idx]);
    }

    if (g_jobAvailableEvent != INVALID_HANDLE_VALUE)
    {
        ::CloseHandle(g_jobAvailableEvent);
        g_jobAvailableEvent = INVALID_HANDLE_VALUE;
    }
    m_topicthread.clear();

    // clear new memeory
    std::unique_lock<std::mutex> lock(g_RecvQueueCs);
    while (!g_RecvQueueData.empty())
    {
        auto pEtwTaskData = g_RecvQueueData.front();
        g_RecvQueueData.pop();
        if (pEtwTaskData)
        {
            delete[] pEtwTaskData;
            pEtwTaskData = nullptr;
        }
    }
}