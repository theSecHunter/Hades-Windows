#include <iostream>
#include <Windows.h>
#include <map>
#include <vector>
#include <string>

#include "sysinfo.h"
#include "msgassist.h"
#include "umsginterface.h"

#include "uautostart.h"
#include "unet.h"
#include "usysuser.h"
#include "uprocesstree.h"
#include "uservicesoftware.h"
#include "ufile.h"
#include "uetw.h"

//rapidjson
#include <rapidjson/rapidjson.h>
#include <rapidjson/document.h>
#include <rapidjson/stringbuffer.h>
#include <rapidjson/writer.h>

static UAutoStart           g_grpc_uautostrobj;
static UNet                 g_grpc_unetobj;
static NSysUser             g_grpc_usysuser;
static UProcess             g_grpc_uprocesstree;
static UServerSoftware      g_grpc_userversoftware;
static UFile                g_grpc_ufile;
static UEtw                 g_grpc_etw;

void uMsgInterface::uMsg_taskPush(const int taskcode, std::vector<std::string>& vec_task_string)
{
    std::string tmpstr; wstring catstr;
    int i = 0, index = 0, veclist_cout = 0;
    DWORD64 dwAllocateMemSize = 0;
    char* ptr_Getbuffer;
    bool nstatus = Choose_mem(ptr_Getbuffer, dwAllocateMemSize, taskcode);
    if (false == nstatus || nullptr == ptr_Getbuffer || dwAllocateMemSize == 0)
        return;

    rapidjson::Document document;
    document.SetObject();
    rapidjson::StringBuffer buffer;
    rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
    
    try
    {
        // ptr_Getbuffer
        do
        {
            switch (taskcode)
            {
            case UF_PROCESS_ENUM:
            {
                if (false == g_grpc_uprocesstree.uf_EnumProcess(ptr_Getbuffer))
                    break;
                PUProcessNode procesNode = (PUProcessNode)ptr_Getbuffer;
                if (!procesNode)
                    break;

                for (i = 0; i < procesNode->processcount; ++i)
                {
                    document.Clear();
                    tmpstr.clear();
                    Wchar_tToString(tmpstr, procesNode->sysprocess[i].fullprocesspath);
                    document.AddMember(rapidjson::StringRef("win_user_process_Path"), rapidjson::StringRef(tmpstr.c_str()), document.GetAllocator());
                    tmpstr.clear();
                    Wchar_tToString(tmpstr, procesNode->sysprocess[i].szExeFile);
                    document.AddMember(rapidjson::StringRef("win_user_process_szExeFile"), rapidjson::StringRef(tmpstr.c_str()), document.GetAllocator());
                    document.AddMember(rapidjson::StringRef("win_user_process_pid"), rapidjson::StringRef(to_string(procesNode->sysprocess[i].pid).c_str()), document.GetAllocator());
                    document.AddMember(rapidjson::StringRef("win_user_process_pribase"), rapidjson::StringRef(procesNode->sysprocess[i].priclassbase), document.GetAllocator());
                    document.AddMember(rapidjson::StringRef("win_user_process_parenid"), rapidjson::StringRef(to_string(procesNode->sysprocess[i].th32ParentProcessID).c_str()), document.GetAllocator());
                    document.AddMember(rapidjson::StringRef("win_user_process_thrcout"), rapidjson::StringRef(to_string(procesNode->sysprocess[i].threadcout).c_str()), document.GetAllocator());
                    document.Accept(writer);
                    vec_task_string[veclist_cout++].assign(buffer.GetString(), buffer.GetLength());
                }
                std::cout << "[User] Process Enum Success" << std::endl;
            }
            break;
            case UF_PROCESS_PID_TREE:
            {
                // Command - pid
                if (false == g_grpc_uprocesstree.uf_GetProcessInfo(4, ptr_Getbuffer))
                    break;
            }
            break;
            case UF_SYSAUTO_START:
            {
                if (false == g_grpc_uautostrobj.uf_EnumAutoStartask(ptr_Getbuffer, dwAllocateMemSize))
                    break;

                PUAutoStartNode autorunnode = (PUAutoStartNode)ptr_Getbuffer;
                if (!autorunnode)
                    break;

                document.Clear();
                document.AddMember(rapidjson::StringRef("win_user_autorun_flag"), rapidjson::StringRef("1"), document.GetAllocator());
                for (i = 0; i < autorunnode->regnumber; ++i)
                {
                    document.AddMember(rapidjson::StringRef("win_user_autorun_regName"), rapidjson::StringRef(autorunnode->regrun[i].szValueName), document.GetAllocator());
                    document.AddMember(rapidjson::StringRef("win_user_autorun_regKey"), rapidjson::StringRef(autorunnode->regrun[i].szValueKey), document.GetAllocator());
                    document.Accept(writer);
                    vec_task_string[veclist_cout++].assign(buffer.GetString(), buffer.GetLength());
                }

                document.AddMember(rapidjson::StringRef("win_user_autorun_flag"), rapidjson::StringRef("2"), document.GetAllocator());
                for (i = 0; i < autorunnode->taskrunnumber; ++i)
                {
                    tmpstr.clear();
                    Wchar_tToString(tmpstr, autorunnode->taskschrun[i].szValueName);
                    document.AddMember(rapidjson::StringRef("win_user_autorun_tschname"), rapidjson::StringRef(tmpstr.c_str()), document.GetAllocator());
                    document.AddMember(rapidjson::StringRef("win_user_autorun_tscState"), rapidjson::StringRef(to_string(autorunnode->taskschrun[i].State).c_str()), document.GetAllocator());
                    document.AddMember(rapidjson::StringRef("win_user_autorun_tscLastTime"), rapidjson::StringRef(to_string(autorunnode->taskschrun[i].LastTime).c_str()), document.GetAllocator());
                    document.AddMember(rapidjson::StringRef("win_user_autorun_tscNextTime"), rapidjson::StringRef(to_string(autorunnode->taskschrun[i].NextTime).c_str()), document.GetAllocator());
                    tmpstr.clear();
                    Wchar_tToString(tmpstr, autorunnode->taskschrun[i].TaskCommand);
                    document.AddMember(rapidjson::StringRef("win_user_autorun_tscCommand"), rapidjson::StringRef(tmpstr.c_str()), document.GetAllocator());
                    document.Accept(writer);
                    vec_task_string[veclist_cout++].assign(buffer.GetString(), buffer.GetLength());
                }

                std::cout << "[User] SystemAutoStartRun Enum Success" << std::endl;
            }
            break;
            case UF_SYSNET_INFO:
            {
                if (false == g_grpc_unetobj.uf_EnumNetwork(ptr_Getbuffer))
                    break;

                PUNetNode netnode = (PUNetNode)ptr_Getbuffer;
                if (!netnode)
                    break;

                document.AddMember(rapidjson::StringRef("win_user_net_flag"), rapidjson::StringRef("1"), document.GetAllocator());
                for (i = 0; i < netnode->tcpnumber; i++)
                {
                    document.AddMember(rapidjson::StringRef("win_user_net_src"), rapidjson::StringRef(netnode->tcpnode[i].szlip), document.GetAllocator());
                    document.AddMember(rapidjson::StringRef("win_user_net_dst"), rapidjson::StringRef(netnode->tcpnode[i].szrip), document.GetAllocator());
                    document.AddMember(rapidjson::StringRef("win_user_net_status"), rapidjson::StringRef(netnode->tcpnode[i].TcpState), document.GetAllocator());
                    document.AddMember(rapidjson::StringRef("win_user_net_pid"), rapidjson::StringRef(netnode->tcpnode[i].PidString), document.GetAllocator());
                    document.Accept(writer);
                    vec_task_string[veclist_cout++].assign(buffer.GetString(), buffer.GetLength());
                }

                document.AddMember(rapidjson::StringRef("win_user_net_flag"), rapidjson::StringRef("2"), document.GetAllocator());
                for (i = 0; i < netnode->udpnumber; i++)
                {
                    document.AddMember(rapidjson::StringRef("win_user_net_src"), rapidjson::StringRef(netnode->tcpnode[i].szlip), document.GetAllocator());
                    document.AddMember(rapidjson::StringRef("win_user_net_pid"), rapidjson::StringRef(netnode->tcpnode[i].PidString), document.GetAllocator());
                    document.Accept(writer);
                    vec_task_string[veclist_cout++].assign(buffer.GetString(), buffer.GetLength());
                }

            }
            break;
            case UF_SYSSESSION_INFO: // v2.0
            {
            }
            break;
            case UF_SYSINFO_ID:     // v1.0 --> 是否上线时候主动发送?非被动采集
            {
            }
            break;
            case UF_SYSLOG_ID:      // 待定 --> etw完全可以取代
            {
            }
            break;
            case UF_SYSUSER_ID:
            {
                if (false == g_grpc_usysuser.uf_EnumSysUser(ptr_Getbuffer))
                    break;

                PUUserNode pusernode = (PUUserNode)ptr_Getbuffer;
                if (!pusernode)
                    break;

                for (i = 0; i < pusernode->usernumber; ++i)
                {
                    tmpstr.clear();
                    Wchar_tToString(tmpstr, pusernode->usernode[i].serveruser);
                    document.AddMember(rapidjson::StringRef("win_user_sysuser_user"), rapidjson::StringRef(tmpstr.c_str()), document.GetAllocator());
                    tmpstr.clear();
                    Wchar_tToString(tmpstr, pusernode->usernode[i].servername);
                    document.AddMember(rapidjson::StringRef("win_user_sysuser_name"), rapidjson::StringRef(tmpstr.c_str()), document.GetAllocator());
                    document.AddMember(rapidjson::StringRef("win_user_sysuser_sid"), rapidjson::StringRef(to_string((ULONGLONG)pusernode->usernode[i].serverusid).c_str()), document.GetAllocator());
                    document.AddMember(rapidjson::StringRef("win_user_sysuser_flag"), rapidjson::StringRef(to_string(pusernode->usernode[i].serveruflag).c_str()), document.GetAllocator());
                    document.Accept(writer);
                    vec_task_string[veclist_cout++].assign(buffer.GetString(), buffer.GetLength());
                }

            }
            break;
            case UF_SYSSERVICE_SOFTWARE_ID:
            {
                if (false != g_grpc_userversoftware.EnumAll(ptr_Getbuffer))
                    break;

                PUAllServerSoftware pNode = (PUAllServerSoftware)ptr_Getbuffer;
                if (!pNode)
                    break;

                document.AddMember(rapidjson::StringRef("win_user_softwareserver_flag"), rapidjson::StringRef("1"), document.GetAllocator());
                for (i = 0; i < pNode->servicenumber; ++i)
                {
                    tmpstr.clear();
                    Wchar_tToString(tmpstr, pNode->uSericeinfo[i].lpServiceName);
                    document.AddMember(rapidjson::StringRef("win_user_server_lpsName"), rapidjson::StringRef(tmpstr.c_str()), document.GetAllocator());
                    tmpstr.clear();
                    Wchar_tToString(tmpstr, pNode->uSericeinfo[i].lpDisplayName);
                    document.AddMember(rapidjson::StringRef("win_user_server_lpdName"), rapidjson::StringRef(tmpstr.c_str()), document.GetAllocator());
                    tmpstr.clear();
                    Wchar_tToString(tmpstr, pNode->uSericeinfo[i].lpBinaryPathName);
                    document.AddMember(rapidjson::StringRef("win_user_server_lpPath"), rapidjson::StringRef(tmpstr.c_str()), document.GetAllocator());
                    tmpstr.clear();
                    Wchar_tToString(tmpstr, pNode->uSericeinfo[i].lpDescription);
                    document.AddMember(rapidjson::StringRef("win_user_server_lpDescr"), rapidjson::StringRef(tmpstr.c_str()), document.GetAllocator());
                    document.AddMember(rapidjson::StringRef("win_user_server_status"), rapidjson::StringRef(pNode->uSericeinfo[i].dwCurrentState.c_str()), document.GetAllocator());
                    document.Accept(writer);
                    vec_task_string[veclist_cout++].assign(buffer.GetString(), buffer.GetLength());
                }

                document.AddMember(rapidjson::StringRef("win_user_softwareserver_flag"), rapidjson::StringRef("2"), document.GetAllocator());
                for (i = 0; i < pNode->softwarenumber; ++i)
                {
                    tmpstr.clear();
                    Wchar_tToString(tmpstr, pNode->uUsoinfo[i].szSoftName);
                    document.AddMember(rapidjson::StringRef("win_user_software_lpsName"), rapidjson::StringRef(tmpstr.c_str()), document.GetAllocator());
                    tmpstr.clear();
                    Wchar_tToString(tmpstr, pNode->uUsoinfo[i].szSoftSize);
                    document.AddMember(rapidjson::StringRef("win_user_software_Size"), rapidjson::StringRef(tmpstr.c_str()), document.GetAllocator());
                    tmpstr.clear();
                    Wchar_tToString(tmpstr, pNode->uUsoinfo[i].szSoftVer);
                    document.AddMember(rapidjson::StringRef("win_user_software_Ver"), rapidjson::StringRef(tmpstr.c_str()), document.GetAllocator());
                    tmpstr.clear();
                    Wchar_tToString(tmpstr, pNode->uUsoinfo[i].strSoftInsPath);
                    document.AddMember(rapidjson::StringRef("win_user_software_installpath"), rapidjson::StringRef(tmpstr.c_str()), document.GetAllocator());
                    tmpstr.clear();
                    Wchar_tToString(tmpstr, pNode->uUsoinfo[i].strSoftUniPath);
                    document.AddMember(rapidjson::StringRef("win_user_software_uninstallpath"), rapidjson::StringRef(tmpstr.c_str()), document.GetAllocator());
                    tmpstr.clear();
                    Wchar_tToString(tmpstr, pNode->uUsoinfo[i].szSoftDate);
                    document.AddMember(rapidjson::StringRef("win_user_software_data"), rapidjson::StringRef(tmpstr.c_str()), document.GetAllocator());
                    tmpstr.clear();
                    Wchar_tToString(tmpstr, pNode->uUsoinfo[i].strSoftVenRel);
                    document.AddMember(rapidjson::StringRef("win_user_software_venrel"), rapidjson::StringRef(tmpstr.c_str()), document.GetAllocator());
                    document.Accept(writer);
                    vec_task_string[veclist_cout++].assign(buffer.GetString(), buffer.GetLength());
                }

            }
            break;
            case UF_SYSFILE_ID:
            {
                // Command 获取 目录路径
                if (false == g_grpc_ufile.uf_GetDirectoryFile((char*)"D:\\bin\\vpn", ptr_Getbuffer))
                    break;

                PUDriectInfo directinfo = (PUDriectInfo)ptr_Getbuffer;
                if (!directinfo)
                    break;

                // 先回发送一次cout和总目录大小
                document.AddMember(rapidjson::StringRef("win_user_driectinfo_flag"), rapidjson::StringRef("1"), document.GetAllocator());
                document.AddMember(rapidjson::StringRef("win_user_driectinfo_filecout"), rapidjson::StringRef(to_string(directinfo->FileNumber).c_str()), document.GetAllocator());
                document.AddMember(rapidjson::StringRef("win_user_driectinfo_size"), rapidjson::StringRef(to_string(directinfo->DriectAllSize).c_str()), document.GetAllocator());
                document.Accept(writer);
                vec_task_string[veclist_cout++].assign(buffer.GetString(), buffer.GetLength());

                document.Clear();
                // 枚举的文件发送
                document.AddMember(rapidjson::StringRef("win_user_driectinfo_flag"), rapidjson::StringRef("2"), document.GetAllocator());
                for (i = 0; i < directinfo->FileNumber; ++i)
                {
                    tmpstr.clear();
                    Wchar_tToString(tmpstr, directinfo->fileEntry[i].filename);
                    document.AddMember(rapidjson::StringRef("win_user_driectinfo_filename"), rapidjson::StringRef(tmpstr.c_str()), document.GetAllocator());
                    tmpstr.clear();
                    Wchar_tToString(tmpstr, directinfo->fileEntry[i].filepath);
                    document.AddMember(rapidjson::StringRef("win_user_driectinfo_filePath"), rapidjson::StringRef(tmpstr.c_str()), document.GetAllocator());
                    document.AddMember(rapidjson::StringRef("win_user_driectinfo_fileSize"), rapidjson::StringRef(to_string(directinfo->fileEntry[i].filesize).c_str()), document.GetAllocator());
                    document.Accept(writer);
                    vec_task_string[veclist_cout++].assign(buffer.GetString(), buffer.GetLength());
                }
            }
            break;
            case UF_FILE_INFO:
            {
                // Command 获取 文件绝对路径
                if (false == g_grpc_ufile.uf_GetFileInfo((char*)"c:\\1.text", ptr_Getbuffer))
                    break;

                PUFileInfo fileinfo = (PUFileInfo)ptr_Getbuffer;
                if (!fileinfo)
                    break;

                tmpstr.clear();
                Wchar_tToString(tmpstr, fileinfo->cFileName);
                document.AddMember(rapidjson::StringRef("win_user_fileinfo_filename"), rapidjson::StringRef(tmpstr.c_str()), document.GetAllocator());
                tmpstr.clear();
                Wchar_tToString(tmpstr, fileinfo->dwFileAttributes);
                document.AddMember(rapidjson::StringRef("win_user_fileinfo_dwFileAttributes"), rapidjson::StringRef(tmpstr.c_str()), document.GetAllocator());
                tmpstr.clear();
                Wchar_tToString(tmpstr, fileinfo->dwFileAttributesHide);
                document.AddMember(rapidjson::StringRef("win_user_fileinfo_dwFileAttributesHide"), rapidjson::StringRef(tmpstr.c_str()), document.GetAllocator());
                tmpstr.clear();
                document.AddMember(rapidjson::StringRef("win_user_fileinfo_md5"), rapidjson::StringRef(fileinfo->md5.c_str()), document.GetAllocator());
                tmpstr.clear();
                Wchar_tToString(tmpstr, fileinfo->m_seFileSizeof);
                document.AddMember(rapidjson::StringRef("win_user_fileinfo_m_seFileSizeof"), rapidjson::StringRef(tmpstr.c_str()), document.GetAllocator());
                tmpstr.clear();
                Wchar_tToString(tmpstr, fileinfo->seFileAccess);
                document.AddMember(rapidjson::StringRef("win_user_fileinfo_seFileAccess"), rapidjson::StringRef(tmpstr.c_str()), document.GetAllocator());
                tmpstr.clear();
                Wchar_tToString(tmpstr, fileinfo->seFileCreate);
                document.AddMember(rapidjson::StringRef("win_user_fileinfo_seFileCreate"), rapidjson::StringRef(tmpstr.c_str()), document.GetAllocator());
                tmpstr.clear();
                Wchar_tToString(tmpstr, fileinfo->seFileModify);
                document.AddMember(rapidjson::StringRef("win_user_fileinfo_seFileModify"), rapidjson::StringRef(tmpstr.c_str()), document.GetAllocator());
                document.Accept(writer);
                vec_task_string[veclist_cout++].assign(buffer.GetString(), buffer.GetLength());
            }
            break;
            case UF_ROOTKIT_ID:     // v2.0
            {
            }
            break;
            default:
                break;
            }
        } while (false);
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