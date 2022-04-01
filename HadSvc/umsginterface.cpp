#include "sysinfo.h"
#include <iostream>
#include <Windows.h>
#include <map>
#include <vector>
#include <string>


#include "msgassist.h"
#include "umsginterface.h"

#include "uautostart.h"
#include "unet.h"
#include "usysuser.h"
#include "uprocesstree.h"
#include "uservicesoftware.h"
#include "ufile.h"
#include "uetw.h"

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
    int i = 0, index = 0;
    DWORD64 dwAllocateMemSize = 0;
    char* ptr_Getbuffer;
    bool nstatus = Choose_mem(ptr_Getbuffer, dwAllocateMemSize, taskcode);
    if (false == nstatus || nullptr == ptr_Getbuffer || dwAllocateMemSize == 0)
        return;
    
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
                    tmpstr.clear();
                    Wchar_tToString(tmpstr, procesNode->sysprocess[i].fullprocesspath);
                    (*MapMessage)["win_user_process_Path"] = tmpstr;
                    tmpstr.clear();
                    Wchar_tToString(tmpstr, procesNode->sysprocess[i].szExeFile);
                    (*MapMessage)["win_user_process_szExeFile"] = tmpstr;
                    (*MapMessage)["win_user_process_pid"] = procesNode->sysprocess[i].pid;
                    (*MapMessage)["win_user_process_pribase"] = procesNode->sysprocess[i].priclassbase;
                    (*MapMessage)["win_user_process_parenid"] = procesNode->sysprocess[i].th32ParentProcessID;
                    (*MapMessage)["win_user_process_thrcout"] = procesNode->sysprocess[i].threadcout;
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


                (*MapMessage)["win_user_autorun_flag"] = "1";
                for (i = 0; i < autorunnode->regnumber; ++i)
                {

                    (*MapMessage)["win_user_autorun_regName"] = autorunnode->regrun[i].szValueName;
                    (*MapMessage)["win_user_autorun_regKey"] = autorunnode->regrun[i].szValueKey;
                }


                (*MapMessage)["win_user_autorun_flag"] = "2";
                for (i = 0; i < autorunnode->taskrunnumber; ++i)
                {
                    tmpstr.clear();
                    Wchar_tToString(tmpstr, autorunnode->taskschrun[i].szValueName);
                    (*MapMessage)["win_user_autorun_tschname"] = tmpstr;
                    (*MapMessage)["win_user_autorun_tscState"] = autorunnode->taskschrun[i].State;
                    (*MapMessage)["win_user_autorun_tscLastTime"] = autorunnode->taskschrun[i].LastTime;
                    (*MapMessage)["win_user_autorun_tscNextTime"] = autorunnode->taskschrun[i].NextTime;
                    tmpstr.clear();
                    Wchar_tToString(tmpstr, autorunnode->taskschrun[i].TaskCommand);
                    (*MapMessage)["win_user_autorun_tscCommand"] = tmpstr;
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

                (*MapMessage)["win_user_net_flag"] = "1";
                for (i = 0; i < netnode->tcpnumber; i++)
                {
                    (*MapMessage)["win_user_net_src"] = netnode->tcpnode[i].szlip;
                    (*MapMessage)["win_user_net_dst"] = netnode->tcpnode[i].szrip;
                    (*MapMessage)["win_user_net_status"] = netnode->tcpnode[i].TcpState;
                    (*MapMessage)["win_user_net_pid"] = netnode->tcpnode[i].PidString;
                }

                (*MapMessage)["win_user_net_flag"] = "2";
                for (i = 0; i < netnode->udpnumber; i++)
                {
                    (*MapMessage)["win_user_net_src"] = netnode->tcpnode[i].szlip;
                    (*MapMessage)["win_user_net_pid"] = netnode->tcpnode[i].PidString;
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
                    (*MapMessage)["win_user_sysuser_user"] = tmpstr;
                    tmpstr.clear();
                    Wchar_tToString(tmpstr, pusernode->usernode[i].servername);
                    (*MapMessage)["win_user_sysuser_name"] = tmpstr;
                    (*MapMessage)["win_user_sysuser_sid"] = to_string((ULONGLONG)pusernode->usernode[i].serverusid);
                    (*MapMessage)["win_user_sysuser_flag"] = to_string(pusernode->usernode[i].serveruflag);
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

                (*MapMessage)["win_user_softwareserver_flag"] = "1";
                for (i = 0; i < pNode->servicenumber; ++i)
                {
                    tmpstr.clear();
                    Wchar_tToString(tmpstr, pNode->uSericeinfo[i].lpServiceName);
                    (*MapMessage)["win_user_server_lpsName"] = tmpstr;
                    tmpstr.clear();
                    Wchar_tToString(tmpstr, pNode->uSericeinfo[i].lpDisplayName);
                    (*MapMessage)["win_user_server_lpdName"] = tmpstr;
                    tmpstr.clear();
                    Wchar_tToString(tmpstr, pNode->uSericeinfo[i].lpBinaryPathName);
                    (*MapMessage)["win_user_server_lpPath"] = tmpstr;
                    tmpstr.clear();
                    Wchar_tToString(tmpstr, pNode->uSericeinfo[i].lpDescription);
                    (*MapMessage)["win_user_server_lpDescr"] = tmpstr;
                    (*MapMessage)["win_user_server_status"] = pNode->uSericeinfo[i].dwCurrentState;
                }

                (*MapMessage)["win_user_softwareserver_flag"] = "2";
                for (i = 0; i < pNode->softwarenumber; ++i)
                {
                    tmpstr.clear();
                    Wchar_tToString(tmpstr, pNode->uUsoinfo[i].szSoftName);
                    (*MapMessage)["win_user_software_lpsName"] = tmpstr;
                    tmpstr.clear();
                    Wchar_tToString(tmpstr, pNode->uUsoinfo[i].szSoftSize);
                    (*MapMessage)["win_user_software_Size"] = tmpstr;
                    tmpstr.clear();
                    Wchar_tToString(tmpstr, pNode->uUsoinfo[i].szSoftVer);
                    (*MapMessage)["win_user_software_Ver"] = tmpstr;
                    tmpstr.clear();
                    Wchar_tToString(tmpstr, pNode->uUsoinfo[i].strSoftInsPath);
                    (*MapMessage)["win_user_software_installpath"] = tmpstr;
                    tmpstr.clear();
                    Wchar_tToString(tmpstr, pNode->uUsoinfo[i].strSoftUniPath);
                    (*MapMessage)["win_user_software_uninstallpath"] = tmpstr;
                    tmpstr.clear();
                    Wchar_tToString(tmpstr, pNode->uUsoinfo[i].szSoftDate);
                    (*MapMessage)["win_user_software_data"] = tmpstr;
                    tmpstr.clear();
                    Wchar_tToString(tmpstr, pNode->uUsoinfo[i].strSoftVenRel);
                    (*MapMessage)["win_user_software_venrel"] = tmpstr;
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
                (*MapMessage)["win_user_driectinfo_flag"] = "1";
                (*MapMessage)["win_user_driectinfo_filecout"] = to_string(directinfo->FileNumber);
                (*MapMessage)["win_user_driectinfo_size"] = to_string(directinfo->DriectAllSize);
                m_cs.lock();
                if (Grpc_Getstream())
                    m_stream->Write(rawData);
                m_cs.unlock();

                // 枚举的文件发送
                (*MapMessage)["win_user_driectinfo_flag"] = "2";
                for (i = 0; i < directinfo->FileNumber; ++i)
                {
                    tmpstr.clear();
                    Wchar_tToString(tmpstr, directinfo->fileEntry[i].filename);
                    (*MapMessage)["win_user_driectinfo_filename"] = tmpstr;
                    tmpstr.clear();
                    Wchar_tToString(tmpstr, directinfo->fileEntry[i].filepath);
                    (*MapMessage)["win_user_driectinfo_filePath"] = tmpstr;
                    (*MapMessage)["win_user_driectinfo_fileSize"] = to_string(directinfo->fileEntry[i].filesize);
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
                (*MapMessage)["win_user_fileinfo_filename"] = tmpstr;
                tmpstr.clear();
                Wchar_tToString(tmpstr, fileinfo->dwFileAttributes);
                (*MapMessage)["win_user_fileinfo_dwFileAttributes"] = tmpstr;
                tmpstr.clear();
                Wchar_tToString(tmpstr, fileinfo->dwFileAttributesHide);
                (*MapMessage)["win_user_fileinfo_dwFileAttributesHide"] = tmpstr;
                tmpstr.clear();
                (*MapMessage)["win_user_fileinfo_md5"] = fileinfo->md5;
                tmpstr.clear();
                Wchar_tToString(tmpstr, fileinfo->m_seFileSizeof);
                (*MapMessage)["win_user_fileinfo_m_seFileSizeof"] = tmpstr;
                tmpstr.clear();
                Wchar_tToString(tmpstr, fileinfo->seFileAccess);
                (*MapMessage)["win_user_fileinfo_seFileAccess"] = tmpstr;
                tmpstr.clear();
                Wchar_tToString(tmpstr, fileinfo->seFileCreate);
                (*MapMessage)["win_user_fileinfo_seFileCreate"] = tmpstr;
                tmpstr.clear();
                Wchar_tToString(tmpstr, fileinfo->seFileModify);
                (*MapMessage)["win_user_fileinfo_seFileModify"] = tmpstr;
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