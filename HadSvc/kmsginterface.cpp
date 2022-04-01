#include <iostream>
#include <Windows.h>
#include <vector>
#include <string>
#include <map>

#include "kmsginterface.h"
#include "sysinfo.h"
#include "msgassist.h"

#include "ArkSsdt.h"
#include "ArkIdt.h"
#include "ArkDpcTimer.h"
#include "ArkFsd.h"
#include "ArkMouseKeyBoard.h"
#include "ArkNetwork.h"
#include "ArkProcessInfo.h"
#include "AkrSysDriverDevInfo.h"

//rapidjson
#include <rapidjson/rapidjson.h>
#include <rapidjson/document.h>
#include <rapidjson/stringbuffer.h>
#include <rapidjson/writer.h>

static ArkSsdt		        g_grpc_ssdtobj;
static ArkIdt				    g_grpc_idtobj;
static ArkDpcTimer		    g_grpc_dpcobj;
static ArkFsd				    g_grpc_fsdobj;
static ArkMouseKeyBoard	    g_grpc_mousekeyboardobj;
static ArkNetwork			    g_grpc_networkobj;
static ArkProcessInfo		    g_grpc_processinfo;
static AkrSysDriverDevInfo	g_grpc_sysmodinfo;

void kMsgInterface::kMsg_taskPush(const int taskcode, std::vector<std::string>& vec_task_string)
{
    map<int, wstring>::iterator iter;
    map<int, wstring> Process_list;
    std::string tmpstr; wstring catstr;
    int i = 0, index = 0, veclist_cout = 0;
    DWORD dwAllocateMemSize = 0;
    char* ptr_Getbuffer;
    bool nstatus = Choose_mem(ptr_Getbuffer, dwAllocateMemSize, taskcode);
    if (false == nstatus || nullptr == ptr_Getbuffer || dwAllocateMemSize == 0)
        return;

    rapidjson::Document document;
    document.SetObject();
    rapidjson::StringBuffer buffer;
    rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);

    switch (taskcode)
    {
    case NF_SSDT_ID:
    {
        if (g_grpc_ssdtobj.nf_init())
        {
            if (false == g_grpc_ssdtobj.nf_GetSysCurrentSsdtData((LPVOID)ptr_Getbuffer, dwAllocateMemSize))
                break;
            SSDTINFO* ssdtinfo = (SSDTINFO*)ptr_Getbuffer;
            if (!ssdtinfo)
                break;

            for (i = 0; i < 0x200; ++i)
            {
                if (!ssdtinfo[i].sstd_memoffset)
                    continue;
                document.Clear();
                document.AddMember(rapidjson::StringRef("win_rootkit_ssdt_id"), rapidjson::StringRef(to_string(ssdtinfo[i].ssdt_id).c_str()), document.GetAllocator());
                document.AddMember(rapidjson::StringRef("win_rootkit_ssdt_offsetaddr"), rapidjson::StringRef(to_string(ssdtinfo[i].sstd_memoffset).c_str()), document.GetAllocator());
                document.Accept(writer);
                vec_task_string[veclist_cout++].assign(buffer.GetString(), buffer.GetLength());
            }
            std::cout << "Grpc Ssdt Send Pkg Success" << std::endl;
            break;
        }
    }
    break;
    case NF_IDT_ID:
    {
        if (g_grpc_idtobj.nf_init())
        {
            if (!g_grpc_idtobj.nf_GetIdtData((LPVOID)ptr_Getbuffer, dwAllocateMemSize))
                break;
            IDTINFO* idtinfo = (IDTINFO*)ptr_Getbuffer;
            if (!idtinfo)
                break;

            for (i = 0; i < 0x100; ++i)
            {
                if (!idtinfo[i].idt_isrmemaddr)
                    continue;
                document.Clear();
                document.AddMember(rapidjson::StringRef("win_rootkit_idt_id"), rapidjson::StringRef(to_string(idtinfo[i].idt_id).c_str()), document.GetAllocator());
                document.AddMember(rapidjson::StringRef("win_rootkit_idt_offsetaddr"), rapidjson::StringRef(to_string(idtinfo[i].idt_isrmemaddr).c_str()), document.GetAllocator());
                document.Accept(writer);
                vec_task_string[veclist_cout++].assign(buffer.GetString(), buffer.GetLength());
            }
            std::cout << "Grpc Ssdt Send Pkg Success" << std::endl;
        }
    }
    break;
    case NF_DPC_ID:
    {
        if (false == g_grpc_dpcobj.nf_GetDpcTimerData((LPVOID)ptr_Getbuffer, dwAllocateMemSize))
            break;
        DPC_TIMERINFO* dpcinfo = (DPC_TIMERINFO*)ptr_Getbuffer;
        if (!dpcinfo)
            break;

        for (i = 0; i < 0x100; ++i)
        {
            if (!dpcinfo[i].dpc)
                continue;
            document.Clear();
            document.AddMember(rapidjson::StringRef("win_rootkit_dpc"), rapidjson::StringRef(to_string(dpcinfo[i].dpc).c_str()), document.GetAllocator());
            document.AddMember(rapidjson::StringRef("win_rootkit_dpc_timeobj"), rapidjson::StringRef(to_string(dpcinfo[i].timeroutine).c_str()), document.GetAllocator());
            document.AddMember(rapidjson::StringRef("win_rootkit_dpc_timeroutine"), rapidjson::StringRef(to_string(dpcinfo[i].timeroutine).c_str()), document.GetAllocator());
            document.AddMember(rapidjson::StringRef("win_rootkit_dpc_periodtime"), rapidjson::StringRef(to_string(dpcinfo[i].period).c_str()), document.GetAllocator());
            document.Accept(writer);
            vec_task_string[veclist_cout++].assign(buffer.GetString(), buffer.GetLength());
        }
        std::cout << "Grpc Dpc Send Pkg Success" << std::endl;
    }
    break;
    case NF_FSD_ID:
    {
        if (false == g_grpc_fsdobj.nf_GetFsdInfo(ptr_Getbuffer, dwAllocateMemSize))
            break;

        ULONGLONG* MjAddrArry = (ULONGLONG*)ptr_Getbuffer;
        if (!MjAddrArry)
            break;

        document.Clear();
        document.AddMember(rapidjson::StringRef("win_rootkit_is_fsdmod"), rapidjson::StringRef("1"), document.GetAllocator());
        for (i = 0; i < 0x1b; ++i)
        {
            document.AddMember(rapidjson::StringRef("win_rootkit_fsdfastfat_id"), rapidjson::StringRef(to_string(MjAddrArry[index]).c_str()), document.GetAllocator());
            document.AddMember(rapidjson::StringRef("win_rootkit_fsdfastfat_mjaddr"), rapidjson::StringRef(to_string(MjAddrArry[index]).c_str()), document.GetAllocator());
            document.Accept(writer);
            vec_task_string[veclist_cout++].assign(buffer.GetString(), buffer.GetLength());
            index++;
        }
        std::cout << "FastFat MjFuction End" << std::endl;

        document.AddMember(rapidjson::StringRef("win_rootkit_is_fsdmod"), rapidjson::StringRef("2"), document.GetAllocator());
        for (i = 0; i < 0x1b; ++i)
        {
            document.AddMember(rapidjson::StringRef("win_rootkit_fsdntfs_id"), rapidjson::StringRef(to_string(MjAddrArry[index]).c_str()), document.GetAllocator());
            document.AddMember(rapidjson::StringRef("win_rootkit_fsdntfs_mjaddr"), rapidjson::StringRef(to_string(MjAddrArry[index]).c_str()), document.GetAllocator());
            document.Accept(writer);
            vec_task_string[veclist_cout++].assign(buffer.GetString(), buffer.GetLength());
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
        if (false == g_grpc_mousekeyboardobj.nf_GetMouseKeyInfoData(ptr_Getbuffer, dwAllocateMemSize))
            break;

        ULONGLONG* MjAddrArry = (ULONGLONG*)ptr_Getbuffer;
        if (!MjAddrArry)
            break;

        document.Clear();
        document.AddMember(rapidjson::StringRef("win_rootkit_is_mousekeymod"), rapidjson::StringRef("1"), document.GetAllocator());
        for (i = 0; i < 0x1b; ++i)
        {
            document.AddMember(rapidjson::StringRef("win_rootkit_Mouse_id"), rapidjson::StringRef(to_string(MjAddrArry[index]).c_str()), document.GetAllocator());
            document.AddMember(rapidjson::StringRef("win_rootkit_Mouse_mjaddr"), rapidjson::StringRef(to_string(MjAddrArry[index]).c_str()), document.GetAllocator());
            document.Accept(writer);
            vec_task_string[veclist_cout++].assign(buffer.GetString(), buffer.GetLength());
            index++;
        }
        std::cout << "Mouse MjFuction End" << std::endl;

        document.AddMember(rapidjson::StringRef("win_rootkit_is_mousekeymod"), rapidjson::StringRef("2"), document.GetAllocator());
        for (i = 0; i < 0x1b; ++i)
        {
            document.AddMember(rapidjson::StringRef("win_rootkit_i8042_id"), rapidjson::StringRef(to_string(MjAddrArry[index]).c_str()), document.GetAllocator());
            document.AddMember(rapidjson::StringRef("win_rootkit_i8042_mjaddr"), rapidjson::StringRef(to_string(MjAddrArry[index]).c_str()), document.GetAllocator());
            document.Accept(writer);
            vec_task_string[veclist_cout++].assign(buffer.GetString(), buffer.GetLength());
            index++;
        }
        std::cout << "i8042 MjFuction End" << std::endl;

        document.AddMember(rapidjson::StringRef("win_rootkit_is_mousekeymod"), rapidjson::StringRef("3"), document.GetAllocator());
        for (i = 0; i < 0x1b; ++i)
        {
            document.AddMember(rapidjson::StringRef("win_rootkit_kbd_id"), rapidjson::StringRef(to_string(MjAddrArry[index]).c_str()), document.GetAllocator());
            document.AddMember(rapidjson::StringRef("win_rootkit_kbd_mjaddr"), rapidjson::StringRef(to_string(MjAddrArry[index]).c_str()), document.GetAllocator());
            document.Accept(writer);
            vec_task_string[veclist_cout++].assign(buffer.GetString(), buffer.GetLength());
            index++;
        }
        std::cout << "kbd MjFuction End" << std::endl;
    }
    break;
    case NF_NETWORK_ID:
    {
        if (false == g_grpc_networkobj.nf_GetNteworkProcessInfo(ptr_Getbuffer, dwAllocateMemSize))
            break;

        PSYSNETWORKINFONODE networkinfo = (PSYSNETWORKINFONODE)ptr_Getbuffer;
        if (!networkinfo)
            break;

        document.Clear();
        // Tcp
        document.AddMember(rapidjson::StringRef("win_rootkit_is_mod"), rapidjson::StringRef("1"), document.GetAllocator());
        for (i = 0; i < networkinfo->tcpcout; ++i)
        {
            document.AddMember(rapidjson::StringRef("win_rootkit_tcp_pid"), rapidjson::StringRef(to_string(networkinfo->systcpinfo[i].processinfo.dwTcpProId).c_str()), document.GetAllocator());
            document.AddMember(rapidjson::StringRef("win_rootkit_tcp_localIp_port"), rapidjson::StringRef(to_string(networkinfo->systcpinfo[i].TpcTable.localEntry.dwIP).c_str()), document.GetAllocator());
            document.AddMember(rapidjson::StringRef("win_rootkit_tcp_remoteIp_port"), rapidjson::StringRef(to_string(networkinfo->systcpinfo[i].TpcTable.remoteEntry.dwIP).c_str()), document.GetAllocator());
            document.AddMember(rapidjson::StringRef("win_rootkit_tcp_Status"), rapidjson::StringRef(to_string(networkinfo->systcpinfo[i].socketStatus.dwState).c_str()), document.GetAllocator());
            document.Accept(writer);
            vec_task_string[veclist_cout++].assign(buffer.GetString(), buffer.GetLength());
        }
        std::cout << "Tpc Port Send Grpc Success" << std::endl;

        document.AddMember(rapidjson::StringRef("win_rootkit_is_mod"), rapidjson::StringRef("2"), document.GetAllocator());
        std::string udpipport;
        for (i = 0; i < networkinfo->udpcout; ++i)
        {
            udpipport = to_string(networkinfo->sysudpinfo[i].UdpTable.dwIP) + ":" + to_string(ntohs(networkinfo->sysudpinfo[i].UdpTable.Port));
            document.AddMember(rapidjson::StringRef("win_rootkit_udp_pid"), rapidjson::StringRef(to_string(networkinfo->sysudpinfo[i].processinfo.dwUdpProId).c_str()), document.GetAllocator());
            document.AddMember(rapidjson::StringRef("win_rootkit_udp_localIp_port"), rapidjson::StringRef(udpipport.c_str()), document.GetAllocator());
            document.Accept(writer);
            vec_task_string[veclist_cout++].assign(buffer.GetString(), buffer.GetLength());
        }
        std::cout << "Udp Port Send Grpc Success" << std::endl;
    }
    break;
    case NF_PROCESS_ENUM:
    {
        if (false == g_grpc_processinfo.nf_EnumProcess(ptr_Getbuffer, dwAllocateMemSize))
            break;

        PHANDLE_INFO phandleinfo = (PHANDLE_INFO)ptr_Getbuffer;
        if (phandleinfo && phandleinfo[0].CountNum)
        {

            for (i = 0; i < phandleinfo[0].CountNum; ++i)
            {
                wcout << "Pid: " << phandleinfo[i].ProcessId << " - Process: " << phandleinfo[i].ProcessPath << endl;// " - ProcessName: " << phandleinfo[i].ProcessName << endl;
                // È¥ÖØ
                catstr = phandleinfo[i].ProcessPath;
                catstr += L" - ";
                catstr += phandleinfo[i].ProcessName;
                Process_list[phandleinfo[i].ProcessId] = catstr;
                catstr.clear();
            }


            for (iter = Process_list.begin(); iter != Process_list.end(); iter++)
            {
                document.AddMember(rapidjson::StringRef("win_rootkit_process_pid"), rapidjson::StringRef(to_string(iter->first).c_str()), document.GetAllocator());
                tmpstr.clear();
                Wchar_tToString(tmpstr, (wchar_t*)iter->second.data());
                document.AddMember(rapidjson::StringRef("win_rootkit_process_info"), rapidjson::StringRef(tmpstr.c_str()), document.GetAllocator());
                document.Accept(writer);
                vec_task_string[veclist_cout++].assign(buffer.GetString(), buffer.GetLength());
            }

            std::cout << "processinfo to server Success" << std::endl;
        }
    }
    break;
    case NF_PROCESS_MOD:
    {
        int Process_Pid = 4;
         cout << "Please Input Pid: ";
         scanf("%d", &Process_Pid);
        // Ä¬ÈÏ²âÊÔ
        if (false == g_grpc_processinfo.nf_GetProcessMod(Process_Pid, ptr_Getbuffer, dwAllocateMemSize))
            break;

        PPROCESS_MOD modptr = (PPROCESS_MOD)ptr_Getbuffer;
        if (modptr)
        {
            document.AddMember(rapidjson::StringRef("win_rootkit_processmod_pid"), rapidjson::StringRef(to_string(Process_Pid).c_str()), document.GetAllocator());
            for (i = 0; i < 1024 * 2; ++i)
            {
                if (0 == modptr[i].EntryPoint && 0 == modptr[i].SizeOfImage && 0 == modptr[i].DllBase)
                    continue;
                document.Clear();
                document.AddMember(rapidjson::StringRef("win_rootkit_process_DllBase"), rapidjson::StringRef(to_string(modptr[i].DllBase).c_str()), document.GetAllocator());
                document.AddMember(rapidjson::StringRef("win_rootkit_process_SizeofImage"), rapidjson::StringRef(to_string(modptr[i].SizeOfImage).c_str()), document.GetAllocator());
                document.AddMember(rapidjson::StringRef("win_rootkit_process_EntryPoint"), rapidjson::StringRef(to_string(modptr[i].EntryPoint).c_str()), document.GetAllocator());
                tmpstr.clear();
                Wchar_tToString(tmpstr, modptr[i].BaseDllName);
                document.AddMember(rapidjson::StringRef("win_rootkit_process_BaseDllName"), rapidjson::StringRef(tmpstr.c_str()), document.GetAllocator());
                tmpstr.clear();
                Wchar_tToString(tmpstr, modptr[i].FullDllName);
                document.AddMember(rapidjson::StringRef("win_rootkit_process_FullDllName"), rapidjson::StringRef(tmpstr.c_str()), document.GetAllocator());
                document.Accept(writer);
                vec_task_string[veclist_cout++].assign(buffer.GetString(), buffer.GetLength());
            }
        }
        std::cout << "Process Mod Success" << std::endl;
    }
    break;
    case NF_PROCESS_KILL:
    {
         g_grpc_processinfo.nf_KillProcess();
    }
    break;
    case NF_SYSMOD_ENUM:
    {
        if (false == g_grpc_sysmodinfo.nf_EnumSysMod(ptr_Getbuffer, dwAllocateMemSize))
            break;


        PPROCESS_MOD modptr = (PPROCESS_MOD)ptr_Getbuffer;
        if (modptr)
        {
            for (i = 0; i < 1024 * 2; ++i)
            {
                // Bug
                if (0 == modptr[i].EntryPoint && 0 == modptr[i].SizeOfImage && 0 == modptr[i].DllBase)
                    continue;
                document.Clear();
                document.AddMember(rapidjson::StringRef("win_rootkit_sys_DllBase"), rapidjson::StringRef(to_string(modptr[i].DllBase).c_str()), document.GetAllocator());
                document.AddMember(rapidjson::StringRef("win_rootkit_sys_SizeofImage"), rapidjson::StringRef(to_string(modptr[i].SizeOfImage).c_str()), document.GetAllocator());
                document.AddMember(rapidjson::StringRef("win_rootkit_sys_EntryPoint"), rapidjson::StringRef(to_string(modptr[i].EntryPoint).c_str()), document.GetAllocator());
                tmpstr.clear();
                Wchar_tToString(tmpstr, modptr[i].BaseDllName);
                document.AddMember(rapidjson::StringRef("win_rootkit_sys_BaseDllName"), rapidjson::StringRef(tmpstr.c_str()), document.GetAllocator());
                tmpstr.clear();
                Wchar_tToString(tmpstr, modptr[i].FullDllName);
                document.AddMember(rapidjson::StringRef("win_rootkit_sys_FullDllName"), rapidjson::StringRef(tmpstr.c_str()), document.GetAllocator());
                document.Accept(writer);
                vec_task_string[veclist_cout++].assign(buffer.GetString(), buffer.GetLength());
            }
        }
        std::cout << "SystemDriver Enum Success" << std::endl;
    }
    break;

    default:
        break;
    }
}