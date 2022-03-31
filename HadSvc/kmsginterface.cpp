#include "kmsginterface.h"
//#include "ArkSsdt.h"
//#include "ArkIdt.h"
//#include "ArkDpcTimer.h"
//#include "ArkFsd.h"
//#include "ArkMouseKeyBoard.h"
//#include "ArkNetwork.h"
//#include "ArkProcessInfo.h"
//#include "AkrSysDriverDevInfo.h"

//static ArkSsdt		        g_grpc_ssdtobj;
//static ArkIdt				    g_grpc_idtobj;
//static ArkDpcTimer		    g_grpc_dpcobj;
//static ArkFsd				    g_grpc_fsdobj;
//static ArkMouseKeyBoard	    g_grpc_mousekeyboardobj;
//static ArkNetwork			    g_grpc_networkobj;
//static ArkProcessInfo		    g_grpc_processinfo;
//static AkrSysDriverDevInfo	g_grpc_sysmodinfo;

/*
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
            (*MapMessage)["win_rootkit_ssdt_id"] = to_string(ssdtinfo[i].ssdt_id);
            (*MapMessage)["win_rootkit_ssdt_offsetaddr"] = to_string(ssdtinfo[i].sstd_memoffset);
            m_cs.lock();
            if (Grpc_Getstream())
                m_stream->Write(rawData);
            m_cs.unlock();
        }
        cout << "Grpc Ssdt Send Pkg Success" << endl;
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
            (*MapMessage)["win_rootkit_idt_id"] = to_string(idtinfo[i].idt_id);
            (*MapMessage)["win_rootkit_idt_offsetaddr"] = to_string(idtinfo[i].idt_isrmemaddr);
            m_cs.lock();
            if (Grpc_Getstream())
                m_stream->Write(rawData);
            m_cs.unlock();
        }
        cout << "Grpc Ssdt Send Pkg Success" << endl;
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
        (*MapMessage)["win_rootkit_dpc"] = to_string(dpcinfo[i].dpc);
        (*MapMessage)["win_rootkit_dpc_timeobj"] = to_string(dpcinfo[i].timeroutine);
        (*MapMessage)["win_rootkit_dpc_timeroutine"] = to_string(dpcinfo[i].timeroutine);
        (*MapMessage)["win_rootkit_dpc_periodtime"] = to_string(dpcinfo[i].period);
        m_cs.lock();
        if (Grpc_Getstream())
            m_stream->Write(rawData);
        m_cs.unlock();
    }
    cout << "Grpc Dpc Send Pkg Success" << endl;
}
break;
case NF_FSD_ID:
{
    if (false == g_grpc_fsdobj.nf_GetFsdInfo(ptr_Getbuffer, dwAllocateMemSize))
        break;

    ULONGLONG* MjAddrArry = (ULONGLONG*)ptr_Getbuffer;
    if (!MjAddrArry)
        break;

    (*MapMessage)["win_rootkit_is_fsdmod"] = "1";
    for (i = 0; i < 0x1b; ++i)
    {
        (*MapMessage)["win_rootkit_fsdfastfat_id"] = to_string(MjAddrArry[index]);
        (*MapMessage)["win_rootkit_fsdfastfat_mjaddr"] = to_string(MjAddrArry[index]);
        m_cs.lock();
        if (Grpc_Getstream())
            m_stream->Write(rawData);
        m_cs.unlock();
        index++;
    }
    cout << "FastFat MjFuction End" << endl;

    (*MapMessage)["win_rootkit_is_fsdmod"] = "2";
    for (i = 0; i < 0x1b; ++i)
    {
        (*MapMessage)["win_rootkit_fsdntfs_id"] = to_string(MjAddrArry[index]);
        (*MapMessage)["win_rootkit_fsdntfs_mjaddr"] = to_string(MjAddrArry[index]);
        m_cs.lock();
        if (Grpc_Getstream())
            m_stream->Write(rawData);
        m_cs.unlock();
        index++;
    }
    cout << "Ntfs MjFuction End" << endl;
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

    (*MapMessage)["win_rootkit_is_mousekeymod"] = "1";
    for (i = 0; i < 0x1b; ++i)
    {
        (*MapMessage)["win_rootkit_Mouse_id"] = to_string(MjAddrArry[index]);
        (*MapMessage)["win_rootkit_Mouse_mjaddr"] = to_string(MjAddrArry[index]);
        m_cs.lock();
        if (Grpc_Getstream())
            m_stream->Write(rawData);
        m_cs.unlock();
        index++;
    }
    cout << "Mouse MjFuction End" << endl;

    (*MapMessage)["win_rootkit_is_mousekeymod"] = "2";
    for (i = 0; i < 0x1b; ++i)
    {
        (*MapMessage)["win_rootkit_i8042_id"] = to_string(MjAddrArry[index]);
        (*MapMessage)["win_rootkit_i8042_mjaddr"] = to_string(MjAddrArry[index]);
        m_cs.lock();
        if (Grpc_Getstream())
            m_stream->Write(rawData);
        m_cs.unlock();
        index++;
    }
    cout << "i8042 MjFuction End" << endl;


    (*MapMessage)["win_rootkit_is_mousekeymod"] = "3";
    for (i = 0; i < 0x1b; ++i)
    {
        (*MapMessage)["win_rootkit_kbd_id"] = to_string(MjAddrArry[index]);
        (*MapMessage)["win_rootkit_kbd_mjaddr"] = to_string(MjAddrArry[index]);
        m_cs.lock();
        if (Grpc_Getstream())
            m_stream->Write(rawData);
        m_cs.unlock();
        index++;
    }
    cout << "kbd MjFuction End" << endl;
}
break;
case NF_NETWORK_ID:
{
    if (false == g_grpc_networkobj.nf_GetNteworkProcessInfo(ptr_Getbuffer, dwAllocateMemSize))
        break;

    PSYSNETWORKINFONODE networkinfo = (PSYSNETWORKINFONODE)ptr_Getbuffer;
    if (!networkinfo)
        break;

    // Tcp

    (*MapMessage)["win_rootkit_is_mod"] = "1";
    for (i = 0; i < networkinfo->tcpcout; ++i)
    {
        (*MapMessage)["win_rootkit_tcp_pid"] = to_string(networkinfo->systcpinfo[i].processinfo.dwTcpProId);
        (*MapMessage)["win_rootkit_tcp_localIp_port"] = to_string(networkinfo->systcpinfo[i].TpcTable.localEntry.dwIP) + ":" + to_string(ntohs(networkinfo->systcpinfo[i].TpcTable.localEntry.Port));
        (*MapMessage)["win_rootkit_tcp_remoteIp_port"] = to_string(networkinfo->systcpinfo[i].TpcTable.remoteEntry.dwIP) + ":" + to_string(ntohs(networkinfo->systcpinfo[i].TpcTable.remoteEntry.Port));
        (*MapMessage)["win_rootkit_tcp_Status"] = to_string(networkinfo->systcpinfo[i].socketStatus.dwState);
        m_cs.lock();
        if (Grpc_Getstream())
            m_stream->Write(rawData);
        m_cs.unlock();
    }
    cout << "Tpc Port Send Grpc Success" << endl;


    (*MapMessage)["win_rootkit_is_mod"] = "2";
    for (i = 0; i < networkinfo->udpcout; ++i)
    {
        (*MapMessage)["win_rootkit_udp_pid"] = to_string(networkinfo->sysudpinfo[i].processinfo.dwUdpProId);
        (*MapMessage)["win_rootkit_udp_localIp_port"] = to_string(networkinfo->sysudpinfo[i].UdpTable.dwIP) + ":" + to_string(ntohs(networkinfo->sysudpinfo[i].UdpTable.Port));
        m_cs.lock();
        if (Grpc_Getstream())
            m_stream->Write(rawData);
        m_cs.unlock();
    }
    cout << "Udp Port Send Grpc Success" << endl;
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
            //wcout << "Pid: " << phandleinfo[i].ProcessId << " - Process: " << phandleinfo[i].ProcessPath << endl;// " - ProcessName: " << phandleinfo[i].ProcessName << endl;
            // È¥ÖØ
            catstr = phandleinfo[i].ProcessPath;
            catstr += L" - ";
            catstr += phandleinfo[i].ProcessName;
            Process_list[phandleinfo[i].ProcessId] = catstr;
            catstr.clear();
        }


        for (iter = Process_list.begin(); iter != Process_list.end(); iter++)
        {
            (*MapMessage)["win_rootkit_process_pid"] = to_string(iter->first);
            tmpstr.clear();
            Wchar_tToString(tmpstr, (wchar_t*)iter->second.data());
            (*MapMessage)["win_rootkit_process_info"] = tmpstr;
            m_cs.lock();
            if (Grpc_Getstream())
                m_stream->Write(rawData);
            m_cs.unlock();
        }

        cout << "processinfo to server Success" << endl;
    }
}
break;
case NF_PROCESS_MOD:
{
    int Process_Pid = 4;
    // cout << "Please Input Pid: ";
    // scanf("%d", &Process_Pid);
    // Ä¬ÈÏ²âÊÔ
    if (false == g_grpc_processinfo.nf_GetProcessMod(Process_Pid, ptr_Getbuffer, dwAllocateMemSize))
        break;

    PPROCESS_MOD modptr = (PPROCESS_MOD)ptr_Getbuffer;
    if (modptr)
    {

        (*MapMessage)["win_rootkit_processmod_pid"] = to_string(Process_Pid);
        for (i = 0; i < 1024 * 2; ++i)
        {
            if (0 == modptr[i].EntryPoint && 0 == modptr[i].SizeOfImage && 0 == modptr[i].DllBase)
                continue;

            (*MapMessage)["win_rootkit_process_DllBase"] = to_string(modptr[i].DllBase);
            (*MapMessage)["win_rootkit_process_SizeofImage"] = to_string(modptr[i].SizeOfImage);
            (*MapMessage)["win_rootkit_process_EntryPoint"] = to_string(modptr[i].EntryPoint);
            tmpstr.clear();
            Wchar_tToString(tmpstr, modptr[i].BaseDllName);
            (*MapMessage)["win_rootkit_process_BaseDllName"] = tmpstr;
            tmpstr.clear();
            Wchar_tToString(tmpstr, modptr[i].FullDllName);
            (*MapMessage)["win_rootkit_process_FullDllName"] = tmpstr;
            m_cs.lock();
            if (Grpc_Getstream())
                m_stream->Write(rawData);
            m_cs.unlock();
        }
    }
    cout << "Process Mod Success" << endl;
}
break;
case NF_PROCESS_KILL:
{
    // g_grpc_processinfo.nf_KillProcess();
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

            (*MapMessage)["win_rootkit_sys_DllBase"] = to_string(modptr[i].DllBase);
            (*MapMessage)["win_rootkit_sys_SizeofImage"] = to_string(modptr[i].SizeOfImage);
            (*MapMessage)["win_rootkit_sys_EntryPoint"] = to_string(modptr[i].EntryPoint);
            tmpstr.clear();
            Wchar_tToString(tmpstr, modptr[i].BaseDllName);
            (*MapMessage)["win_rootkit_sys_BaseDllName"] = tmpstr;
            tmpstr.clear();
            Wchar_tToString(tmpstr, modptr[i].FullDllName);
            (*MapMessage)["win_rootkit_sys_FullDllName"] = tmpstr;
            m_cs.lock();
            if (Grpc_Getstream())
                m_stream->Write(rawData);
            m_cs.unlock();
        }
    }
    cout << "SystemDriver Enum Success" << endl;
}
break;
*/