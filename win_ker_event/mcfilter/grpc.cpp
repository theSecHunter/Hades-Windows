#include "grpc.h"

#include "ArkSsdt.h"
#include "ArkIdt.h"
#include "ArkDpcTimer.h"
#include "ArkFsd.h"
#include "ArkMouseKeyBoard.h"
#include "ArkNetwork.h"
#include "ArkProcessInfo.h"
#include "AkrSysDriverDevInfo.h"

#include "sysinfo.h"
#include <time.h>
#include <winsock.h>
#include <map>

static ArkSsdt				g_grpc_ssdtobj;
static ArkIdt				g_grpc_idtobj;
static ArkDpcTimer			g_grpc_dpcobj;
static ArkFsd				g_grpc_fsdobj;
static ArkMouseKeyBoard		g_grpc_mousekeyboardobj;
static ArkNetwork			g_grpc_networkobj;
static ArkProcessInfo		g_grpc_processinfo;
static AkrSysDriverDevInfo	g_grpc_sysmodinfo;

using namespace std;

bool Grpc::Grpc_Transfer(RawData rawData)
{
    Status status;
    ClientContext context;
    // Write Server Msg
    bool nRet = false;
    if(Grpc_Getstream())
        nRet = m_stream->Write(rawData);
    if (false == nRet)
    {
        cout << "Write Buffer Error" << endl;
        return false;
    }

    return true;
}

bool Choose_mem(char*& ptr, DWORD64& dwAllocateMemSize, const int code)
{
    switch (code)
    {
    case NF_SSDT_ID:
    {
        OutputDebugString(L"Entry NF_SSDT_ID");
        dwAllocateMemSize = sizeof(SSDTINFO) * 0x200;
    }
    break;
    case NF_IDT_ID:
    {
        dwAllocateMemSize = sizeof(IDTINFO) * 0x100;
    }
    break;
    case NF_DPC_ID:
    {
        dwAllocateMemSize = sizeof(DPC_TIMERINFO) * 0x200;
    }
    break;
    case NF_FSD_ID:
    {
        dwAllocateMemSize = sizeof(ULONGLONG) * 0x1b * 2 + 1;
    }
    break;
    case NF_MOUSEKEYBOARD_ID:
    {
        dwAllocateMemSize = sizeof(ULONGLONG) * 0x1b * 3 + 1;
    }
    break;
    case NF_NETWORK_ID:
    {
        dwAllocateMemSize = sizeof(SYSNETWORKINFONODE);
    }
    break;
    case NF_PROCESS_ENUM:
    {
        dwAllocateMemSize = sizeof(HANDLE_INFO) * 1024 * 2;
    }
    break;
    case NF_PROCESS_MOD:
    {
        dwAllocateMemSize = sizeof(PROCESS_MOD) * 1024 * 2;
    }
    break;
    case NF_PROCESS_KILL:
    {
        dwAllocateMemSize = 1;
    }
    break;
    case NF_SYSMOD_ENUM:
    {
        dwAllocateMemSize = sizeof(NOTIFY_INFO) * 0x100 + sizeof(MINIFILTER_INFO) * 1000 + 100;
    }
    break;
    case NF_EXIT:
    {
        dwAllocateMemSize = 1;
    }
    break;
    default:
        return false;
    }

    if (0 == dwAllocateMemSize)
        return false;

    ptr = new char[dwAllocateMemSize];
    if (ptr)
    {
        RtlSecureZeroMemory(ptr, dwAllocateMemSize);
        OutputDebugString(L"ptr NF_SSDT_ID Success");
        return true;
    }

    return false;
}
void Wchar_tToString(std::string& szDst, wchar_t* wchar)
{
    wchar_t* wText = wchar;
    DWORD dwNum = WideCharToMultiByte(CP_OEMCP, NULL, wText, -1, NULL, 0, NULL, FALSE);//WideCharToMultiByte的运用
    char* psText;  // psText为char*的临时数组，作为赋值给std::string的中间变量
    psText = new char[dwNum];
    WideCharToMultiByte(CP_OEMCP, NULL, wText, -1, psText, dwNum, NULL, FALSE);//WideCharToMultiByte的再次运用
    szDst = psText;// std::string赋值
    delete[]psText;// psText的清除
}

void Grpc::Grpc_ReadDispatchHandle(Command& command)
{
    map<int, wstring>::iterator iter;
    map<int, wstring> Process_list;
    string tmpstr; wstring catstr;
    int i = 0, index = 0;

    DWORD64 dwAllocateMemSize = 0;
    int code = command.agentctrl();
    char* ptr_Getbuffer;
    bool nstatus = Choose_mem(ptr_Getbuffer, dwAllocateMemSize, code);
    if (false == nstatus || nullptr == ptr_Getbuffer || dwAllocateMemSize == 0)
        return;

    // Send Raw to Server
    ::proto::RawData rawData;
    ::proto::Record* pkg = rawData.add_pkg();
    if (!pkg)
    {
        if (ptr_Getbuffer)
        {
            delete[] ptr_Getbuffer;
            ptr_Getbuffer = nullptr;
        }
    }

    auto MapMessage = pkg->mutable_message();
    if (!MapMessage)
    {
        if (ptr_Getbuffer)
        {
            delete[] ptr_Getbuffer;
            ptr_Getbuffer = nullptr;
        }
    }

    (*MapMessage)["data_type"] = to_string(code);
    switch (code)
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
                (*MapMessage)["win_rootkit_ssdt_id"] = to_string(ssdtinfo[i].ssdt_id);
                (*MapMessage)["win_rootkit_ssdt_offsetaddr"] = to_string(ssdtinfo[i].sstd_memoffset);
                if (Grpc_Getstream())
                    m_stream->Write(rawData);				
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
                if (Grpc_Getstream())
                    m_stream->Write(rawData);
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
            if (Grpc_Getstream())
                m_stream->Write(rawData);
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
            if (Grpc_Getstream())
                m_stream->Write(rawData);
            index++;
        }
        cout << "FastFat MjFuction End" << endl;

        (*MapMessage)["win_rootkit_is_fsdmod"] = "2";
        for (i = 0; i < 0x1b; ++i)
        {
            (*MapMessage)["win_rootkit_fsdntfs_id"] = to_string(MjAddrArry[index]);
            (*MapMessage)["win_rootkit_fsdntfs_mjaddr"] = to_string(MjAddrArry[index]);
            if (Grpc_Getstream())
                m_stream->Write(rawData);
            index++;
        }
        cout << "Ntfs MjFuction End" << endl;
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
            if (Grpc_Getstream())
                m_stream->Write(rawData);
            index++;
        }
        cout << "Mouse MjFuction End" << endl;

        (*MapMessage)["win_rootkit_is_mousekeymod"] = "2";
        for (i = 0; i < 0x1b; ++i)
        {
            (*MapMessage)["win_rootkit_i8042_id"] = to_string(MjAddrArry[index]);
            (*MapMessage)["win_rootkit_i8042_mjaddr"] = to_string(MjAddrArry[index]);
            if (Grpc_Getstream())
                m_stream->Write(rawData);
            index++;
        }
        cout << "i8042 MjFuction End" << endl;

        (*MapMessage)["win_rootkit_is_mousekeymod"] = "3";
        for (i = 0; i < 0x1b; ++i)
        {
            (*MapMessage)["win_rootkit_kbd_id"] = to_string(MjAddrArry[index]);
            (*MapMessage)["win_rootkit_kbd_mjaddr"] = to_string(MjAddrArry[index]);
            if (Grpc_Getstream())
                m_stream->Write(rawData);
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

            if (Grpc_Getstream())
                m_stream->Write(rawData);
        }
        cout << "Tpc Port Send Grpc Success" << endl;

        (*MapMessage)["win_rootkit_is_mod"] = "2";
        for (i = 0; i < networkinfo->udpcout; ++i)
        {
            (*MapMessage)["win_rootkit_udp_pid"] = to_string(networkinfo->sysudpinfo[i].processinfo.dwUdpProId);
            (*MapMessage)["win_rootkit_udp_localIp_port"] = to_string(networkinfo->sysudpinfo[i].UdpTable.dwIP) + ":" + to_string(ntohs(networkinfo->sysudpinfo[i].UdpTable.Port));
            if (Grpc_Getstream())
                m_stream->Write(rawData);
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
                // 去重
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

                if (Grpc_Getstream())
                    m_stream->Write(rawData);
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
        // 默认测试
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

                if (Grpc_Getstream())
                    m_stream->Write(rawData);
            }
        }
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
                if (Grpc_Getstream())
                    m_stream->Write(rawData);
            }
        }
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