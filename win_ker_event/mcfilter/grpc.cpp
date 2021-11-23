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

void Grpc::Grpc_ReadDispatchHandle(Command& command)
{
    DWORD64 dwAllocateMemSize = 0;
    int code = command.agentctrl();
    char* ptr_Getbuffer;
    bool nstatus = Choose_mem(ptr_Getbuffer, dwAllocateMemSize, code);
    printf("0x%p:%d", ptr_Getbuffer, dwAllocateMemSize);
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

    switch (code)
    {
    case NF_SSDT_ID:
    {
        if (g_grpc_ssdtobj.nf_init())
        {
            // Get Sys Current Mem Ssdt Info
            if (false == g_grpc_ssdtobj.nf_GetSysCurrentSsdtData((LPVOID)ptr_Getbuffer, dwAllocateMemSize))
                break;

            (*MapMessage)["data_type"] = to_string(code);
            SSDTINFO* ssdtinfo = (SSDTINFO*)ptr_Getbuffer;
            if (!ssdtinfo)
                break;
            	
            cout << "SystemCurrent Ssdt Info:" << endl;
            int i = 0;
            for (i = 0; i < 0x200; ++i)
            {
            	if (!ssdtinfo[i].sstd_memoffset)
            		break;

                (*MapMessage)["win_rootkit_ssdt_id"] = to_string(ssdtinfo[i].ssdt_id);
                (*MapMessage)["win_rootkit_ssdt_offsetaddr"] = to_string(ssdtinfo[i].sstd_memoffset);
                if (Grpc_Getstream())
                    m_stream->Write(rawData);				
            	cout << hex << "Index: " << ssdtinfo[i].ssdt_id << " - offset: " << ssdtinfo[i].sstd_memoffset << " - SsdtAddr: " << ssdtinfo[i].sstd_memaddr << endl;
            }
            cout << "SystemCurrent Ssdt End:" << endl;
            break;
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