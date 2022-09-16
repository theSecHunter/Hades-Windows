#include "umsginterface.h"
#include "kmsginterface.h"
#include "NamedPipe.h"
#include "AnonymousPipe.h"

#include <sysinfo.h>
#include <winsock.h>
#include <map>
#include <queue>
#include <mutex>
#include <iostream>
#include <memory>
#include <string>
#include <vector>
#include <time.h>
#include <functional>
#include <atlstr.h>

#include "DataHandler.h"
#include "DriverManager.h"
#include "transfer.pb.h"

static bool                         g_shutdown = false;
static mutex                        g_pipwritecs;
static LPVOID                       g_user_interface = nullptr;
static LPVOID                       g_kern_interface = nullptr;

// gloable UserSubQueue
static std::queue<std::shared_ptr<USubNode>>    g_Etw_SubQueue_Ptr;
static std::mutex                               g_Etw_QueueCs_Ptr;
static HANDLE                                   g_Etw_Queue_Event = nullptr;

// gloable KernSubQueue
static std::queue<std::shared_ptr<USubNode>>    g_Ker_SubQueue_Ptr;
static std::mutex                               g_Ker_QueueCs_Ptr;
static HANDLE                                   g_Ker_Queue_Event = nullptr;

// ExitEvent
static HANDLE                                   g_ExitEvent;

// NamedPip|Anonymous
const std::wstring PIPE_HADESWIN_NAME = L"\\\\.\\Pipe\\HadesPipe";
std::shared_ptr<NamedPipe> g_namedpipe = nullptr;
std::shared_ptr<AnonymousPipe> g_anonymouspipe = nullptr;

// Drivers
static DriverManager		g_DrvManager;
const std::wstring			g_drverName = L"sysmondriver";

void GetOSVersion(std::string& strOSVersion, int& verMajorVersion, int& verMinorVersion, bool& Is64)
{
    try
    {
        CStringA tmpbuffer;
        std::string str;
        OSVERSIONINFOEX osvi;
        SYSTEM_INFO si;
        BOOL bOsVersionInfoEx;

        ZeroMemory(&si, sizeof(SYSTEM_INFO));
        ZeroMemory(&osvi, sizeof(OSVERSIONINFOEX));

        osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
        if (!(bOsVersionInfoEx = GetVersionEx((OSVERSIONINFO*)&osvi)))
        {
            osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
            GetVersionEx((OSVERSIONINFO*)&osvi);
        }

        GetProcAddress(GetModuleHandle(TEXT("kernel32.dll")), "GetNativeSystemInfo");
        GetSystemInfo(&si);
        verMajorVersion = osvi.dwMajorVersion;
        verMinorVersion = osvi.dwMinorVersion;
        switch (osvi.dwPlatformId)
        {
        case VER_PLATFORM_WIN32_NT:
            if (osvi.dwMajorVersion == 6 && osvi.dwMinorVersion == 2)
            {
                str = "Windows 10 ";
            }
            if (osvi.dwMajorVersion == 6 && osvi.dwMinorVersion == 1)
            {
                str = "Windows 7 ";
            }
            if (osvi.dwMajorVersion == 6 && osvi.dwMinorVersion == 0)
            {
                if (osvi.wProductType == VER_NT_WORKSTATION)
                {
                    str = "Windows Vista ";
                }
                else
                {
                    str = "Windows Server \"Longhorn\" ";
                }
            }
            if (osvi.dwMajorVersion == 5 && osvi.dwMinorVersion == 2)
            {
                if (GetSystemMetrics(SM_SERVERR2))
                {
                    str = "Microsoft Windows Server 2003 \"R2\" ";
                }
                else if (osvi.wProductType == VER_NT_WORKSTATION &&
                    si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64)
                {
                    str = "Microsoft Windows XP Professional x64 Edition ";
                }
                else
                {
                    str = "Microsoft Windows Server 2003, ";
                }
            }
            if (osvi.dwMajorVersion == 5 && osvi.dwMinorVersion == 1)
            {
                str = "Microsoft Windows XP ";
            }
            if (osvi.dwMajorVersion == 5 && osvi.dwMinorVersion == 0)
            {
                str = "Microsoft Windows 2000 ";
            }
            if (osvi.dwMajorVersion <= 4)
            {
                str = "Microsoft Windows NT ";
            }

            // Test for specific product on Windows NT 4.0 SP6 and later.  
            if (bOsVersionInfoEx)
            {
                //tmpbuffer.Format("Service Pack %d", osvi.wServicePackMajor);
                //strServiceVersion = tmpbuffer.GetBuffer();
                // Test for the workstation type.  
                if (osvi.wProductType == VER_NT_WORKSTATION &&
                    si.wProcessorArchitecture != PROCESSOR_ARCHITECTURE_AMD64)
                {
                    if (osvi.dwMajorVersion == 4)
                        str = str + "Workstation 4.0";
                    else if (osvi.wSuiteMask & VER_SUITE_PERSONAL)
                        str = str + "Home Edition";
                    else str = str + "Professional";
                }

                // Test for the server type.  
                else if (osvi.wProductType == VER_NT_SERVER ||
                    osvi.wProductType == VER_NT_DOMAIN_CONTROLLER)
                {
                    if (osvi.dwMajorVersion == 5 && osvi.dwMinorVersion == 2)
                    {
                        if (si.wProcessorArchitecture ==
                            PROCESSOR_ARCHITECTURE_IA64)
                        {
                            if (osvi.wSuiteMask & VER_SUITE_DATACENTER)
                                str = str + "Datacenter Edition for Itanium-based Systems";
                            else if (osvi.wSuiteMask & VER_SUITE_ENTERPRISE)
                                str = str + "Enterprise Edition for Itanium-based Systems";
                        }

                        else if (si.wProcessorArchitecture ==
                            PROCESSOR_ARCHITECTURE_AMD64)
                        {
                            if (osvi.wSuiteMask & VER_SUITE_DATACENTER)
                                str = str + "Datacenter x64 Edition ";
                            else if (osvi.wSuiteMask & VER_SUITE_ENTERPRISE)
                                str = str + "Enterprise x64 Edition ";
                            else str = str + "Standard x64 Edition ";
                        }

                        else
                        {
                            if (osvi.wSuiteMask & VER_SUITE_DATACENTER)
                                str = str + "Datacenter Edition ";
                            else if (osvi.wSuiteMask & VER_SUITE_ENTERPRISE)
                                str = str + "Enterprise Edition ";
                            else if (osvi.wSuiteMask & VER_SUITE_BLADE)
                                str = str + "Web Edition ";
                            else str = str + "Standard Edition ";
                        }
                    }
                    else if (osvi.dwMajorVersion == 5 && osvi.dwMinorVersion == 0)
                    {
                        if (osvi.wSuiteMask & VER_SUITE_DATACENTER)
                            str = str + "Datacenter Server ";
                        else if (osvi.wSuiteMask & VER_SUITE_ENTERPRISE)
                            str = str + "Advanced Server ";
                        else str = str + "Server ";
                    }
                    else  // Windows NT 4.0   
                    {
                        if (osvi.wSuiteMask & VER_SUITE_ENTERPRISE)
                            str = str + "Server 4.0, Enterprise Edition ";
                        else str = str + "Server 4.0 ";
                    }
                }
            }
            // Test for specific product on Windows NT 4.0 SP5 and earlier  
            else
            {
                HKEY hKey;
                TCHAR szProductType[256];
                DWORD dwBufLen = 256 * sizeof(TCHAR);
                LONG lRet;

                lRet = RegOpenKeyEx(HKEY_LOCAL_MACHINE,
                    L"SYSTEM\\CurrentControlSet\\Control\\ProductOptions", 0, KEY_QUERY_VALUE, &hKey);
                if (lRet != ERROR_SUCCESS)
                    strOSVersion = str;
                return;

                lRet = RegQueryValueEx(hKey, TEXT("ProductType"),
                    NULL, NULL, (LPBYTE)szProductType, &dwBufLen);
                RegCloseKey(hKey);

                if ((lRet != ERROR_SUCCESS) ||
                    (dwBufLen > 256 * sizeof(TCHAR)))
                    strOSVersion = str;
                return;

                if (lstrcmpi(TEXT("WINNT"), szProductType) == 0)
                    str = str + "Workstation ";
                if (lstrcmpi(TEXT("LANMANNT"), szProductType) == 0)
                    str = str + "Server ";
                if (lstrcmpi(TEXT("SERVERNT"), szProductType) == 0)
                    str = str + "Advanced Server ";
                tmpbuffer.Format("%d.%d ", osvi.dwMajorVersion, osvi.dwMinorVersion);
                str = tmpbuffer.GetString();
            }

            // Display service pack (if any) and build number.  

            if (osvi.dwMajorVersion == 4 &&
                lstrcmpi(osvi.szCSDVersion, L"Service Pack 6") == 0)
            {
                HKEY hKey;
                LONG lRet;

                // Test for SP6 versus SP6a.  
                lRet = RegOpenKeyEx(HKEY_LOCAL_MACHINE,
                    L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Hotfix\\Q246009", 0, KEY_QUERY_VALUE, &hKey);
                if (lRet == ERROR_SUCCESS)
                {
                    tmpbuffer.Format(("Service Pack 6a (Build %d)\n"), osvi.dwBuildNumber & 0xFFFF);
                    str = tmpbuffer.GetBuffer();
                }
                else // Windows NT 4.0 prior to SP6a  
                {
                    _tprintf(TEXT("%s (Build %d)\n"),
                        osvi.szCSDVersion,
                        osvi.dwBuildNumber & 0xFFFF);
                }

                RegCloseKey(hKey);
            }
            else // not Windows NT 4.0   
            {
                _tprintf(TEXT("%s (Build %d)\n"),
                    osvi.szCSDVersion,
                    osvi.dwBuildNumber & 0xFFFF);
            }

            break;

            // Test for the Windows Me/98/95.  
        case VER_PLATFORM_WIN32_WINDOWS:

            if (osvi.dwMajorVersion == 4 && osvi.dwMinorVersion == 0)
            {
                str = "Microsoft Windows 95 ";
                if (osvi.szCSDVersion[1] == 'C' || osvi.szCSDVersion[1] == 'B')
                    str = str + "OSR2 ";
            }
            if (osvi.dwMajorVersion == 4 && osvi.dwMinorVersion == 10)
            {
                str = "Microsoft Windows 98 ";
                if (osvi.szCSDVersion[1] == 'A' || osvi.szCSDVersion[1] == 'B')
                    str = str + "SE ";
            }
            if (osvi.dwMajorVersion == 4 && osvi.dwMinorVersion == 90)
            {
                str = "Microsoft Windows Millennium Edition\n";
            }
            break;

        case VER_PLATFORM_WIN32s:
            str = "Microsoft Win32s\n";
            break;
        default:
            break;
        }

        GetNativeSystemInfo(&si);
        if (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64 ||
            si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_IA64)
        {
            Is64 = true;
            str += " x64";
        }
        else
        {
            Is64 = false;
            str += " x32";
        }

        strOSVersion = str;
    }
    catch (const std::exception&)
    {
    }
}
// 检测驱动是否安装
bool DrvCheckStart()
{
    std::wstring pszCmd = L"sc start sysmondriver";
    STARTUPINFO si = { sizeof(STARTUPINFO) };
    int nSeriverstatus = g_DrvManager.nf_GetServicesStatus(g_drverName.c_str());
    switch (nSeriverstatus)
    {
        // 正在运行
    case SERVICE_CONTINUE_PENDING:
    case SERVICE_RUNNING:
    case SERVICE_START_PENDING:
    {
        OutputDebugString(L"Driver Running");
        break;
    }
    break;
    // 已安装 - 未运行
    case SERVICE_STOPPED:
    case SERVICE_STOP_PENDING:
    {
        GetStartupInfo(&si);
        si.dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;
        si.wShowWindow = SW_HIDE;
        // 启动命令行
        PROCESS_INFORMATION pi;
        CreateProcess(NULL, (LPWSTR)pszCmd.c_str(), NULL, NULL, TRUE, NULL, NULL, NULL, &si, &pi);
        Sleep(3000);
        nSeriverstatus = g_DrvManager.nf_GetServicesStatus(g_drverName.c_str());
        if (SERVICE_RUNNING == nSeriverstatus)
        {
            OutputDebugString(L"sc Driver Running");
            break;
        }
        else
        {
            OutputDebugString(L"sc Driver Install Failuer");
            return false;
        }
    }
    break;
    case 0x424:
    {
        // 仅未安装驱动的时候提醒
        const int nret = MessageBox(NULL, L"开启内核采集需要安装驱动，系统并未安装\n示例驱动没有签名,请自行打签名或者关闭系统驱动签名认证安装.\n是否进行驱动安装开启内核态采集\n", L"提示", MB_OKCANCEL | MB_ICONWARNING);
        if (nret == 1)
        {
            wchar_t output[MAX_PATH] = { 0, };
            std::string verkerlinfo;
            int verMajorVersion;
            int verMinorVersion;
            bool Is64;
            GetOSVersion(verkerlinfo, verMajorVersion, verMinorVersion, Is64);
            if (!g_DrvManager.nf_DriverInstall_Start(verMajorVersion, verMinorVersion, Is64))
            {
                MessageBox(NULL, L"驱动安装失败，请您手动安装再次开启内核态采集", L"提示", MB_OKCANCEL);
                return false;
            }
        }
        else
            return false;
    }
    break;
    default:
        return false;
    }

    return true;
}

DataHandler::DataHandler()
{
}
DataHandler::~DataHandler() 
{
}

// 管道写
bool PipWriteAnonymous(std::string& serializbuf, const int datasize)
{
    /*
    * |---------------------------------
    * | Serializelengs|  SerializeBuf  |
    * |---------------------------------
    * |   4 byte      |    xxx byte    |
    * |---------------------------------
    */
    {
        std::lock_guard<std::mutex> lock{ g_pipwritecs };
        const int sendlens = datasize + sizeof(uint32_t);
        std::shared_ptr<uint8_t> data{ new uint8_t[sendlens] };
        *(uint32_t*)(data.get()) = datasize;
        ::memcpy(data.get() + 0x4, serializbuf.c_str(), datasize);
        if (g_anonymouspipe)
            g_anonymouspipe->write(data, sendlens);
    }

    return true;
}

// 设置主程序退出Event
void DataHandler::SetExitSvcEvent(HANDLE & hexitEvent)
{
    g_ExitEvent = hexitEvent;
}

// Task Handler
DWORD WINAPI DataHandler::PTaskHandlerNotify(LPVOID lpThreadParameter)
{
    if (!lpThreadParameter || g_shutdown)
        return 0;

    std::vector<std::string> task_array_data;
    task_array_data.clear();

    // Driver Install Check 
    const int taskid = (DWORD)lpThreadParameter;
    if ((403 <= taskid) && (406 >= taskid))
        DrvCheckStart();

    if (taskid == 188)
    {
        if(g_ExitEvent)
            SetEvent(g_ExitEvent);
        CloseHandle(g_ExitEvent);
    }
    else if ((taskid >= 100) && (taskid < 200))
        ((kMsgInterface*)g_kern_interface)->kMsg_taskPush(taskid, task_array_data);
    else if ((taskid >= 200) && (taskid < 300))
        ((uMsgInterface*)g_user_interface)->uMsg_taskPush(taskid, task_array_data);
    else if (401 == taskid)
    {//用户态开关
        const auto g_ulib = ((uMsgInterface*)g_user_interface);
        if (!g_ulib)
            return 0;
        task_array_data.clear();
        const auto uStatus = g_ulib->GetEtwMonStatus();
        if (false == uStatus)
        {
            g_ulib->uMsg_EtwInit();
            task_array_data.push_back("User_Etw MonitorControl Enable");
        }
        else
            task_array_data.push_back("User_Etw MonitorControl Runing");
    }
    else if (402 == taskid) {
        const auto g_ulib = ((uMsgInterface*)g_user_interface);
        if (!g_ulib)
            return 0;
        task_array_data.clear();
        const auto uStatus = g_ulib->GetEtwMonStatus();
        if (true == uStatus)
        {
            task_array_data.push_back("User_Etw MonitorControl Disable");
            g_ulib->uMsg_EtwClose();
        }
        else
            task_array_data.push_back("User_Etw MonitorControl NotActivated");
    }
    else if (403 == taskid) {
        const auto g_klib = ((kMsgInterface*)g_kern_interface);
        if (!g_klib)
            return 0;
        task_array_data.clear();
        const bool kStatus = g_klib->GetKerMonStatus();
        if (false == g_klib->GetKerInitStatus())
            g_klib->DriverInit(false); // 初始化启动read i/o线程
        else
        {
            if (false == kStatus)
                g_klib->StartReadFileThread();//如果不需要初始化，行为拦截正在工作 - 只启动线程
        }
        if (false == kStatus)
        {
            OutputDebugString(L"[HadesSvc] GetKerMonStatus Send Enable KernelMonitor Command");
            g_klib->OnMonitor();
            task_array_data.push_back("Kernel MonitorControl Enable");
        }
        else
            task_array_data.push_back("Kernel MonitorControl Runing");
    }
    else if (404 == taskid)
    {//内核态开关
        const auto g_klib = ((kMsgInterface*)g_kern_interface);
        if (!g_klib)
            return 0;
        task_array_data.clear();
        const bool kStatus = g_klib->GetKerMonStatus();
        
        if (false == g_klib->GetKerInitStatus())
            g_klib->DriverInit(false); // 初始化启动read i/o线程
        else
        {
            if (false == kStatus)
                g_klib->StartReadFileThread();//如果不需要初始化，行为拦截正在工作 - 只启动线程
        }

        if (true == kStatus)
        {
            OutputDebugString(L"[HadesSvc] GetKerMonStatus Send Disable KernelMonitor Command");
            g_klib->OffMonitor();
            OutputDebugString(L"[HadesSvc] GetKerMonStatus Disable KernelMonitor Success");
            if ((true == g_klib->GetKerInitStatus()) && (false == g_klib->GetKerBeSnipingStatus()))
                g_klib->DriverFree();
            else
                g_klib->StopReadFileThread(); // 开启行为拦截状态下，关闭线程 - 防止下发I/O
        }
    }
    else if (405 == taskid)
    {
        const auto g_klib = ((kMsgInterface*)g_kern_interface);
        if (!g_klib)
            return 0;
        task_array_data.clear();
        if (false == g_klib->GetKerInitStatus())
            g_klib->DriverInit(true);// 初始化不启动read i/o线程
        const bool kStatus = g_klib->GetKerBeSnipingStatus();
        if (false == kStatus)
        {
            OutputDebugString(L"[HadesSvc] OnBeSnipingMonitor Send Enable KernelMonitor Command");
            g_klib->OnBeSnipingMonitor();
            OutputDebugString(L"[HadesSvc] OnBeSnipingMonitor Enable KernelMonitor Success");
        }
    }
    else if (406 == taskid)
    {
        const auto g_klib = ((kMsgInterface*)g_kern_interface);
        if (!g_klib)
            return 0;
        task_array_data.clear();
        if (false == g_klib->GetKerInitStatus())
            g_klib->DriverInit(true);// 初始化不启动read i/o线程
        const bool kStatus = g_klib->GetKerBeSnipingStatus();
        if (true == kStatus)
        {
            OutputDebugString(L"[HadesSvc] OnBeSnipingMonitor Disable Disable KernelMonitor Command");
            g_klib->OffBeSnipingMonitor();
            OutputDebugString(L"[HadesSvc] OnBeSnipingMonitor Disable KernelMonitor Success");
            if ((true == g_klib->GetKerInitStatus()) && (false == g_klib->GetKerMonStatus()))
                g_klib->DriverFree();
        }
    }
    else
        return 0;

    // Write Pip
    {
        size_t coutwrite = 0, idx = 0;
        std::string serializbuf;
        std::shared_ptr<protocol::Record> record = std::make_shared<protocol::Record>();
        if (!record)
            return 0;
        protocol::Payload* PayloadMsg = record->mutable_data();
        if (!PayloadMsg)
            return 0;
        auto MapMessage = PayloadMsg->mutable_fields();
        if (!MapMessage)
            return 0;
        std::mutex crecord_mutex;
        std::lock_guard<std::mutex> lock{ crecord_mutex };
        coutwrite = task_array_data.size();
        record->set_data_type(taskid);
        record->set_timestamp(GetCurrentTime());
        for (idx = 0; idx < coutwrite; ++idx)
        {
            (*MapMessage)["data_type"] = to_string(taskid);
            if (task_array_data[idx].size())
                (*MapMessage)["udata"] = task_array_data[idx]; // json
            else
                (*MapMessage)["udata"] = "error";

            serializbuf = record->SerializeAsString();
            const int datasize = serializbuf.size();
            PipWriteAnonymous(serializbuf, datasize);
            MapMessage->clear();
        }
    }

    task_array_data.clear();
    return 0;
}
// Recv Task
void DataHandler::OnPipMessageNotify(const std::shared_ptr<uint8_t>& data, size_t size)
{
    if (!data && (size <= 1024 && size >= 0))
        return;
    try
    {
        const int isize = *((int*)data.get());
        // 匿名管道不确定因素多，插件下发Task MaxLen <= 1024
        if (isize <= 0 && isize >= 1024)
            return;
        // 反序列化成Task
        protocol::Task pTask;
        pTask.ParseFromString((char*)(data.get() + 0x4));
        const int taskid = pTask.data_type();
        QueueUserWorkItem(DataHandler::PTaskHandlerNotify, (LPVOID)taskid, WT_EXECUTEDEFAULT);
    }
    catch (const std::exception&)
    {
        return;
    }  
}
// Debug interface
void DataHandler::DebugTaskInterface(const int taskid)
{
    QueueUserWorkItem(DataHandler::PTaskHandlerNotify, (PVOID)taskid, WT_EXECUTEDEFAULT);
}

// 内核数据ConSumer
void DataHandler::KerSublthreadProc()
{
    static std::mutex krecord_mutex;
    std::shared_ptr<protocol::Record> record = std::make_shared<protocol::Record>();
    if (!record)
        return;
    static protocol::Payload* PayloadMsg = record->mutable_data();
    if (!PayloadMsg)
        return;
    static auto MapMessage = PayloadMsg->mutable_fields();
    if (!MapMessage)
        return;
    static std::string serializbuf;

    do {
        WaitForSingleObject(g_Ker_Queue_Event, INFINITE);
        if (g_shutdown)
            break;
        do{
            {
                g_Ker_QueueCs_Ptr.lock();
                if (g_Ker_SubQueue_Ptr.empty())
                {
                    g_Ker_QueueCs_Ptr.unlock();
                    break;
                }
                const auto subwrite = g_Ker_SubQueue_Ptr.front();
                g_Ker_SubQueue_Ptr.pop();
                g_Ker_QueueCs_Ptr.unlock();

                krecord_mutex.lock();
                record->set_data_type(subwrite->taskid);
                record->set_timestamp(GetCurrentTime());
                (*MapMessage)["data_type"] = to_string(subwrite->taskid);
                (*MapMessage)["udata"] = subwrite->data->c_str(); // json
                serializbuf = record->SerializeAsString();
                const int datasize = serializbuf.size();
                PipWriteAnonymous(serializbuf, datasize);
                krecord_mutex.unlock();
            }
            MapMessage->clear();
            serializbuf.clear();
        } while (false);

    } while (!g_shutdown);
}
// Etw数据ConSumer
void DataHandler::EtwSublthreadProc()
{
    static std::mutex urecord_mutex;
    static std::shared_ptr<protocol::Record> record = std::make_shared<protocol::Record>();
    if (!record)
        return;
    static protocol::Payload* PayloadMsg = record->mutable_data();
    if (!PayloadMsg)
        return;
    static auto MapMessage = PayloadMsg->mutable_fields();
    if (!MapMessage)
        return;

    static std::string serializbuf;
    do {
        WaitForSingleObject(g_Etw_Queue_Event, INFINITE);
        if (g_shutdown || !record)
            break;

        do {
            {
                g_Etw_QueueCs_Ptr.lock();
                if (g_Etw_SubQueue_Ptr.empty())
                {
                    g_Etw_QueueCs_Ptr.unlock();
                    break;
                }
                const auto subwrite = g_Etw_SubQueue_Ptr.front();
                g_Etw_SubQueue_Ptr.pop();
                g_Etw_QueueCs_Ptr.unlock();

                urecord_mutex.lock();
                record->set_data_type(subwrite->taskid);
                record->set_timestamp(GetCurrentTime());
                (*MapMessage)["data_type"] = to_string(subwrite->taskid);
                (*MapMessage)["udata"] = subwrite->data->c_str(); // json
                serializbuf = record->SerializeAsString();
                const int datasize = serializbuf.size();
                PipWriteAnonymous(serializbuf, datasize);
                urecord_mutex.unlock();
            }
            MapMessage->clear();
            serializbuf.clear();
        } while (false);
    } while (!g_shutdown);
}
static unsigned WINAPI _KerSubthreadProc(void* pData)
{
    (reinterpret_cast<DataHandler*>(pData))->KerSublthreadProc();
    return 0;
}
static unsigned WINAPI _EtwSubthreadProc(void* pData)
{
    (reinterpret_cast<DataHandler*>(pData))->EtwSublthreadProc();
    return 0;
}

// 初始化Pip
bool DataHandler::PipInit()
{
    g_namedpipe = std::make_shared<NamedPipe>();
    g_namedpipe->set_on_read(std::bind(&DataHandler::OnPipMessageNotify, this, std::placeholders::_1, std::placeholders::_2));
    if (!g_namedpipe->init(PIPE_HADESWIN_NAME))
        return false;
    return true;
}
void DataHandler::PipFree()
{
    if (g_namedpipe)
        g_namedpipe->uninit();
}
bool DataHandler::PipInitAnonymous()
{
    g_anonymouspipe = std::make_shared<AnonymousPipe>();
    g_anonymouspipe->set_on_read(std::bind(&DataHandler::OnPipMessageNotify, this, std::placeholders::_1, std::placeholders::_2));
    if (!g_anonymouspipe->initPip())
        return false;
    return true;
}
void DataHandler::PipFreeAnonymous()
{
    if (g_anonymouspipe)
        g_anonymouspipe->uninPip();
}

// 初始化Lib库指针
bool DataHandler::SetUMontiorLibPtr(void* ulibptr)
{
    g_user_interface = ulibptr;
    return g_user_interface ? true : false;
}
bool DataHandler::SetKMontiorLibPtr(void* klibptr)
{
    g_kern_interface = (kMsgInterface*)klibptr;
    return g_kern_interface ? true : false;
}

// 设置ConSumer订阅,初始化队列线程
bool DataHandler::ThreadPool_Init()
{
    g_Ker_Queue_Event = CreateEvent(NULL, FALSE, FALSE, NULL);
    g_Etw_Queue_Event = CreateEvent(NULL, FALSE, FALSE, NULL);
    this->m_jobAvailableEvnet_WriteTask = CreateEvent(NULL, FALSE, FALSE, NULL);
    if (!g_Etw_Queue_Event || !g_Ker_Queue_Event || !m_jobAvailableEvnet_WriteTask)
        return false;

    ((uMsgInterface*)g_user_interface)->uMsg_SetSubEventPtr(g_Etw_Queue_Event);
    ((uMsgInterface*)g_user_interface)->uMsg_SetSubQueueLockPtr(g_Etw_QueueCs_Ptr);
    ((uMsgInterface*)g_user_interface)->uMsg_SetSubQueuePtr(g_Etw_SubQueue_Ptr);

    ((kMsgInterface*)g_kern_interface)->kMsg_SetSubEventPtr(g_Ker_Queue_Event);
    ((kMsgInterface*)g_kern_interface)->kMsg_SetSubQueueLockPtr(g_Ker_QueueCs_Ptr);
    ((kMsgInterface*)g_kern_interface)->kMsg_SetSubQueuePtr(g_Ker_SubQueue_Ptr);

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

    // 处理Kernel上抛
    for (i = 0; i < threadCount; i++)
    {
        hThread = (HANDLE)_beginthreadex(0, 0,
            _KerSubthreadProc,
            (LPVOID)this,
            0,
            &threadId);

        if (hThread != 0 && hThread != (HANDLE)(-1L))
        {
            m_ker_subthreads.push_back(hThread);
        }
    }

    // 处理Uetw上抛
    for (i = 0; i < threadCount; i++)
    {
        hThread = (HANDLE)_beginthreadex(0, 0,
            _EtwSubthreadProc,
            (LPVOID)this,
            0,
            &threadId);

        if (hThread != 0 && hThread != (HANDLE)(-1L))
        {
            m_etw_subthreads.push_back(hThread);
        }
    }

    return true;
}
bool DataHandler::ThreadPool_Free()
{
    // 设置标志
    g_shutdown = true;
    Sleep(100);

    // 循环关闭句柄
    for (tThreads::iterator it = m_ker_subthreads.begin();
        it != m_ker_subthreads.end();
        it++)
    {
        SetEvent(g_Ker_Queue_Event);
        WaitForSingleObject(*it, 1000);
        CloseHandle(*it);
    }


    if (g_Ker_Queue_Event != INVALID_HANDLE_VALUE)
    {
        ::CloseHandle(g_Ker_Queue_Event);
        g_Ker_Queue_Event = INVALID_HANDLE_VALUE;
    }

    for (tThreads::iterator it = m_etw_subthreads.begin();
        it != m_etw_subthreads.end();
        it++)
    {
        SetEvent(g_Etw_Queue_Event);
        WaitForSingleObject(*it, 1000);
        CloseHandle(*it);
    }

    if (g_Etw_Queue_Event != INVALID_HANDLE_VALUE)
    {
        ::CloseHandle(g_Etw_Queue_Event);
        g_Etw_Queue_Event = INVALID_HANDLE_VALUE;
    }

    for (tThreads::iterator it = m_threads_write.begin();
        it != m_threads_write.end();
        it++)
    {
        SetEvent(m_jobAvailableEvnet_WriteTask);
        WaitForSingleObject(*it, 1000);
        CloseHandle(*it);
    }

    if (m_jobAvailableEvnet_WriteTask != INVALID_HANDLE_VALUE)
    {
        ::CloseHandle(m_jobAvailableEvnet_WriteTask);
        m_jobAvailableEvnet_WriteTask = INVALID_HANDLE_VALUE;
    }

    m_ker_subthreads.clear();
    m_etw_subthreads.clear();
    m_threads_write.clear();

    return true;
}
