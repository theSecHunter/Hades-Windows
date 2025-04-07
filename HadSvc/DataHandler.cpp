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
#include "transfer.pb.h"
#include "singGloal.h"
#include "NamedPipe.h"
#include "AnonymousPipe.h"
#include "CodeTool.h"

#include <rapidjson/rapidjson.h>
#include <rapidjson/document.h>
#include <rapidjson/stringbuffer.h>
#include <rapidjson/writer.h>

static bool                         g_shutdown = false;
static mutex                        g_pipwritecs;

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
static const std::wstring PIPE_HADESWIN_NAME = L"\\\\.\\Pipe\\HadesPipe";
static std::shared_ptr<NamedPipe> g_namedpipe = nullptr;
static std::shared_ptr<AnonymousPipe> g_anonymouspipe = nullptr;

// Drivers
static const std::wstring g_drverName = L"sysmondriver";
static const std::wstring g_drverNdrName = L"hadesndr";

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

// 检测安装驱动检测
const bool DataHandler::DrvCheckStatus()
{
    int nSeriverstatus = SingletonDrvManage::instance()->nf_GetServicesStatus(g_drverName.c_str());
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
        PROCESS_INFORMATION pi;
        std::wstring pszCmd = L"sc start sysmondriver";
        STARTUPINFO si = { sizeof(STARTUPINFO) };
        GetStartupInfo(&si);
        si.dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;
        si.wShowWindow = SW_HIDE;
        if (CreateProcess(NULL, (LPWSTR)pszCmd.c_str(), NULL, NULL, TRUE, NULL, NULL, NULL, &si, &pi)) 
        {
            WaitForSingleObject(pi.hProcess, 3000);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
        }
        nSeriverstatus = SingletonDrvManage::instance()->nf_GetServicesStatus(g_drverName.c_str());
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
        std::string strVerkerLinfo = "";
        bool Is64 = false;
        int verMajorVersion = 0;
        int verMinorVersion = 0;
        GetOSVersion(strVerkerLinfo, verMajorVersion, verMinorVersion, Is64);
        if (!SingletonDrvManage::instance()->nf_DriverInstall_SysMonStart(verMajorVersion, verMinorVersion, Is64))
        {
            MessageBox(NULL, L"驱动安装失败，请您手动安装再次开启内核态采集", L"提示", MB_OKCANCEL);
            return false;
        }
    }
    break;
    default:
        return false;
    }

    return true;
}
const bool DataHandler::NetCheckStatus()
{
    int nSeriverstatus = SingletonDrvManage::instance()->nf_GetServicesStatus(g_drverNdrName.c_str());
    switch (nSeriverstatus)
    {
        // 正在运行
    case SERVICE_CONTINUE_PENDING:
    case SERVICE_RUNNING:
    case SERVICE_START_PENDING:
    {
        OutputDebugString(L"[HadesNetMon] Driver Running");
        break;
    }
    break;
    // 已安装 - 未运行
    case SERVICE_STOPPED:
    case SERVICE_STOP_PENDING:
    {
        PROCESS_INFORMATION pi;
        std::wstring pszCmd = L"[HadesNetMon] sc start hadesndr";
        STARTUPINFO si = { sizeof(STARTUPINFO) };
        GetStartupInfo(&si);
        si.dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;
        si.wShowWindow = SW_HIDE;
        if (CreateProcess(NULL, (LPWSTR)pszCmd.c_str(), NULL, NULL, TRUE, NULL, NULL, NULL, &si, &pi))
        {
            WaitForSingleObject(pi.hProcess, 3000);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
        }
        nSeriverstatus = SingletonDrvManage::instance()->nf_GetServicesStatus(g_drverNdrName.c_str());
        if (SERVICE_RUNNING == nSeriverstatus)
        {
            OutputDebugString(L"[HadesNetMon] sc Driver Running");
            break;
        }
        else
        {
            OutputDebugString(L"[HadesNetMon] sc Driver Install Failuer");
            return false;
        }
    }
    break;
    case 0x424:
    {
        std::string strVerkerLinfo = "";
        bool Is64 = false;
        int verMajorVersion = 0;
        int verMinorVersion = 0;
        GetOSVersion(strVerkerLinfo, verMajorVersion, verMinorVersion, Is64);
        if (!SingletonDrvManage::instance()->nf_DriverInstall_NetMonStart(verMajorVersion, verMinorVersion, Is64))
        {
            MessageBox(NULL, L"流量驱动安装失败，请您手动安装.", L"提示", MB_OKCANCEL);
            return false;
        }
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
inline bool PipWriteAnonymous(std::string& serializbuf, const int datasize)
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
        const int sendlens = datasize + sizeof(uint32_t) + 1;
        std::shared_ptr<uint8_t> data{ new uint8_t[sendlens] };
        if (data) {
            memset(data.get(), 0, sendlens);
            *(uint32_t*)(data.get()) = datasize;
            ::memcpy(data.get() + 0x4, serializbuf.c_str(), datasize);
            if (g_anonymouspipe)
                g_anonymouspipe->write(data, sendlens);
        }
    }

    return true;
}

// 设置主程序退出Event
void DataHandler::SetExitSvcEvent(HANDLE & hexitEvent)
{
    g_ExitEvent = hexitEvent;
}

// Hboat Server Task Handler
bool DataHandler::PTaskHandlerNotify(const DWORD taskid)
{
    std::vector<std::string> task_array_data;
    task_array_data.clear();

    if ((taskid >= 403) && (taskid <= 410))
    {
        if (!DrvCheckStatus())
            return false;
    }
    else if ((taskid >= 411) && (taskid <= 413)) {
        NetCheckStatus();
    }

    if (taskid == 188)
    {
        if (g_ExitEvent)
        {
            SetEvent(g_ExitEvent);
            CloseHandle(g_ExitEvent);
            task_array_data.push_back("Success!");
        }
        else
            task_array_data.push_back("Failuer!");
    }
    else if ((taskid >= 100) && (taskid < 200))
        SingletonKerMon::instance()->kMsg_taskPush(taskid, task_array_data);
    else if ((taskid >= 200) && (taskid < 300))
        SingletonUMon::instance()->uMsg_taskPush(taskid, task_array_data);
    else
    {
        switch (taskid)
        {
        case 401:
        {// Etw采集开启
            task_array_data.clear();
            const auto uStatus = SingletonUMon::instance()->GetEtwMonStatus();
            if (false == uStatus)
            {
                SingletonUMon::instance()->uMsg_EtwInit();
                task_array_data.push_back("Success");
            }
        }
        break;
        case 402:
        {// Etw采集关闭
            task_array_data.clear();
            const auto uStatus = SingletonUMon::instance()->GetEtwMonStatus();
            if (true == uStatus)
            {
                SingletonUMon::instance()->uMsg_EtwClose();
                task_array_data.push_back("Success");
            }
        }
        break;
        case 403:
        {// 内核态采集开启
            task_array_data.clear();
            if (false == SingletonKerMon::instance()->GetKerInitStatus())
            {
                SingletonKerMon::instance()->DriverInit(false); // 初始化启动read i/o线程
                if (false == SingletonKerMon::instance()->GetKerInitStatus())
                {
                    OutputDebugString(L"GetKerInitStatus false");
                    return 0;
                }
            }
            const bool kStatus = SingletonKerMon::instance()->GetKerMonStatus();
            if (false == kStatus)
            {
                OutputDebugString(L"[HadesSvc] GetKerMonStatus Send Enable KernelMonitor Command");
                SingletonKerMon::instance()->OnMonitor();
                OutputDebugString(L"[HadesSvc] GetKerMonStatus Enable KernelMonitor Success");
                // 开启Read IO Thread
                SingletonKerMon::instance()->StartReadFileThread();
                task_array_data.push_back("Success");
            }
        }
        break;
        case 404:
        {// 内核态采集关闭
            task_array_data.clear();
            if (false == SingletonKerMon::instance()->GetKerInitStatus())
                return 0;
            const bool kStatus = SingletonKerMon::instance()->GetKerMonStatus();
            if (true == kStatus)
            {
                OutputDebugString(L"[HadesSvc] GetKerMonStatus Send Disable KernelMonitor Command");
                SingletonKerMon::instance()->OffMonitor();
                OutputDebugString(L"[HadesSvc] GetKerMonStatus Disable KernelMonitor Success");
                // 行为拦截没开启，关闭驱动句柄
                if ((true == SingletonKerMon::instance()->GetKerInitStatus()) && (false == SingletonKerMon::instance()->GetKerBeSnipingStatus()))
                    SingletonKerMon::instance()->DriverFree();
                else
                    SingletonKerMon::instance()->StopReadFileThread(); // 开启行为拦截状态下，关闭线程 - 防止下发I/O
                task_array_data.push_back("Success");
            }
        }
        break;
        case 405:
        {// 行为监控开启
            task_array_data.clear();
            if (false == SingletonKerMon::instance()->GetKerInitStatus())
            {
                SingletonKerMon::instance()->DriverInit(true);
                if (false == SingletonKerMon::instance()->GetKerInitStatus())
                {
                    OutputDebugString(L"[HadesSvc] GetKerInitStatus false");
                    return 0;
                }
            }
            const bool kStatus = SingletonKerMon::instance()->GetKerBeSnipingStatus();
            if (false == kStatus)
            {
                OutputDebugString(L"[HadesSvc] OnBeSnipingMonitor Send Enable KernelMonitor Command");
                SingletonKerMon::instance()->OnBeSnipingMonitor();
                OutputDebugString(L"[HadesSvc] OnBeSnipingMonitor Enable KernelMonitor Success");
                task_array_data.push_back("Success");
            }
        }
        break;
        case 406:
        {// 行为监控关闭
            task_array_data.clear();
            if (false == SingletonKerMon::instance()->GetKerInitStatus())
                return 0;
            const bool kStatus = SingletonKerMon::instance()->GetKerBeSnipingStatus();
            if (true == kStatus)
            {
                OutputDebugString(L"[HadesSvc] OnBeSnipingMonitor Disable Disable KernelMonitor Command");
                SingletonKerMon::instance()->OffBeSnipingMonitor();
                OutputDebugString(L"[HadesSvc] OnBeSnipingMonitor Disable KernelMonitor Success");
                if ((true == SingletonKerMon::instance()->GetKerInitStatus()) && (false == SingletonKerMon::instance()->GetKerMonStatus()))
                    SingletonKerMon::instance()->DriverFree();
                task_array_data.push_back("Success");
            }
        }
        break;
        case 407:
        {// 进程规则重载
            task_array_data.clear();
            // 驱动未启动
            if (false == SingletonKerMon::instance()->GetKerInitStatus())
                return 0;
            const int ioldStatus = SingletonKerMon::instance()->GetKerBeSnipingStatus();
            OutputDebugString(L"[HadesSvc] ReLoadProcessRuleConfig Send Enable KernelMonitor Command");
            SingletonKerMon::instance()->ReLoadProcessRuleConfig();
            OutputDebugString(L"[HadesSvc] ReLoadProcessRuleConfig Enable KernelMonitor Success");
            // 规则重载内核会关闭行为监控 - 如果之前开启这里要重新开启
            if (ioldStatus)
                SingletonKerMon::instance()->OnBeSnipingMonitor();
            task_array_data.push_back("Success");
        }
        break;
        case 408:
        {// 注册表规则重载
            task_array_data.clear();
            // 驱动未启动
            if (false == SingletonKerMon::instance()->GetKerInitStatus())
                return 0;
            const int ioldStatus = SingletonKerMon::instance()->GetKerBeSnipingStatus();
            OutputDebugString(L"[HadesSvc] ReLoadRegisterRuleConfig Send Enable KernelMonitor Command");
            SingletonKerMon::instance()->ReLoadRegisterRuleConfig();
            OutputDebugString(L"[HadesSvc] ReLoadRegisterRuleConfig Enable KernelMonitor Success");
            // 规则重载内核会关闭行为监控 - 如果之前开启这里要重新开启
            if (ioldStatus)
                SingletonKerMon::instance()->OnBeSnipingMonitor();
            task_array_data.push_back("Success");
        }
        break;
        case 409:
        {// 目录规则重载
            task_array_data.clear();
            // 驱动未启动
            if (false == SingletonKerMon::instance()->GetKerInitStatus())
                return 0;
            const int ioldStatus = SingletonKerMon::instance()->GetKerBeSnipingStatus();
            OutputDebugString(L"[HadesSvc] ReLoadDirectoryRuleConfig Send Enable KernelMonitor Command");
            SingletonKerMon::instance()->ReLoadDirectoryRuleConfig();
            OutputDebugString(L"[HadesSvc] ReLoadDirectpryRuleConfig Enable KernelMonitor Success");
            // 规则重载内核会关闭行为监控 - 如果之前开启这里要重新开启
            if (ioldStatus)
                SingletonKerMon::instance()->OnBeSnipingMonitor();
            task_array_data.push_back("Success");
        }
        break;
        case 410:
        {// 线程注入规则
            task_array_data.clear();
            // 驱动未启动
            if (false == SingletonKerMon::instance()->GetKerInitStatus())
                return 0;
            const int ioldStatus = SingletonKerMon::instance()->GetKerBeSnipingStatus();
            OutputDebugString(L"[HadesSvc] ReLoadThreadInjectRuleConfig Send Enable KernelMonitor Command");
            SingletonKerMon::instance()->ReLoadThreadInjectRuleConfig();
            OutputDebugString(L"[HadesSvc] ReLoadThreadInjectRuleConfig Enable KernelMonitor Success");
            // 规则重载内核会关闭行为监控 - 如果之前开启这里要重新开启
            if (ioldStatus)
                SingletonKerMon::instance()->OnBeSnipingMonitor();
            task_array_data.push_back("Success");
        }
        break;

#ifdef _X64
        case 411:
        {// 网络主防开启
            SingletonKNetWork::instance()->ReLoadIpPortConnectRule();
            if (SingletonDataHandler::instance()->NetCheckStatus()) {
                if (!SingletonKNetWork::instance()->GetNetNdrStus())
                    SingletonKNetWork::instance()->NetNdrInit();
            }      
        }
        break;
        case 412:
        {// 网络主防关闭
            if (SingletonDataHandler::instance()->NetCheckStatus()) {
                if (SingletonKNetWork::instance()->GetNetNdrStus())
                    SingletonKNetWork::instance()->NetNdrClose();
            }
        }
        break;
        case 413:
        {// 网路规则重载
            task_array_data.clear();
            OutputDebugString(L"[HadesSvc] ReLoadIpPortConnectRule Send Enable KernelMonitor Command");
            SingletonKNetWork::instance()->ReLoadIpPortConnectRule();
            OutputDebugString(L"[HadesSvc] ReLoadIpPortConnectRule Enable KernelMonitor Success");
            task_array_data.push_back("Success");
        }
        break;
#endif
        default:
            task_array_data.clear();
            return 0;
        }

    }

    // Write Pip
    {
        std::shared_ptr<protocol::Record> record = std::make_shared<protocol::Record>();
        if (!record)
            return 0;
        protocol::Payload* const PayloadMsg = record->mutable_data();
        if (!PayloadMsg)
            return 0;
        auto MapMessage = PayloadMsg->mutable_fields();
        if (!MapMessage)
            return 0;

        std::string serializbuf = "";
        record->set_data_type(taskid);
        record->set_timestamp(GetTickCount64());
        for(const auto& iter : task_array_data)
        {
            (*MapMessage)["data_type"] = std::to_string(taskid).c_str();
            if (!iter.empty()) {
                (*MapMessage)["udata"] = iter.c_str(); // json
            }
            else
                (*MapMessage)["udata"] = "error";

            serializbuf = record->SerializeAsString();
            const size_t datasize = serializbuf.size();
            PipWriteAnonymous(serializbuf, datasize);
            Sleep(10);
            MapMessage->clear();
        }
    }

    // Write Pip
    //for (const auto& iter : task_array_data) {
    //    const std::string sData = CodeTool::GbkToUtf8(iter.c_str()).c_str();

    //    rapidjson::Document document;
    //    document.SetObject();
    //    document.AddMember(rapidjson::StringRef("taskid"), rapidjson::StringRef(std::to_string(taskid).c_str()), document.GetAllocator());
    //    document.AddMember(rapidjson::StringRef("timestamp"), rapidjson::StringRef(std::to_string(GetTickCount64()).c_str()), document.GetAllocator());
    //    document.AddMember(rapidjson::StringRef("data"), rapidjson::StringRef(sData.c_str()), document.GetAllocator());

    //    std::string sJsonData = "";
    //    rapidjson::StringBuffer sbuffer;
    //    rapidjson::Writer<rapidjson::StringBuffer> writer(sbuffer);
    //    document.Accept(writer);
    //    sJsonData = sbuffer.GetString();
    //    PipWriteAnonymous(sJsonData, sJsonData.size());
    //}

    task_array_data.clear();
    return 0;
}
static DWORD WINAPI PTaskHandlerThread(LPVOID lpThreadParameter)
{
    try
    {
        THREADPA_PARAMETER_NODE* pthreadPara = reinterpret_cast<THREADPA_PARAMETER_NODE*>(lpThreadParameter);
        if (!pthreadPara || (pthreadPara == nullptr))
            return 0;
        if (g_shutdown)
        {
            delete pthreadPara;
            return 0;
        }
        const int taskid = pthreadPara->nTaskId;
        if (pthreadPara->pDataHandler)
            pthreadPara->pDataHandler->PTaskHandlerNotify(taskid);

        delete pthreadPara;
        pthreadPara = nullptr;
        return 0;
    }
    catch (const std::exception&)
    {
        return 0;
    }
}

// Recv Task
void DataHandler::OnPipMessageNotify(const std::shared_ptr<uint8_t>& data, size_t size)
{
    // filter size
    if (!data || (data == nullptr) || (size <= 0 && size >= 1024))
        return;
    try
    {
        const int taskid = *((int*)data.get());
        // 匿名管道不确定因素多，Filter Task id <= 1024
        if (taskid <= 0 && taskid >= 1024)
            return;

        PTHREADPA_PARAMETER_NODE pThreadPara = nullptr;
        pThreadPara = new THREADPA_PARAMETER_NODE;
        if (pThreadPara) {
            pThreadPara->clear();
            // 反序列化成Task
            protocol::Task pTask;
            pTask.ParseFromString((char*)(data.get() + 0x4));
            pThreadPara->nTaskId = pTask.data_type();
            pThreadPara->pDataHandler = this;
            QueueUserWorkItem(PTaskHandlerThread, (LPVOID)pThreadPara, WT_EXECUTEDEFAULT);
        }
    }
    catch (const std::exception&)
    {
        return;
    }  
}

// Debug interface
void DataHandler::DebugTaskInterface(const int taskid)
{
    THREADPA_PARAMETER_NODE threadPara;
    threadPara.clear();
    threadPara.nTaskId = taskid;
    threadPara.pDataHandler = this;
    QueueUserWorkItem(PTaskHandlerThread, (LPVOID)&threadPara, WT_EXECUTEDEFAULT);
}

// 内核数据ConSumer
void DataHandler::KerSublthreadProc()
{
    std::shared_ptr<protocol::Record> record = std::make_shared<protocol::Record>();
    if (!record)
        return;
    protocol::Payload* const PayloadMsg = record->mutable_data();
    if (!PayloadMsg)
        return;
    auto MapMessage = PayloadMsg->mutable_fields();
    if (!MapMessage)
        return;
    std::string serializbuf = "";

    do {
        WaitForSingleObject(g_Ker_Queue_Event, INFINITE);
        if (g_shutdown)
            break;
        do{
            std::unique_lock<std::mutex> lock(g_Ker_QueueCs_Ptr);
            if (g_Ker_SubQueue_Ptr.empty())
                break;
            const auto subwrite = g_Ker_SubQueue_Ptr.front();
            g_Ker_SubQueue_Ptr.pop();
            if (!subwrite)
                break;
            record->set_data_type(subwrite->taskid);
            record->set_timestamp(GetTickCount64());
            (*MapMessage)["data_type"] = to_string(subwrite->taskid);
            (*MapMessage)["udata"] = subwrite->data->c_str(); // json
            serializbuf = record->SerializeAsString();
            const size_t datasize = serializbuf.size();
            PipWriteAnonymous(serializbuf, datasize);
            MapMessage->clear();
            serializbuf.clear();
        } while (false);
    } while (!g_shutdown);
}
static unsigned WINAPI _KerSubthreadProc(void* pData)
{
    if (pData)
        (reinterpret_cast<DataHandler*>(pData))->KerSublthreadProc();
    return 0;
}
// Etw数据ConSumer
void DataHandler::EtwSublthreadProc()
{
    std::shared_ptr<protocol::Record> record = std::make_shared<protocol::Record>();
    if (!record)
        return;
    protocol::Payload* const PayloadMsg = record->mutable_data();
    if (!PayloadMsg)
        return;
    auto MapMessage = PayloadMsg->mutable_fields();
    if (!MapMessage)
        return;

    std::string serializbuf = "";
    do {
        WaitForSingleObject(g_Etw_Queue_Event, INFINITE);
        if (g_shutdown || !record)
            break;
        do {
            std::unique_lock<std::mutex> lock(g_Etw_QueueCs_Ptr);
            if (g_Etw_SubQueue_Ptr.empty())
                break;
            const auto subwrite = g_Etw_SubQueue_Ptr.front();
            g_Etw_SubQueue_Ptr.pop();
            if (!subwrite)
                break;
            record->set_data_type(subwrite->taskid);
            record->set_timestamp(GetTickCount64());
            (*MapMessage)["data_type"] = to_string(subwrite->taskid);
            (*MapMessage)["udata"] = subwrite->data->c_str(); // json
            serializbuf = record->SerializeAsString();
            const size_t datasize = serializbuf.size();
            PipWriteAnonymous(serializbuf, datasize);
            MapMessage->clear();
            serializbuf.clear();
        } while (false);
    } while (!g_shutdown);
}
static unsigned WINAPI _EtwSubthreadProc(void* pData)
{
    if (pData)
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

// 设置ConSumer订阅,初始化队列线程
bool DataHandler::ThreadPool_Init()
{
    g_Ker_Queue_Event = CreateEvent(NULL, FALSE, FALSE, NULL);
    g_Etw_Queue_Event = CreateEvent(NULL, FALSE, FALSE, NULL);
    this->m_jobAvailableEvnet_WriteTask = CreateEvent(NULL, FALSE, FALSE, NULL);
    if (!g_Etw_Queue_Event || !g_Ker_Queue_Event || !m_jobAvailableEvnet_WriteTask)
        return false;

    SingletonUMon::instance()->uMsg_SetSubEventPtr(g_Etw_Queue_Event);
    SingletonUMon::instance()->uMsg_SetSubQueueLockPtr(g_Etw_QueueCs_Ptr);
    SingletonUMon::instance()->uMsg_SetSubQueuePtr(g_Etw_SubQueue_Ptr);

    SingletonKerMon::instance()->kMsg_SetSubEventPtr(g_Ker_Queue_Event);
    SingletonKerMon::instance()->kMsg_SetSubQueueLockPtr(g_Ker_QueueCs_Ptr);
    SingletonKerMon::instance()->kMsg_SetSubQueuePtr(g_Ker_SubQueue_Ptr);

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
