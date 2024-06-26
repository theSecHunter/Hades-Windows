#include <Windows.h>
#include "UntsSvc.h"
#include "singGloal.h"

#include <atlstr.h>
#pragma warning(disable: 4996)

UntsSvc::UntsSvc()
{
}

UntsSvc::~UntsSvc()
{
}

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

const bool UntsSvc::UnTs_NetCheckStatus(const std::wstring sDriverName)
{
    int nSeriverstatus = SingletonDrvManage::instance()->nf_GetServicesStatus(sDriverName.c_str());
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
        nSeriverstatus = SingletonDrvManage::instance()->nf_GetServicesStatus(sDriverName.c_str());
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
