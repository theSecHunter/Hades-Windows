#include <Windows.h>
#include "usysinfo.h"
#include <sysinfo.h>
#include <BluetoothAPIs.h>  
#include <amvideo.h>
#include <vector>
#include <strmif.h>
#include <uuids.h>
#include <iostream>
#include <Vfw.h>
#include <DXGI.h> 

#pragma comment(lib,"Strmiids.lib")
#pragma comment(lib,"Bthprops.lib") 
#pragma comment(lib, "DXGI.lib")

extern "C" void __stdcall GetCpuid(DWORD * deax, DWORD * debx, DWORD * decx, DWORD * dedx, char* cProStr);

// View: 系统版本
void USysBaseInfo::GetOSVersion(std::string& strOSVersion, int& verMajorVersion, int& verMinorVersion, bool& Is64)
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
            str = "Windows 8 ";
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
// View: 系统磁盘
void USysBaseInfo::GetDiskInfo(std::vector<std::string>& diskinfo)
{
    DWORD DiskCount = 0;

    //利用GetLogicalDrives()函数可以获取系统中逻辑驱动器的数量，函数返回的是一个32位无符号整型数据。  
    DWORD DiskInfo = GetLogicalDrives();

    //通过循环操作查看每一位数据是否为1，如果为1则磁盘为真,如果为0则磁盘不存在。  
    while (DiskInfo)
    {
        //通过位运算的逻辑与操作，判断是否为1  
        Sleep(10);
        if (DiskInfo & 1)
        {
            DiskCount++;
        }
        DiskInfo = DiskInfo >> 1;//通过位运算的右移操作保证每循环一次所检查的位置向右移动一位。*/  
    }

    //-------------------------------------------------------------------//  
    //通过GetLogicalDriveStrings()函数获取所有驱动器字符串信息长度  
    int DSLength = GetLogicalDriveStrings(0, NULL);

    WCHAR* DStr = new WCHAR[DSLength];
    memset(DStr, 0, DSLength);

    //通过GetLogicalDriveStrings将字符串信息复制到堆区数组中,其中保存了所有驱动器的信息。  
    GetLogicalDriveStrings(DSLength, DStr);

    int DType;
    int si = 0;
    BOOL fResult;
    unsigned _int64 i64FreeBytesToCaller;
    unsigned _int64 i64TotalBytes;
    unsigned _int64 i64FreeBytes;

    //读取各驱动器信息，由于DStr内部数据格式是A:\NULLB:\NULLC:\NULL，所以DSLength/4可以获得具体大循环范围  
    for (int i = 0; i < DSLength / 4; ++i)
    {
        Sleep(10);
        CStringA strdriver = DStr + i * 4;
        CStringA strTmp, strTotalBytes, strFreeBytes;
        DType = GetDriveTypeA(strdriver);//GetDriveType函数，可以获取驱动器类型，参数为驱动器的根目录  
        switch (DType)
        {
        case DRIVE_FIXED:
        {
            strTmp.Format("本地磁盘");
        }
        break;
        case DRIVE_CDROM:
        {
            strTmp.Format("DVD驱动器");
        }
        break;
        case DRIVE_REMOVABLE:
        {
            strTmp.Format("可移动磁盘");
        }
        break;
        case DRIVE_REMOTE:
        {
            strTmp.Format("网络磁盘");
        }
        break;
        case DRIVE_RAMDISK:
        {
            strTmp.Format("虚拟RAM磁盘");
        }
        break;
        case DRIVE_UNKNOWN:
        {
            strTmp.Format("虚拟RAM未知设备");
        }
        break;
        default:
            strTmp.Format("未知设备");
            break;
        }

        //GetDiskFreeSpaceEx函数，可以获取驱动器磁盘的空间状态,函数返回的是个BOOL类型数据  
        fResult = GetDiskFreeSpaceExA(strdriver,
            (PULARGE_INTEGER)&i64FreeBytesToCaller,
            (PULARGE_INTEGER)&i64TotalBytes,
            (PULARGE_INTEGER)&i64FreeBytes);

        if (fResult)
        {
            strTotalBytes.Format(("磁盘总容量%fMB"), (float)i64TotalBytes / 1024 / 1024);
            strFreeBytes.Format(("磁盘剩余空间%fMB"), (float)i64FreeBytesToCaller / 1024 / 1024);
        }
        else
        {
            strTotalBytes.Format("");
            strFreeBytes.Format("");
        }
        auto tmpstr = strTmp + _T("(") + strdriver + _T("):") + strTotalBytes + strFreeBytes;
        diskinfo.push_back(tmpstr.GetBuffer());
        si += 4;
    }
}
// View: 系统主板
void USysBaseInfo::GetDisplayCardInfo(std::vector<std::string>& Cardinfo)
{
    HKEY keyServ;
    HKEY keyEnum;
    HKEY key;
    HKEY key2;
    LONG lResult;//LONG型变量－保存函数返回值  

    //查询"SYSTEM\\CurrentControlSet\\Services"下的所有子键保存到keyServ  
    lResult = RegOpenKeyEx(HKEY_LOCAL_MACHINE, TEXT("SYSTEM\\CurrentControlSet\\Services"), 0, KEY_READ, &keyServ);
    if (ERROR_SUCCESS != lResult)
        return;


    //查询"SYSTEM\\CurrentControlSet\\Enum"下的所有子键保存到keyEnum  
    lResult = RegOpenKeyEx(HKEY_LOCAL_MACHINE, TEXT("SYSTEM\\CurrentControlSet\\Enum"), 0, KEY_READ, &keyEnum);
    if (ERROR_SUCCESS != lResult)
        return;

    int i = 0, count = 0;
    DWORD size = 0, type = 0;
    for (;; ++i)
    {
        Sleep(5);
        size = 512;
        TCHAR name[512] = { 0 };//保存keyServ下各子项的字段名称  

        //逐个枚举keyServ下的各子项字段保存到name中  
        lResult = RegEnumKeyEx(keyServ, i, name, &size, NULL, NULL, NULL, NULL);

        //要读取的子项不存在，即keyServ的子项全部遍历完时跳出循环  
        if (lResult == ERROR_NO_MORE_ITEMS)
            break;

        //打开keyServ的子项字段为name所标识的字段的值保存到key  
        lResult = RegOpenKeyEx(keyServ, name, 0, KEY_READ, &key);
        if (lResult != ERROR_SUCCESS)
        {
            RegCloseKey(keyServ);
            return;
        }


        size = 512;
        //查询key下的字段为Group的子键字段名保存到name  
        lResult = RegQueryValueEx(key, TEXT("Group"), 0, &type, (LPBYTE)name, &size);
        if (lResult == ERROR_FILE_NOT_FOUND)
        {
            //?键不存在  
            RegCloseKey(key);
            continue;
        };



        //如果查询到的name不是Video则说明该键不是显卡驱动项  
        if (_tcscmp(TEXT("Video"), name) != 0)
        {
            RegCloseKey(key);
            continue;     //返回for循环  
        };

        //如果程序继续往下执行的话说明已经查到了有关显卡的信息，所以在下面的代码执行完之后要break第一个for循环，函数返回  
        lResult = RegOpenKeyEx(key, TEXT("Enum"), 0, KEY_READ, &key2);
        RegCloseKey(key);
        key = key2;
        size = sizeof(count);
        lResult = RegQueryValueEx(key, TEXT("Count"), 0, &type, (LPBYTE)&count, &size);//查询Count字段（显卡数目）  

        for (int j = 0; j < count; ++j)
        {
            CHAR sz[512] = { 0 };
            CHAR name[64] = { 0 };
            sprintf(name, "%d", j);
            size = sizeof(sz);
            lResult = RegQueryValueExA(key, name, 0, &type, (LPBYTE)sz, &size);


            lResult = RegOpenKeyExA(keyEnum, sz, 0, KEY_READ, &key2);
            if (ERROR_SUCCESS)
            {
                RegCloseKey(keyEnum);
                return;
            }


            size = sizeof(sz);
            lResult = RegQueryValueExA(key2, "FriendlyName", 0, &type, (LPBYTE)sz, &size);
            if (lResult == ERROR_FILE_NOT_FOUND)
            {
                size = sizeof(sz);
                lResult = RegQueryValueExA(key2, "DeviceDesc", 0, &type, (LPBYTE)sz, &size);
                Cardinfo.push_back(sz);
            };
            RegCloseKey(key2);
            key2 = NULL;
        };
        RegCloseKey(key);
        key = NULL;
        break;
    }
}
// View: 系统CPU
#ifdef _WIN64
#else
long GetCPUFreq()
{//获取CPU频率,单位: MHZ  
    int start, over;
    _asm
    {
        RDTSC
        mov start, eax
    }
    Sleep(50);
    _asm
    {
        RDTSC
        mov over, eax
    }
    return (over - start) / 50000;
}
#endif // _WIN64
void USysBaseInfo::GetSysCpuInfo(std::string& cpuinfo)
{//制造商信息
    DWORD deax = 10;
    DWORD debx = 20;
    DWORD decx = 30;
    DWORD dedx = 40;
    //厂商
    char ID[25] = { 0, };
    //字串
    char cProStr[49] = { 0, };
    memset(ID, 0, sizeof(ID));
    GetCpuid(&deax, &debx, &decx, &dedx, cProStr);
    memcpy(ID + 0, &debx, 4);
    memcpy(ID + 4, &dedx, 4);
    memcpy(ID + 8, &decx, 4);
    cpuinfo = ID;
    cpuinfo += " ";
    cpuinfo += cProStr;
}
// View: 系统电池 - (笔记本)内置和外置 - 台式 也可以用于区分笔记本或台式类型
void USysBaseInfo::Getbattery(std::vector<std::string>& batteryinfo) {
    // 获取具体电池使用时间-电量
    SYSTEM_POWER_STATUS powerStatus;
    if (GetSystemPowerStatus(&powerStatus) == 0)
        return;
    CStringA tmpstr, tmpstr1;
    tmpstr.Format("%d_", (int)powerStatus.BatteryLifePercent);  // 电量
    tmpstr1 += tmpstr;
    tmpstr.Format("%d_", (int)powerStatus.ACLineStatus);    // 状态
    tmpstr1 += tmpstr;
    tmpstr.Format("%d_", (int)powerStatus.BatteryLifeTime); // 剩余使用时间
    tmpstr1 += tmpstr;
    tmpstr.Format("%d_", (int)powerStatus.BatteryFullLifeTime);
    tmpstr1 += tmpstr;
    batteryinfo.push_back(tmpstr1.GetBuffer());
}
// View: 系统网卡
void USysBaseInfo::GetNetworkCard(std::vector<std::string>& networkcar)
{

}
// View: 系统显卡(GPU)
void USysBaseInfo::GetGPU(std::vector<std::string>& monitor) {
    // 参数定义  
    IDXGIFactory* pFactory;
    IDXGIAdapter* pAdapter;
    std::vector <IDXGIAdapter*> vAdapters;            // 显卡  
    // 显卡的数量  
    int iAdapterNum = 0;
    // 创建一个DXGI工厂  
    HRESULT hr = CreateDXGIFactory(__uuidof(IDXGIFactory), (void**)(&pFactory));
    if (FAILED(hr))
        return;
    // 枚举适配器  
    while (pFactory->EnumAdapters(iAdapterNum, &pAdapter) != DXGI_ERROR_NOT_FOUND)
    {
        vAdapters.push_back(pAdapter);
        ++iAdapterNum;
    }
    for (size_t i = 0; i < vAdapters.size(); i++)
    {
        //std::cout << "Video card" << i + 1 << ":" << std::endl;
        // 获取信息  
        DXGI_ADAPTER_DESC adapterDesc;
        vAdapters[i]->GetDesc(&adapterDesc);
        std::string bb;
        Wchar_tToString(bb, adapterDesc.Description);
        monitor.push_back(bb.c_str());
        //std::string bb = WStringToString(aa);
        //std::cout << "Video card " << i + 1 << " DedicatedVideoMemory:" << adapterDesc.DedicatedVideoMemory / 1024 / 1024 << "M" << std::endl;
        //std::cout << "Video card " << i + 1 << " SharedSystemMemory:" << adapterDesc.SharedSystemMemory / 1024 / 1024 << "M" << std::endl;
        //std::cout << "系统视频内存:" << adapterDesc.DedicatedSystemMemory / 1024 / 1024 << "M" << std::endl;
        //std::cout << "专用视频内存:" << adapterDesc.DedicatedVideoMemory / 1024 / 1024 << "M" << std::endl;
        //std::cout << "共享系统内存:" << adapterDesc.SharedSystemMemory / 1024 / 1024 << "M" << std::endl;
        //std::cout << "设备描述:" << bb.c_str() << std::endl;
        //std::cout << "设备ID:" << adapterDesc.DeviceId << std::endl;
        //std::cout << "PCI ID修正版本:" << adapterDesc.Revision << std::endl;
        //std::cout << "子系统PIC ID:" << adapterDesc.SubSysId << std::endl;
        //std::cout << "厂商编号:" << adapterDesc.VendorId << std::endl
        
        // 输出设备  
        IDXGIOutput* pOutput;
        std::vector<IDXGIOutput*> vOutputs;
        // 输出设备数量  
        int iOutputNum = 0;
        while (vAdapters[i]->EnumOutputs(iOutputNum, &pOutput) != DXGI_ERROR_NOT_FOUND)
        {
            vOutputs.push_back(pOutput);
            iOutputNum++;
        }

        //std::cout << std::endl;
        //std::cout << "该显卡获取到" << iOutputNum << "个显示设备:" << std::endl;

        for (size_t n = 0; n < vOutputs.size(); n++)
        {
            // 获取显示设备信息  
            DXGI_OUTPUT_DESC outputDesc;
            vOutputs[n]->GetDesc(&outputDesc);

            // 获取设备支持  
            UINT uModeNum = 0;
            DXGI_FORMAT format = DXGI_FORMAT_R8G8B8A8_UNORM;
            UINT flags = DXGI_ENUM_MODES_INTERLACED;

            vOutputs[n]->GetDisplayModeList(format, flags, &uModeNum, 0);
            DXGI_MODE_DESC* pModeDescs = new DXGI_MODE_DESC[uModeNum];
            vOutputs[n]->GetDisplayModeList(format, flags, &uModeNum, pModeDescs);

            //std::cout << "DisplayDevice:" << n + 1 << " Name:" << outputDesc.DeviceName << std::endl;
            //std::cout << "DisplayDevice " << n + 1 << " Resolution ratio:" << outputDesc.DesktopCoordinates.right - outputDesc.DesktopCoordinates.left << "*" << outputDesc.DesktopCoordinates.bottom - outputDesc.DesktopCoordinates.top << std::endl;

            // 所支持的分辨率信息  
            //std::cout << "分辨率信息:" << std::endl;
            /*for (UINT m = 0; m < uModeNum; m++)
            {
                std::cout << "== 分辨率:" << pModeDescs[m].Width << "*" << pModeDescs[m].Height << "     刷新率" << (pModeDescs[m].RefreshRate.Numerator) / (pModeDescs[m].RefreshRate.Denominator) << std::endl;
            }*/
        }
        vOutputs.clear();
    }
    vAdapters.clear();

}

// 时间转换
double FILETIMEDouble(const _FILETIME& filetime)
{
    return double(filetime.dwHighDateTime * 4.294967296e9) + double(filetime.dwLowDateTime);
}
// Monitor/View: 系统蓝牙
void USysBaseInfo::GetBluetooth(std::vector<std::string>& blueinfo)
{
    HBLUETOOTH_RADIO_FIND hbf = NULL;
    HANDLE hbr = NULL;
    HBLUETOOTH_DEVICE_FIND hbdf = NULL;
    //调用BluetoothFindFirstDevice搜索本机蓝牙收发器所需要的搜索参数对象
    BLUETOOTH_FIND_RADIO_PARAMS btfrp = { sizeof(BLUETOOTH_FIND_RADIO_PARAMS) };
    //初始化一个储存蓝牙收发器信息（BLUETOOTH_RADIO_INFO）的对象bri
    BLUETOOTH_RADIO_INFO bri = { sizeof(BLUETOOTH_RADIO_INFO) };
    //调用BluetoothFindFirstDevice搜索本所需要的搜索参数对象
    BLUETOOTH_DEVICE_SEARCH_PARAMS btsp = { sizeof(BLUETOOTH_DEVICE_SEARCH_PARAMS) };
    //初始化一个远程蓝牙设备信息（BLUETOOTH_DEVICE_INFO）对象btdi，以储存搜索到的蓝牙设备信息
    BLUETOOTH_DEVICE_INFO btdi = { sizeof(BLUETOOTH_DEVICE_INFO) };
    //得到第一个被枚举的蓝牙收发器的句柄hbf可用于BluetoothFindNextRadio，hbr可用于BluetoothFindFirstDevice。
    //若没有找到本机的蓝牙收发器，则得到的句柄hbf=NULL
    //具体可参考https://msdn.microsoft.com/en-us/library/aa362786(v=vs.85).aspx 
    hbf = BluetoothFindFirstRadio(&btfrp, &hbr);

    bool brfind = hbf != NULL;
    while (brfind)
    {
        if (BluetoothGetRadioInfo(hbr, &bri) == ERROR_SUCCESS)//获取蓝牙收发器的信息，储存在bri中  
        {
            //std::cout << "Class of device: 0x" << uppercase << hex << bri.ulClassofDevice << endl;
            //wcout << "Name:" << bri.szName << endl;  //蓝牙收发器的名字
            //cout << "Manufacture:0x" << uppercase << hex << bri.manufacturer << endl;
            //cout << "Subversion:0x" << uppercase << hex << bri.lmpSubversion << endl;
            //  
            btsp.hRadio = hbr;  //设置执行搜索设备所在的句柄，应设为执行BluetoothFindFirstRadio函数所得到的句柄
            btsp.fReturnAuthenticated = TRUE;//是否搜索已配对的设备  
            btsp.fReturnConnected = FALSE;//是否搜索已连接的设备  
            btsp.fReturnRemembered = TRUE;//是否搜索已记忆的设备  
            btsp.fReturnUnknown = TRUE;//是否搜索未知设备  
            btsp.fIssueInquiry = TRUE;//是否重新搜索，True的时候会执行新的搜索，时间较长，FALSE的时候会直接返回上次的搜索结果。
            btsp.cTimeoutMultiplier = 30;//指示查询超时的值，以1.28秒为增量。 例如，12.8秒的查询的cTimeoutMultiplier值为10.此成员的最大值为48.当使用大于48的值时，调用函数立即失败并返回 
            hbdf = BluetoothFindFirstDevice(&btsp, &btdi);//通过找到第一个设备得到的HBLUETOOTH_DEVICE_FIND句柄hbdf来枚举远程蓝牙设备，搜到的第一个远程蓝牙设备的信息储存在btdi对象中。若没有远程蓝牙设备，hdbf=NULL。  
            bool bfind = hbdf != NULL;
            while (bfind)
            {
                //wcout << "[Name]:" << btdi.szName;  //远程蓝牙设备的名字
                //cout << ",[Address]:0x" << uppercase << hex << btdi.Address.ullLong << endl;
                bfind = BluetoothFindNextDevice(hbdf, &btdi);//通过BluetoothFindFirstDevice得到的HBLUETOOTH_DEVICE_FIND句柄来枚举搜索下一个远程蓝牙设备，并将远程蓝牙设备的信息储存在btdi中  
            }
            BluetoothFindDeviceClose(hbdf);//使用完后记得关闭HBLUETOOTH_DEVICE_FIND句柄hbdf。  
        }
        CloseHandle(hbr);
        brfind = BluetoothFindNextRadio(hbf, &hbr);//通过BluetoothFindFirstRadio得到的HBLUETOOTH_RADIO_FIND句柄hbf来枚举搜索下一个本地蓝牙收发器，得到可用于BluetoothFindFirstDevice的句柄hbr。    
    }
    BluetoothFindRadioClose(hbf);//使用完后记得关闭HBLUETOOTH_RADIO_FIND句柄hbf。  
    return;
}
// Monitor/View: 系统摄像头 - 支持的分辨率
std::vector<std::pair<int, int>> GetCameraSupportResolutions(IBaseFilter* pBaseFilter)
{
    HRESULT hr = 0;
    std::vector<IPin*> pins;
    IEnumPins* EnumPins;
    pBaseFilter->EnumPins(&EnumPins);
    pins.clear();

    std::vector<std::pair<int, int>> result;

    for (;;)
    {
        IPin* pin;
        hr = EnumPins->Next(1, &pin, NULL);
        if (hr != S_OK)
        {
            break;
        }
        pins.push_back(pin);
        pin->Release();
    }

    EnumPins->Release();

    PIN_INFO pInfo;
    for (int i = 0; i < pins.size(); i++)
    {
        if (nullptr == pins[i])
        {
            break;
        }
        pins[i]->QueryPinInfo(&pInfo);

        IEnumMediaTypes* emt = NULL;
        pins[i]->EnumMediaTypes(&emt);
        AM_MEDIA_TYPE* pmt;

        for (;;)
        {
            hr = emt->Next(1, &pmt, NULL);
            if (hr != S_OK)
            {
                break;
            }
            if ((pmt->formattype == FORMAT_VideoInfo)
                //&& (pmt->subtype == MEDIASUBTYPE_RGB24)
                && (pmt->cbFormat >= sizeof(VIDEOINFOHEADER))
                && (pmt->pbFormat != NULL)) {

                VIDEOINFOHEADER* pVIH = (VIDEOINFOHEADER*)pmt->pbFormat;

                auto insertParam = std::pair<int, int>{ pVIH->bmiHeader.biWidth, pVIH->bmiHeader.biHeight };
                bool isSet = false;

                for (auto param : result)
                {
                    if (param.first == insertParam.first && param.second == insertParam.second)
                    {
                        isSet = true;
                        break;
                    }
                }

                if (!isSet)
                {
                    result.push_back(insertParam);
                }
            }

            if (pmt->cbFormat != 0)
            {
                CoTaskMemFree((PVOID)pmt->pbFormat);
                pmt->cbFormat = 0;
                pmt->pbFormat = NULL;
            }
            if (pmt->pUnk != NULL)
            {
                // pUnk should not be used.
                pmt->pUnk->Release();
                pmt->pUnk = NULL;
            }
        }
        break;
        emt->Release();
    }
    return result;
}
void USysBaseInfo::GetCameraInfoList(std::vector<std::string>& cameraInfo)
{
    std::vector<CameraInfo> nameList;
    HRESULT hr;

    ICreateDevEnum* pSysDevEnum = NULL;
    hr = CoCreateInstance(CLSID_SystemDeviceEnum, NULL, CLSCTX_INPROC_SERVER,
        IID_ICreateDevEnum, (void**)&pSysDevEnum);

    if (FAILED(hr))
    {
        pSysDevEnum->Release();
        return;
    }

    IEnumMoniker* pEnumCat = NULL;
    hr = pSysDevEnum->CreateClassEnumerator(CLSID_VideoInputDeviceCategory, &pEnumCat, 0);

    if (FAILED(hr))
    {
        pSysDevEnum->Release();
        return;
    }

    IMoniker* pMoniker = NULL;
    ULONG cFetched;
    auto index = 0;
    while (pEnumCat->Next(1, &pMoniker, &cFetched) == S_OK)
    {
        IPropertyBag* pPropBag;
        hr = pMoniker->BindToStorage(0, 0, IID_IPropertyBag, (void**)&pPropBag);
        if (SUCCEEDED(hr))
        {
            IBaseFilter* pFilter;
            hr = pMoniker->BindToObject(NULL, NULL, IID_IBaseFilter, (void**)&pFilter);
            if (!pFilter)
            {
                pMoniker->Release();
                break;
            }

            VARIANT varName;
            VariantInit(&varName);
            hr = pPropBag->Read(L"FriendlyName", &varName, 0);
            if (SUCCEEDED(hr))
            {
                CameraInfo info;
                CStringA tmpstr;
                info.resolutionList = GetCameraSupportResolutions(pFilter);
                tmpstr.Format("%ws", varName.bstrVal);
                info.cameraName = tmpstr.GetBuffer();
                nameList.push_back(info);
                cameraInfo.push_back(tmpstr.GetBuffer());
            }
            VariantClear(&varName);
            pFilter->Release();
            pPropBag->Release();
        }
        pMoniker->Release();
    }
    pEnumCat->Release();

    //return nameList;
}
void USysBaseInfo::GetCamerStatus()
{
    auto nStatus = SendMessage(NULL, WM_CAP_DRIVER_CONNECT, 0, 0);
    if (false == nStatus)
    {

    }
    else
    {

    }
}
// Monitor/View: 系统麦克风 - 型号 - 状态
void USysBaseInfo::GetMicroPhone(std::vector<std::string>& micrphone)
{
}

// Monitor: 主板温度
void USysBaseInfo::GetSysDynManBoardTempera()
{

}
// Monitor: 磁盘温度
void USysBaseInfo::GetSysDynDiskTempera()
{

}
// Monitor: Cpu温度
void USysBaseInfo::GetSysDynCpuTempera()
{
}
// Monitor: Gpu温度
void USysBaseInfo::GetSysDynGpuTempera()
{

}

// Monitor: Cpu占用率
const double USysBaseInfo::GetSysDynCpuUtiliza()
{
    // 获取空闲时间 内核 用户
    _FILETIME idleTime, kernelTime, userTime;
    GetSystemTimes(&idleTime, &kernelTime, &userTime);
    // Creates or opens a named or unnamed event object.
    // 创建或打开一个命名的或无名的事件对象。
    // failure 0  | sucess handle
    HANDLE hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
    // 等待1000毫秒，内核对象会更精确
    WaitForSingleObject(hEvent, 1000);
    // 获取新的时间
    _FILETIME newidleTime, newkernelTime, newuserTime;
    GetSystemTimes(&newidleTime, &newkernelTime, &newuserTime);
    // 转换时间
    double	doldidleTime = FILETIMEDouble(idleTime);
    double	doldkernelTime = FILETIMEDouble(kernelTime);
    double	dolduserTime = FILETIMEDouble(userTime);
    double	dnewidleTime = FILETIMEDouble(newidleTime);
    double	dnewkernelTime = FILETIMEDouble(newkernelTime);
    double	dnewuserTime = FILETIMEDouble(newuserTime);
    double	Times = dnewidleTime - doldidleTime;
    double	Kerneltime = dnewkernelTime - doldkernelTime;
    double	usertime = dnewuserTime - dolduserTime;
    // 计算使用率
    double Cpurate = (100.0 - Times / (Kerneltime + usertime) * 100.0);
    return Cpurate;
}
// Monitor: 内存占用率
const DWORD USysBaseInfo::GetSysDynSysMem()
{
    // 创建结构体对象 获取内存信息函数
    MEMORYSTATUS memStatus;
    GlobalMemoryStatus(&memStatus);
    return memStatus.dwMemoryLoad;

    CString m_MemoryBFB, m_Pymemory, m_Pagesize, m_Memorysize, m_Kymemorysize;
    // 已使用物理内存大小 Physical memory size
    size_t memPhysize = memStatus.dwTotalPhys - memStatus.dwAvailPhys;
    m_Pymemory.Format(L"%u", (memPhysize / 1024 / 1024 / 8));
    m_Pymemory += " MB";
    // 文件交换大小 Size of the file exchange
    m_Pagesize.Format(L"%u", (memStatus.dwAvailPageFile / 1024 / 1024 / 8));
    m_Pagesize += " MB";
    // 虚拟内存大小 Virtual memory size
    m_Memorysize.Format(L"%u", (memStatus.dwTotalVirtual / 1024 / 1024 / 8));
    m_Memorysize += " MB";
    // 可用虚拟内存大小 Available virtual memory size
    m_Kymemorysize.Format(L"%d", (memStatus.dwAvailVirtual / 1024 / 1024 / 8));
    m_Kymemorysize += " MB";
}
// Monitor: 磁盘占用率
void USysBaseInfo::GetSysDynDiskIo()
{

}
// Monitor: Gpu占用率
void USysBaseInfo::GetSysDynGpu()
{

}
// Mem优化
void USysBaseInfo::MemSwap()
{
    CString str, str1;
    str = "一键加速成功！ 节省了空间：  ";
    // 1. 获取当前已用物理内存状态
    MEMORYSTATUSEX stcMemStatusEx = { 0 };
    stcMemStatusEx.dwLength = sizeof(stcMemStatusEx);
    GlobalMemoryStatusEx(&stcMemStatusEx);
    DWORDLONG preUsedMem = stcMemStatusEx.ullTotalPhys - stcMemStatusEx.ullAvailPhys;
    // 2. 清理内存
    DWORD dwPIDList[1000] = { 0 };
    DWORD bufSize = sizeof(dwPIDList);
    DWORD dwNeedSize = 0;
    // EnumProcesses(dwPIDList, bufSize, &dwNeedSize);
    for (DWORD i = 0; i < dwNeedSize / sizeof(DWORD); ++i)
    {
        HANDLE hProccess = OpenProcess(PROCESS_SET_QUOTA, false, dwPIDList[i]);
        SetProcessWorkingSetSize(hProccess, -1, -1);
    }
    // 3. 获取清理后的内存状态
    GlobalMemoryStatusEx(&stcMemStatusEx);
    DWORDLONG afterCleanUserdMem = stcMemStatusEx.ullTotalPhys - stcMemStatusEx.ullAvailPhys;
    // 4. 计算并弹出清理成功
    DWORDLONG CleanofSuccess = preUsedMem - afterCleanUserdMem;
    str1.Format(L"%d", (CleanofSuccess / 1024 / 1024 / 8));
    str = str + str1 + " MB";
}

USysBaseInfo::USysBaseInfo()
{
}
USysBaseInfo::~USysBaseInfo()
{
}


