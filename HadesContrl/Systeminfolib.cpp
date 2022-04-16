#include "Systeminfolib.h"
#include <usysinfo.h>
#include <Windows.h>

#ifdef _WIN64
#ifdef _DEBUG
#pragma comment(lib, "D:\\Hades\\Hades-Windows\\HadesSdk\\sysmonuser\\lib\\SysMonUserlib64.lib")
#else
#pragma comment(lib, "D:\\Hades\\Hades-Windows\\HadesSdk\\sysmonuser\\lib\\SysMonUserlib64.lib")
#endif
#else
#ifdef _DEBUG
#pragma comment(lib, "D:\\Hades\\Hades-Windows\\HadesSdk\\sysmonuser\\lib\\SysMonUserlib_d.lib")
#else
#pragma comment(lib, "D:\\Hades\\Hades-Windows\\HadesSdk\\sysmonuser\\lib\\SysMonUserlib.lib")
#endif
#endif

SystemAttributesNode SYSTEMPUBLIC::sysattriinfo;
SystemDynamicNode SYSTEMPUBLIC::sysdynamicinfo;

static USysBaseInfo g_systmelib;

Systeminfolib::Systeminfolib()
{
    try
    {
        DWORD ComUserLen = MAX_PATH;
        CHAR ComUserName[MAX_PATH] = { 0, };
        GetComputerNameA(ComUserName, &ComUserLen);
        SYSTEMPUBLIC::sysattriinfo.currentUser = ComUserName;
        g_systmelib.GetOSVersion(SYSTEMPUBLIC::sysattriinfo.verkerlinfo);
        g_systmelib.GetDisplayCardInfo(SYSTEMPUBLIC::sysattriinfo.mainboard);
        g_systmelib.GetDiskInfo(SYSTEMPUBLIC::sysattriinfo.sysdisk);
        g_systmelib.Getbattery(SYSTEMPUBLIC::sysattriinfo.battery);
        g_systmelib.GetManID(SYSTEMPUBLIC::sysattriinfo.cpuinfo);
    }
    catch (const std::exception&)
    {

    }
}

Systeminfolib::~Systeminfolib()
{

}