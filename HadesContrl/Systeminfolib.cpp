#include "Systeminfolib.h"
#include <usysinfo.h>
#include <Windows.h>

SystemAttributesNode SYSTEMPUBLIC::sysattriinfo;
SystemDynamicNode SYSTEMPUBLIC::sysdynamicinfo;

static USysBaseInfo g_systmelib;
HWND MainWin_hwnd;

Systeminfolib::Systeminfolib()
{
    try
    {
        DWORD ComUserLen = MAX_PATH;
        CHAR ComUserName[MAX_PATH] = { 0, };
        GetComputerNameA(ComUserName, &ComUserLen);
        SYSTEMPUBLIC::sysattriinfo.currentUser = ComUserName;
        g_systmelib.GetOSVersion(SYSTEMPUBLIC::sysattriinfo.verkerlinfo, SYSTEMPUBLIC::sysattriinfo.verMajorVersion, SYSTEMPUBLIC::sysattriinfo.verMinorVersion, SYSTEMPUBLIC::sysattriinfo.Is64);
        g_systmelib.GetDisplayCardInfo(SYSTEMPUBLIC::sysattriinfo.mainboard);
        g_systmelib.GetDiskInfo(SYSTEMPUBLIC::sysattriinfo.sysdisk);
        g_systmelib.Getbattery(SYSTEMPUBLIC::sysattriinfo.battery);
        g_systmelib.GetSysCpuInfo(SYSTEMPUBLIC::sysattriinfo.cpuinfo);
        g_systmelib.GetBluetooth(SYSTEMPUBLIC::sysattriinfo.bluetooth);
        g_systmelib.GetCameraInfoList(SYSTEMPUBLIC::sysattriinfo.camera);
        g_systmelib.GetGPU(SYSTEMPUBLIC::sysattriinfo.monitor);
    }
    catch (const std::exception&)
    {

    }
}

Systeminfolib::~Systeminfolib()
{
    KillTimer(NULL, 1);
    KillTimer(NULL, 2);
}