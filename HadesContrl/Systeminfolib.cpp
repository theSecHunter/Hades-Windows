#include "Systeminfolib.h"
#include <Windows.h>
#include "Interface.h"

SystemDynamicNode SYSTEMPUBLIC::sysdynamicinfo;
SystemAttributesNode SYSTEMPUBLIC::sysattriinfo;

Systeminfolib::Systeminfolib()
{
    try
    {
        DWORD ComUserLen = MAX_PATH;
        CHAR ComUserName[MAX_PATH] = { 0, };
        GetComputerNameA(ComUserName, &ComUserLen);
        SYSTEMPUBLIC::sysattriinfo.currentUser = ComUserName;
        SingletonUSysBaseInfo::instance()->GetOSVersion(SYSTEMPUBLIC::sysattriinfo.verkerlinfo, SYSTEMPUBLIC::sysattriinfo.verMajorVersion, SYSTEMPUBLIC::sysattriinfo.verMinorVersion, SYSTEMPUBLIC::sysattriinfo.Is64);
        SingletonUSysBaseInfo::instance()->GetDisplayCardInfoWmic(SYSTEMPUBLIC::sysattriinfo.mainboard);
        // SingletonUSysBaseInfo::instance()->GetDiskInfo(SYSTEMPUBLIC::sysattriinfo.sysdisk);
        // SingletonUSysBaseInfo::instance()->Getbattery(SYSTEMPUBLIC::sysattriinfo.battery);
        SingletonUSysBaseInfo::instance()->GetSysCpuInfo(SYSTEMPUBLIC::sysattriinfo.cpuinfo);
        SingletonUSysBaseInfo::instance()->GetBluetooth(SYSTEMPUBLIC::sysattriinfo.bluetooth);
        SingletonUSysBaseInfo::instance()->GetCameraInfoList(SYSTEMPUBLIC::sysattriinfo.camera);
        SingletonUSysBaseInfo::instance()->GetMicroPhone(SYSTEMPUBLIC::sysattriinfo.microphone);
        SingletonUSysBaseInfo::instance()->GetGPU(SYSTEMPUBLIC::sysattriinfo.monitor);
    }
    catch (const std::exception&)
    {

    }
}

Systeminfolib::~Systeminfolib()
{
}