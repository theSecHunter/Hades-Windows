#pragma once
#include <string>

// OS固定数据
typedef struct _SystemAttributesNode
{
	std::string currentUser;	//当前用户	
	std::string cpuinfo;		//cpu信息
	std::string verkerlinfo;	//版本
	std::string mainboard;		//主板
	std::string monitor;		//显卡
	std::string netcard;		//网卡
	std::string battery;		//电池
	std::string camera;			//摄像头
	std::string bluetooth;		//蓝牙
	std::string voice;			//音频
}SystemAttributesNode, * PSystemAttributesNode;


// OS变动数据
typedef struct _SystemDynamicNode
{
	std::string cpu_temperature;
	std::string monitor_temperature;
	std::string mainboard_temperature;
	std::string disk_temperature;
	std::string cpu_utilization;
	std::string sys_memory;
	std::string disk_io;
	std::string GPU;
}SystemDynamicNode, * PSystemDynamicNode;


namespace SYSTEMPUBLIC {
	extern SystemAttributesNode sysattriinfo;
	extern SystemDynamicNode sysdynamicinfo;
}

// 初始化系统属性
extern void SysAttributesInit();


// 系统数据动态回调
extern void SysDynCpuTempera();
extern void SysDynMonTempera();
extern void SysDynManBoardTempera();
extern void SysDynDiskTempera();
extern void SysDynCpuUtilizaTempera();
extern void SysDynSysMemTempera();
extern void SysDynDiskIoTempera();
extern void SysDynGpuTempera();