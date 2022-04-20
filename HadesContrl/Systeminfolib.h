#pragma once
#include <string>
#include <vector>

/*
	管理系统数据类
*/
// OS固定数据
typedef struct _SystemAttributesNode
{
	std::string currentUser;	//当前用户	
	std::string cpuinfo;		//cpu信息
	std::string verkerlinfo;	//版本
	int verMajorVersion;
	int verMinorVersion;
	bool Is64;
	std::vector<std::string> mainboard;		//主板
	std::vector<std::string> sysdisk;		//磁盘
	std::vector<std::string> monitor;		//显卡
	std::vector<std::string> netcard;		//网卡
	std::vector<std::string> battery;		//电池
	std::vector<std::string> camera;		//摄像头
	std::vector<std::string> bluetooth;		//蓝牙
	std::vector<std::string> voice;			//音频
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

class Systeminfolib
{
public:
	Systeminfolib();
	~Systeminfolib();

private:
};

