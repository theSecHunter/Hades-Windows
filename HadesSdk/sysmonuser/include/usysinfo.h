#pragma once
#include <atlstr.h>
#include <string>
#include <vector>

struct CameraInfo
{
	std::string cameraName;
	std::vector<std::pair<int, int>> resolutionList;

	CameraInfo()
	{
		resolutionList.clear();
	}
	~CameraInfo()
	{
		resolutionList.clear();
	}
};

class USysBaseInfo
{
public:
	USysBaseInfo();
	~USysBaseInfo();

	// Monitor: 系统数据动态回调
	void GetSysDynCpuTempera();
	void GetSysDynMonTempera();
	void GetSysDynManBoardTempera();
	void GetSysDynDiskTempera();
	void GetSysDynCpuUtilizaTempera();
	void GetSysDynSysMemTempera();
	void GetSysDynDiskIoTempera();
	void GetSysDynGpuTempera();
	int GetBluetooth(void);

	// View
	std::vector<CameraInfo> GetCameraInfoList();
	void GetManID(std::string& cpuinfo);
	void GetOSVersion(std::string& strOSVersion);
	void GetDiskInfo(std::vector<std::string>& diskinfo);
	void GetDisplayCardInfo(std::vector<std::string>& Cardinfo);
	int Getbattery(std::vector<std::string>& batteryinfo);

	bool uf_GetSystemBaseInfo(LPVOID outbuf);
private:

};