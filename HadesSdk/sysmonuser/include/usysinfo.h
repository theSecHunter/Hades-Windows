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

	// Monitor
	void GetSysDynManBoardTempera();
	void GetSysDynDiskTempera();
	void GetSysDynCpuTempera();
	void GetSysDynGpuTempera();

	const double GetSysDynCpuUtiliza();
	const DWORD GetSysDynSysMem();
	void GetSysDynDiskIo();
	void GetSysDynGpu();
	void MemSwap();
	void GetBluetooth(std::vector<std::string>& blueinfo);
	void GetMicroPhone(std::vector<std::string>& micrphone);

	// View
	void GetGPU(std::vector<std::string>& monitor);
	void GetNetworkCard(std::vector<std::string>& networkcar);
	void GetCamerStatus();
	void GetCameraInfoList(std::vector<std::string>& cameraInfo);
	void GetDiskInfo(std::vector<std::string>& diskinfo);
	void GetDisplayCardInfo(std::vector<std::string>& Cardinfo);
	void Getbattery(std::vector<std::string>& batteryinfo);	
	void GetSysCpuInfo(std::string& cpuinfo);
	void GetOSVersion(std::string& strOSVersion, int& verMajorVersion, int& verMinorVersion, bool& Is64);
private:

};