#include <Windows.h>
#include "usysinfo.h"
#include <sysinfo.h>
#include <atlstr.h>



USysBaseInfo::USysBaseInfo()
{
}

USysBaseInfo::~USysBaseInfo()
{
}

// Mem优化
void MemSwap()
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
// 时间转换
double FILETIMEDouble(const _FILETIME& filetime)
{
	return double(filetime.dwHighDateTime * 4.294967296e9) + double(filetime.dwLowDateTime);
}
// CPU
void GetCpuUsage(LPVOID outbuf)
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
	//m_Cpusyl.Format(L"%0.2lf", Cpurate);
	//m_Cpusyl += "%";
}
// Virtual Memory
void GetMemoryInfo(LPVOID outbuf)
{
	// 创建结构体对象 获取内存信息函数
	MEMORYSTATUS memStatus;
	GlobalMemoryStatus(&memStatus);
	//// 当前占用率 Occupancy rate
	//m_MemoryBFB.Format(L"%u", memStatus.dwMemoryLoad);
	//m_MemoryBFB += "%";
	//// 已使用物理内存大小 Physical memory size
	//size_t memPhysize = memStatus.dwTotalPhys - memStatus.dwAvailPhys;
	//m_Pymemory.Format(L"%u", (memPhysize / 1024 / 1024 / 8));
	//m_Pymemory += " MB";
	//// 文件交换大小 Size of the file exchange
	//m_Pagesize.Format(L"%u", (memStatus.dwAvailPageFile / 1024 / 1024 / 8));
	//m_Pagesize += " MB";
	//// 虚拟内存大小 Virtual memory size
	//m_Memorysize.Format(L"%u", (memStatus.dwTotalVirtual / 1024 / 1024 / 8));
	//m_Memorysize += " MB";
	//// 可用虚拟内存大小 Available virtual memory size
	//m_Kymemorysize.Format(L"%d", (memStatus.dwAvailVirtual / 1024 / 1024 / 8));
	//m_Kymemorysize += " MB";
}

bool USysBaseInfo::uf_GetSystemBaseInfo(LPVOID outbuf)
{
	// 硬件信息


	// 软件信息


	// 系统运行信息
	//GetCpuUsage();
	//GetMemoryInfo();

	return true;
}