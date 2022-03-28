#include <Windows.h>
#include <string>
#include "uservicesoftware.h"

#include "sysinfo.h"
using namespace std;

#define MAX_SERVICE_SIZE 1024 * 64
#define MAX_QUERY_SIZE   1024 * 8

UServerSoftware::UServerSoftware()
{
}
UServerSoftware::~UServerSoftware()
{
}

DWORD UServerSoftware::EnumService(LPVOID outbuf)
{
	if (!outbuf)
		return FALSE;

	PUServicesNode serinfo = (PUServicesNode)outbuf;
	DWORD count = 0;

	do {
		SC_HANDLE SCMan = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
		if (SCMan == NULL) {
			break;
		}
		LPENUM_SERVICE_STATUS service_status;
		DWORD cbBytesNeeded = NULL;
		DWORD ServicesReturned = NULL;
		DWORD ResumeHandle = NULL;

		service_status = (LPENUM_SERVICE_STATUS)LocalAlloc(LPTR, MAX_SERVICE_SIZE);

		BOOL ESS = EnumServicesStatus(SCMan,						// 句柄
			SERVICE_WIN32,                                          // 服务类型
			SERVICE_STATE_ALL,                                      // 服务的状态
			(LPENUM_SERVICE_STATUS)service_status,                  // 输出参数，系统服务的结构
			MAX_SERVICE_SIZE,                                       // 结构的大小
			&cbBytesNeeded,                                         // 输出参数，接收返回所需的服务
			&ServicesReturned,                                      // 输出参数，接收返回服务的数量
			&ResumeHandle);                                         // 输入输出参数，第一次调用必须为0，返回为0代表成功
		if (ESS == NULL) {
			break;
		}

		string str;
	
		for (int i = 0; i < static_cast<int>(ServicesReturned); i++) {

			lstrcpyW(serinfo[count].lpDisplayName, service_status[i].lpDisplayName);
			
			switch (service_status[i].ServiceStatus.dwCurrentState) { // 服务状态
			case SERVICE_CONTINUE_PENDING:
				str = "CONTINUE_PENDING\n";
				break;
			case SERVICE_PAUSE_PENDING:
				str = "PAUSE_PENDING\n";
				break;
			case SERVICE_PAUSED:
				str = "PAUSED\n";
				break;
			case SERVICE_RUNNING:
				str = "RUNNING\n";
				break;
			case SERVICE_START_PENDING:
				str = "START_PENDING\n";
				break;
			case SERVICE_STOPPED:
				str = "STOPPED\n";
				break;
			default:
				str = "UNKNOWN\n";
				break;
			}
			serinfo[count].dwCurrentState = str;
			LPQUERY_SERVICE_CONFIG lpServiceConfig = NULL;          // 服务详细信息结构
			SC_HANDLE service_curren = NULL;                        // 当前的服务句柄
			LPSERVICE_DESCRIPTION lpqscBuf2 = NULL;					// 服务描述信息
			service_curren = OpenService(SCMan, service_status[i].lpServiceName, SERVICE_QUERY_CONFIG);        // 打开当前服务
			lpServiceConfig = (LPQUERY_SERVICE_CONFIG)LocalAlloc(LPTR, MAX_QUERY_SIZE);                        // 分配内存， 最大为8kb 

			if (NULL == QueryServiceConfig(service_curren, lpServiceConfig, MAX_QUERY_SIZE, &ResumeHandle)) {
				break;
			}

			lstrcpyW(serinfo[count].lpServiceName, service_status[i].lpServiceName);
			lstrcpyW(serinfo[count].lpBinaryPathName, lpServiceConfig->lpBinaryPathName);
			// fwprintf(g_pFile, L"Path: %s\n", lpServiceConfig->lpBinaryPathName);

			DWORD dwNeeded = 0;
			if (QueryServiceConfig2(service_curren, SERVICE_CONFIG_DESCRIPTION, NULL, 0,
				&dwNeeded) == FALSE && GetLastError() == ERROR_INSUFFICIENT_BUFFER)
			{
				lpqscBuf2 = (LPSERVICE_DESCRIPTION)LocalAlloc(LPTR, MAX_QUERY_SIZE);
				if (QueryServiceConfig2(service_curren, SERVICE_CONFIG_DESCRIPTION,
					(BYTE*)lpqscBuf2, dwNeeded, &dwNeeded))
				{
					if (lstrlenW(lpqscBuf2->lpDescription))
						lstrcpyW(serinfo[count].lpDescription, lpqscBuf2->lpDescription);
				}
				if (lpqscBuf2)
				{
					LocalFree(lpqscBuf2);
					lpqscBuf2 = NULL;
				}
			}
			
			count++;

			CloseServiceHandle(service_curren);
		}
		
		CloseServiceHandle(SCMan);

	} while (0);

	return count;
}

const HKEY RootKey = HKEY_LOCAL_MACHINE;
const LPCTSTR lpSubKey = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall";
HKEY hkResult = 0;
DWORD UServerSoftware::EnumSoftware(LPVOID outbuf)
{
	if (!outbuf)
		return false;

	PUSOFTINFO softwareinfo = (PUSOFTINFO)outbuf;

	USOFTINFO SoftInfo = { 0 };
	FILETIME ftLastWriteTimeA;					// last write time 
	// 1. 打开一个已存在的注册表键
	LONG LReturn = RegOpenKeyEx(RootKey, lpSubKey, 0, KEY_ENUMERATE_SUB_KEYS | KEY_WOW64_32KEY | KEY_QUERY_VALUE, &hkResult);
	// 2. 计算大小注册表
	// TCHAR    achKey[MAX_PATH] = {};			// buffer for subkey name
	DWORD    cbName = 0;						// size of name string 
	TCHAR    achClass[MAX_PATH] = TEXT("");		// buffer for class name 
	DWORD    cchClassName = MAX_PATH;			// size of class string 
	DWORD    cSubKeys = 0;						// number of subkeys 
	DWORD    cbMaxSubKey;						// longest subkey size 
	DWORD    cchMaxClass;						// longest class string 
	DWORD    cValues;							// number of values for key 
	DWORD    cchMaxValue;						// longest value name 
	DWORD    cbMaxValueData;					// longest value data 
	DWORD    cbSecurityDescriptor;				// size of security descriptor 
	FILETIME ftLastWriteTime;					// last write time 
	DWORD	retCode;
	// TCHAR  achValue[MAX_PATH] = {};
	DWORD cchValue = MAX_PATH;
	// Get the class name and the value count. 
	retCode = RegQueryInfoKey(
		hkResult,                // key handle 
		achClass,                // buffer for class name 
		&cchClassName,           // size of class string 
		NULL,                    // reserved 
		&cSubKeys,               // number of subkeys 
		&cbMaxSubKey,            // longest subkey size 
		&cchMaxClass,            // longest class string 
		&cValues,                // number of values for this key 
		&cchMaxValue,            // longest value name 
		&cbMaxValueData,         // longest value data 
		&cbSecurityDescriptor,   // security descriptor 
		&ftLastWriteTime);       // last write time 
	// 3. 循环遍历Uninstall目录下的子健
	int nCount = 1;
	DWORD dwIndex = 0;
	DWORD dwKeyLen = 255;
	DWORD dwType = 0;
	WCHAR szNewKeyName[MAX_PATH] = {};		// 注册表名称
	WCHAR strMidReg[MAX_PATH] = {};
	DWORD dwNamLen = 255;					// 获取键值
	HKEY hkValueKey = 0;
	LONG lRrturn = ERROR_SUCCESS;
	DWORD countnumber = 0;
	for (SIZE_T i = 0; i < cSubKeys; i++)
	{
		dwKeyLen = MAX_PATH;
		lRrturn = RegEnumKeyEx(hkResult, dwIndex, szNewKeyName, &dwKeyLen, 0, NULL, NULL, &ftLastWriteTimeA);
		// 2.1 通过得到子健的名称重新组合成新的子健路径
		swprintf_s(strMidReg, L"%s%s%s", lpSubKey, L"\\", szNewKeyName);
		// 2.2 打开新的子健, 获取其句柄
		RegOpenKeyEx(RootKey, strMidReg, 0, KEY_QUERY_VALUE, &hkValueKey);
		// 名字
		dwNamLen = 255;
		RegQueryValueEx(hkValueKey, L"DisplayName", 0, &dwType, (LPBYTE)SoftInfo.szSoftName, &dwNamLen);
		lstrcpyW(softwareinfo[countnumber].szSoftName, SoftInfo.szSoftName);
		// 版本号
		dwNamLen = 255;
		RegQueryValueEx(hkValueKey, L"VersionNumber", 0, &dwType, (LPBYTE)SoftInfo.szSoftVer, &dwNamLen);
		lstrcpyW(softwareinfo[countnumber].szSoftVer, SoftInfo.szSoftVer);
		// 安装时间
		dwNamLen = 255;
		RegQueryValueEx(hkValueKey, L"Time", 0, &dwType, (LPBYTE)SoftInfo.szSoftDate, &dwNamLen);
		lstrcpyW(softwareinfo[countnumber].szSoftDate, SoftInfo.szSoftDate);
		// 大小
		dwNamLen = 255;
		RegQueryValueEx(hkValueKey, L"Sizeof", 0, &dwType, (LPBYTE)SoftInfo.szSoftSize, &dwNamLen);
		lstrcpyW(softwareinfo[countnumber].szSoftSize, SoftInfo.szSoftSize);
		// 发布商
		dwNamLen = 255;
		RegQueryValueEx(hkValueKey, L"Sizeof", 0, &dwType, (LPBYTE)SoftInfo.strSoftVenRel, &dwNamLen);
		lstrcpyW(softwareinfo[countnumber].strSoftVenRel, SoftInfo.strSoftVenRel);
		// 卸载路径
		dwNamLen = 255;
		RegQueryValueEx(hkValueKey, L"UninstallString", 0, &dwType, (LPBYTE)SoftInfo.strSoftUniPath, &dwNamLen);
		lstrcpyW(softwareinfo[countnumber].strSoftUniPath, SoftInfo.strSoftUniPath);
		dwNamLen = 255;
		++dwIndex;
		++countnumber;
		if (0x1000 >= countnumber)
			break;
	}
	return countnumber;
}
bool UServerSoftware::EnumAll(LPVOID outbuf)
{
	if (!outbuf)
		return false;

	PUAllServerSoftware psinfo = PUAllServerSoftware(outbuf);
	psinfo->softwarenumber = this->EnumSoftware(psinfo->uUsoinfo);
	psinfo->servicenumber = this->EnumService(psinfo->uSericeinfo);

	return true;
}