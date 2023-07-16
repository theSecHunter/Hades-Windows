#include <Windows.h>
#include <string>
#include <msi.h>
#pragma comment(lib, "msi.lib")
#include "uservicesoftware.h"

#include <sysinfo.h>
using namespace std;

#define MAX_SERVICE_SIZE 1024 * 64
#define MAX_QUERY_SIZE   1024 * 8
static const HKEY RootKey = HKEY_LOCAL_MACHINE;
static const LPCTSTR lpSubKey = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall";
static const LPCTSTR lpSubKey64 = L"SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall";

UServerSoftware::UServerSoftware()
{
}
UServerSoftware::~UServerSoftware()
{
}

const DWORD UServerSoftware::EnumService(LPVOID pData)
{
	if (!pData)
		return FALSE;

	PUServicesNode const serinfo = (PUServicesNode)pData;
	DWORD count = 0;

	do {
		SC_HANDLE SCMan = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
		if (SCMan == NULL) {
			break;
		}
		LPENUM_SERVICE_STATUS service_status = nullptr;
		DWORD cbBytesNeeded = NULL;
		DWORD ServicesReturned = NULL;
		DWORD ResumeHandle = NULL;

		service_status = (LPENUM_SERVICE_STATUS)LocalAlloc(LPTR, MAX_SERVICE_SIZE);
		if (!service_status)
			break;

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
		for (int i = 0; i < static_cast<int>(ServicesReturned); i++) {

			lstrcpyW(serinfo[count].lpDisplayName, service_status[i].lpDisplayName);
			
			switch (service_status[i].ServiceStatus.dwCurrentState) { // 服务状态
			case SERVICE_CONTINUE_PENDING:
				strcpy_s(serinfo[count].dwCurrentState, "CONTINUE_PENDING");
				break;
			case SERVICE_PAUSE_PENDING:
				strcpy_s(serinfo[count].dwCurrentState, "PAUSE_PENDING");
				break;
			case SERVICE_PAUSED:
				strcpy_s(serinfo[count].dwCurrentState, "PAUSED");
				break;
			case SERVICE_RUNNING:
				strcpy_s(serinfo[count].dwCurrentState, "RUNNING");
				break;
			case SERVICE_START_PENDING:
				strcpy_s(serinfo[count].dwCurrentState, "START_PENDING");
				break;
			case SERVICE_STOPPED:
				strcpy_s(serinfo[count].dwCurrentState, "STOPPED");
				break;
			default:
				strcpy_s(serinfo[count].dwCurrentState, "UNKNOWN");
				break;
			}
			LPQUERY_SERVICE_CONFIG lpServiceConfig = NULL;          // 服务详细信息结构
			SC_HANDLE service_curren = NULL;                        // 当前的服务句柄
			LPSERVICE_DESCRIPTION lpqscBuf2 = NULL;					// 服务描述信息
			service_curren = OpenService(SCMan, service_status[i].lpServiceName, SERVICE_QUERY_CONFIG);        // 打开当前服务
			lpServiceConfig = (LPQUERY_SERVICE_CONFIG)LocalAlloc(LPTR, MAX_QUERY_SIZE);                        // 分配内存， 最大为8kb 

			if (!QueryServiceConfig(service_curren, lpServiceConfig, MAX_QUERY_SIZE, &ResumeHandle)) {
				break;
			}

			lstrcpyW(serinfo[count].lpServiceName, service_status[i].lpServiceName);
			lstrcpyW(serinfo[count].lpBinaryPathName, lpServiceConfig->lpBinaryPathName);

			DWORD dwNeeded = 0;
			if (QueryServiceConfig2(service_curren, SERVICE_CONFIG_DESCRIPTION, NULL, 0,
				&dwNeeded) == FALSE && GetLastError() == ERROR_INSUFFICIENT_BUFFER)
			{
				lpqscBuf2 = (LPSERVICE_DESCRIPTION)LocalAlloc(LPTR, MAX_QUERY_SIZE);
				if (QueryServiceConfig2(service_curren, SERVICE_CONFIG_DESCRIPTION,
					(BYTE*)lpqscBuf2, dwNeeded, &dwNeeded))
				{
					if (lpqscBuf2 && lpqscBuf2->lpDescription && lstrlenW(lpqscBuf2->lpDescription))
						lstrcpynW(serinfo[count].lpDescription, lpqscBuf2->lpDescription, MAX_PATH);
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
		if (service_status)
			LocalFree(service_status);
	} while (0);
	return count;
}
const DWORD UServerSoftware::EnumSoftware(LPVOID pData)
{
	DWORD dwCountNumber = 0;
	try
	{
		if (!pData)
			return 0;

		PUSOFTINFO const softwareinfo = (PUSOFTINFO)pData;
		if (!softwareinfo)
			return 0;

		HKEY hkResult = 0;
		const std::wstring lpSubKey = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall";
		const LSTATUS lRet = RegOpenKeyEx(HKEY_LOCAL_MACHINE, lpSubKey.c_str(), 0, KEY_ENUMERATE_SUB_KEYS | KEY_WOW64_32KEY | KEY_QUERY_VALUE, &hkResult);
		if (lRet != ERROR_SUCCESS)
			return false;

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
		DWORD cchValue = MAX_PATH;
		// Get the class name and the value count. 
		const LSTATUS retCode = RegQueryInfoKey(
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
		if (retCode != ERROR_SUCCESS)
		{
			if (hkResult)
				RegCloseKey(hkResult);
			return false;
		}

		USOFTINFO SoftInfo = { 0 };
		HKEY hkValueKey = 0;
		DWORD dwType = REG_SZ;
		DWORD dwKeyLen = MAX_PATH;
		WCHAR szNewKeyName[MAX_PATH] = { 0, };
		std::wstring strMidReg = L"";
		LSTATUS lRetCode = ERROR_SUCCESS;
		for (SIZE_T sIndex = 0; sIndex < cSubKeys; sIndex++)
		{
			do
			{
				dwKeyLen = MAX_PATH;
				lRetCode = RegEnumKeyEx(hkResult, sIndex, szNewKeyName, &dwKeyLen, 0, NULL, NULL, &ftLastWriteTime);
				if (lRetCode != ERROR_SUCCESS)
					break;
				strMidReg = lpSubKey + L"\\" + szNewKeyName;
				lRetCode = RegOpenKeyEx(HKEY_LOCAL_MACHINE, strMidReg.c_str(), 0, KEY_WOW64_32KEY | KEY_QUERY_VALUE, &hkValueKey);
				if (lRetCode != ERROR_SUCCESS)
					break;
				SoftInfo.clear();
				// 名字
				dwKeyLen = MAX_PATH;
				if (ERROR_SUCCESS == RegQueryValueEx(hkValueKey, L"DisplayName", 0, &dwType, (LPBYTE)SoftInfo.szSoftName, &dwKeyLen))
					lstrcpyW(softwareinfo[dwCountNumber].szSoftName, SoftInfo.szSoftName);
				else
				{
					lstrcpyW(softwareinfo[dwCountNumber].szSoftName, szNewKeyName);
				}
				// 版本号
				dwKeyLen = sizeof(SoftInfo.szSoftVer);
				if (ERROR_SUCCESS == RegQueryValueEx(hkValueKey, L"DisplayVersion", 0, &dwType, (LPBYTE)SoftInfo.szSoftVer, &dwKeyLen))
					lstrcpyW(softwareinfo[dwCountNumber].szSoftVer, SoftInfo.szSoftVer);
				dwKeyLen = sizeof(SoftInfo.szSoftVer);
				if (ERROR_SUCCESS == RegQueryValueEx(hkValueKey, L"VersionNumber", 0, &dwType, (LPBYTE)SoftInfo.szSoftVer, &dwKeyLen))
					lstrcpyW(softwareinfo[dwCountNumber].szSoftVer, SoftInfo.szSoftVer);
				// 安装时间
				dwKeyLen = sizeof(SoftInfo.szSoftDate);
				if (ERROR_SUCCESS == RegQueryValueEx(hkValueKey, L"HelpLink", 0, &dwType, (LPBYTE)SoftInfo.szSoftDate, &dwKeyLen))
					lstrcpyW(softwareinfo[dwCountNumber].szSoftDate, SoftInfo.szSoftDate);
				// 大小
				dwKeyLen = sizeof(SoftInfo.szSoftSize);
				if (ERROR_SUCCESS == RegQueryValueEx(hkValueKey, L"Size", 0, &dwType, (LPBYTE)SoftInfo.szSoftSize, &dwKeyLen))
					lstrcpyW(softwareinfo[dwCountNumber].szSoftSize, SoftInfo.szSoftSize);
				// 发布商
				dwKeyLen = sizeof(SoftInfo.strSoftVenRel);
				if (ERROR_SUCCESS == RegQueryValueEx(hkValueKey, L"Publisher", 0, &dwType, (LPBYTE)SoftInfo.strSoftVenRel, &dwKeyLen))
					lstrcpyW(softwareinfo[dwCountNumber].strSoftVenRel, SoftInfo.strSoftVenRel);
				// 卸载路径
				dwKeyLen = sizeof(SoftInfo.strSoftUniPath);
				if (ERROR_SUCCESS == RegQueryValueEx(hkValueKey, L"UninstallString", 0, &dwType, (LPBYTE)SoftInfo.strSoftUniPath, &dwKeyLen))
					lstrcpyW(softwareinfo[dwCountNumber].strSoftUniPath, SoftInfo.strSoftUniPath);
				++dwCountNumber;
			} while (false);
			if (hkValueKey)
			{
				RegCloseKey(hkValueKey);
				hkValueKey = 0;
			}
			strMidReg.clear();
			RtlSecureZeroMemory(szNewKeyName, MAX_PATH);

			// MAX For Count 0x1000
			if (sIndex >= 4095)
				break;
		}
		if (hkResult)
			RegCloseKey(hkResult);
		return dwCountNumber;
	}
	catch (const std::exception&)
	{
		return dwCountNumber;
	}
}
const DWORD UServerSoftware::EnumSoftwareWo64(LPVOID pData, const int iCount)
{
	if (iCount >= 4095)
		return 0;
	DWORD dwCountNumber = iCount, dwSucCount = 0;
	try
	{
		if (!pData)
			return 0;

		PUSOFTINFO const softwareinfo = (PUSOFTINFO)pData;
		if (!softwareinfo)
			return 0;

		HKEY hkResult = 0;
		const std::wstring lpSubKey = L"SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall";
		const LSTATUS lRet = RegOpenKeyEx(HKEY_LOCAL_MACHINE, lpSubKey.c_str(), 0, KEY_ENUMERATE_SUB_KEYS | KEY_WOW64_32KEY | KEY_QUERY_VALUE, &hkResult);
		if (lRet != ERROR_SUCCESS)
			return false;

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
		DWORD cchValue = MAX_PATH;
		// Get the class name and the value count. 
		const LSTATUS retCode = RegQueryInfoKey(
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
		if (retCode != ERROR_SUCCESS)
		{
			if (hkResult)
				RegCloseKey(hkResult);
			return false;
		}

		USOFTINFO SoftInfo = { 0 };
		HKEY hkValueKey = 0;
		DWORD dwType = 0;
		DWORD dwKeyLen = MAX_PATH;
		WCHAR szNewKeyName[MAX_PATH] = { 0, };
		std::wstring strMidReg = L"";
		LSTATUS lRetCode = ERROR_SUCCESS;
		for (SIZE_T sIndex = 0; sIndex < cSubKeys; sIndex++)
		{
			do
			{
				dwKeyLen = MAX_PATH;
				lRetCode = RegEnumKeyEx(hkResult, sIndex, szNewKeyName, &dwKeyLen, 0, NULL, NULL, &ftLastWriteTime);
				if (lRetCode != ERROR_SUCCESS)
					break;
				strMidReg = lpSubKey + L"\\" + szNewKeyName;
				lRetCode = RegOpenKeyEx(HKEY_LOCAL_MACHINE, strMidReg.c_str(), 0, KEY_WOW64_32KEY | KEY_QUERY_VALUE, &hkValueKey);
				if (lRetCode != ERROR_SUCCESS)
					break;
				SoftInfo.clear();
				// 名字
				dwKeyLen = sizeof(SoftInfo.szSoftName);
				if (ERROR_SUCCESS == RegQueryValueEx(hkValueKey, L"DisplayName", 0, &dwType, (LPBYTE)SoftInfo.szSoftName, &dwKeyLen))
					lstrcpyW(softwareinfo[dwCountNumber].szSoftName, SoftInfo.szSoftName);
				else
				{
					lstrcpyW(softwareinfo[dwCountNumber].szSoftName, szNewKeyName);
				}
				// 版本号
				dwKeyLen = sizeof(SoftInfo.szSoftVer);
				if (ERROR_SUCCESS == RegQueryValueEx(hkValueKey, L"DisplayVersion", 0, &dwType, (LPBYTE)SoftInfo.szSoftVer, &dwKeyLen))
					lstrcpyW(softwareinfo[dwCountNumber].szSoftVer, SoftInfo.szSoftVer);
				dwKeyLen = sizeof(SoftInfo.szSoftVer);
				if (ERROR_SUCCESS == RegQueryValueEx(hkValueKey, L"VersionNumber", 0, &dwType, (LPBYTE)SoftInfo.szSoftVer, &dwKeyLen))
					lstrcpyW(softwareinfo[dwCountNumber].szSoftVer, SoftInfo.szSoftVer);
				// 安装时间
				dwKeyLen = sizeof(SoftInfo.szSoftDate);
				if (ERROR_SUCCESS == RegQueryValueEx(hkValueKey, L"HelpLink", 0, &dwType, (LPBYTE)SoftInfo.szSoftDate, &dwKeyLen))
					lstrcpyW(softwareinfo[dwCountNumber].szSoftDate, SoftInfo.szSoftDate);
				// 大小
				dwKeyLen = sizeof(SoftInfo.szSoftSize);
				if (ERROR_SUCCESS == RegQueryValueEx(hkValueKey, L"Size", 0, &dwType, (LPBYTE)SoftInfo.szSoftSize, &dwKeyLen))
					lstrcpyW(softwareinfo[dwCountNumber].szSoftSize, SoftInfo.szSoftSize);
				// 发布商
				dwKeyLen = sizeof(SoftInfo.strSoftVenRel);
				if (ERROR_SUCCESS == RegQueryValueEx(hkValueKey, L"Publisher", 0, &dwType, (LPBYTE)SoftInfo.strSoftVenRel, &dwKeyLen))
					lstrcpyW(softwareinfo[dwCountNumber].strSoftVenRel, SoftInfo.strSoftVenRel);
				// 卸载路径
				dwKeyLen = sizeof(SoftInfo.strSoftUniPath);
				if (ERROR_SUCCESS == RegQueryValueEx(hkValueKey, L"UninstallString", 0, &dwType, (LPBYTE)SoftInfo.strSoftUniPath, &dwKeyLen))
					lstrcpyW(softwareinfo[dwCountNumber].strSoftUniPath, SoftInfo.strSoftUniPath);
				++dwCountNumber; ++dwSucCount;
			} while (false);
			if (hkValueKey)
			{
				RegCloseKey(hkValueKey);
				hkValueKey = 0;
			}
			strMidReg.clear();
			RtlSecureZeroMemory(szNewKeyName, MAX_PATH);

			// MAX For Count 0x1000
			if ((sIndex + iCount) >= 4095)
				break;
		}
		if (hkResult)
			RegCloseKey(hkResult);
		return dwSucCount;
	}
	catch (const std::exception&)
	{
		return dwSucCount;
	}
}
const UINT UServerSoftware::DetermineContextForAllProducts()
{
	const int cchGUID = 38;
	WCHAR wszProductCode[cchGUID + 1] = { 0 };
	WCHAR wszAssignmentType[10] = { 0 };
	DWORD cchAssignmentType =
		sizeof(wszAssignmentType) / sizeof(wszAssignmentType[0]);
	DWORD dwIndex = 0;

	DWORD cchProductName = MAX_PATH;
	WCHAR* lpProductName = new WCHAR[cchProductName];
	if (!lpProductName)
	{
		return ERROR_OUTOFMEMORY;
	}

	UINT uiStatus = ERROR_SUCCESS;

	// enumerate all visible products
	do
	{
		uiStatus = MsiEnumProducts(dwIndex,
			wszProductCode);
		if (ERROR_SUCCESS == uiStatus)
		{
			cchAssignmentType =
				sizeof(wszAssignmentType) / sizeof(wszAssignmentType[0]);
			BOOL fPerMachine = FALSE;
			BOOL fManaged = FALSE;

			// Determine assignment type of product
			// This indicates whether the product
			// instance is per-user or per-machine
			if (ERROR_SUCCESS ==
				MsiGetProductInfo(wszProductCode, INSTALLPROPERTY_ASSIGNMENTTYPE, wszAssignmentType, &cchAssignmentType))
			{
				if (L'1' == wszAssignmentType[0])
					fPerMachine = TRUE;
			}
			else
			{
				// This halts the enumeration and fails. Alternatively the error
				// could be logged and enumeration continued for the
				// remainder of the products
				uiStatus = ERROR_FUNCTION_FAILED;
				break;
			}

			// determine the "managed" status of the product.
			// If fManaged is TRUE, product is installed managed
			// and runs with elevated privileges.
			// If fManaged is FALSE, product installation operations
			// run as the user.
			if (ERROR_SUCCESS != MsiIsProductElevated(wszProductCode,
				&fManaged))
			{
				// This halts the enumeration and fails. Alternatively the error
				// could be logged and enumeration continued for the
				// remainder of the products
				uiStatus = ERROR_FUNCTION_FAILED;
				break;
			}

			// obtain the user friendly name of the product
			UINT uiReturn = MsiGetProductInfo(wszProductCode, INSTALLPROPERTY_PRODUCTNAME, lpProductName, &cchProductName);
			if (ERROR_MORE_DATA == uiReturn)
			{
				// try again, but with a larger product name buffer
				delete[] lpProductName;

				// returned character count does not include
				// terminating NULL
				++cchProductName;

				lpProductName = new WCHAR[cchProductName];
				if (!lpProductName)
				{
					uiStatus = ERROR_OUTOFMEMORY;
					break;
				}

				uiReturn = MsiGetProductInfo(wszProductCode, INSTALLPROPERTY_VERSIONSTRING, lpProductName, &cchProductName);
			}

			if (ERROR_SUCCESS != uiReturn)
			{
				// This halts the enumeration and fails. Alternatively the error
				// could be logged and enumeration continued for the
				// remainder of the products
				uiStatus = ERROR_FUNCTION_FAILED;
				break;
			}

			// output information
			//wprintf(L" Product %s:\n", lpProductName);
			//wprintf(L"\t%s\n", wszProductCode);
			//wprintf(L"\tInstalled %s %s\n",
			//	fPerMachine ? L"per-machine" : L"per-user",
			//	fManaged ? L"managed" : L"non-managed");
			//std::wstring output = lpProductName;
			//output.append(L" ").append(wszProductCode).append(L"\r\n");
			//OutputDebugString(output.c_str());
		}
		dwIndex++;
	} while (ERROR_SUCCESS == uiStatus);

	if (lpProductName)
	{
		delete[] lpProductName;
		lpProductName = NULL;
	}

	return (ERROR_NO_MORE_ITEMS == uiStatus) ? ERROR_SUCCESS : uiStatus;
}

const bool UServerSoftware::uf_EnumAll(LPVOID pData)
{
	if (!pData)
		return false;

	PUAllServerSoftware const pSinfo = PUAllServerSoftware(pData);
	if (pSinfo)
	{
		pSinfo->softwarenumber = this->EnumSoftware(pSinfo->uUsoinfo);
		pSinfo->softwarenumber += this->EnumSoftwareWo64(pSinfo->uUsoinfo, pSinfo->softwarenumber);
		pSinfo->servicenumber = this->EnumService(pSinfo->uSericeinfo);
	}
	return true;
}