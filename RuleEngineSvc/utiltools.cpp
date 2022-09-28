#include "pch.h"
#include "utiltools.h"
#include <string>
#include <direct.h>
#include <shlwapi.h>
#pragma comment(lib ,"Shlwapi.lib")

bool GetCurrentExePath(std::string& Path)
{
	char czFileName[1024] = { 0 };
	GetModuleFileNameA(NULL, czFileName, _countof(czFileName) - 1);
	PathRemoveFileSpecA(czFileName);
	Path = czFileName;
	if (Path.empty())
		return false;
	return true;
}

bool IsFile(const std::string& fileName)
{
	std::string strRet;
	if (!GetCurrentExePath(strRet))
		return false;
	strRet.append("\\config\\");
	strRet.append(fileName.c_str());

	const HANDLE FileHandle = CreateFileA(
		strRet.c_str(),
		GENERIC_READ | GENERIC_WRITE,
		0,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL
	);
	if (FileHandle)
	{
		CloseHandle(FileHandle);
		return true;
	}
	return false;
}

void SplitiStr(std::set<std::string>& vecProcesName, const std::string& sData)
{
	try
	{
		static std::string strSp;
		char* vector_routeip = strtok((char*)sData.data(), "|");
		while (vector_routeip != NULL)
		{
			strSp = vector_routeip;
			strSp.append("|");
			vecProcesName.insert(strSp);
			vector_routeip = strtok(NULL, "|");
		}
	}
	catch (const std::exception&)
	{
	}
}
