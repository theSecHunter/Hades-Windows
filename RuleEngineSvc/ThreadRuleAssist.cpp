#include "pch.h"
#include "utiltools.h"
#include "ThreadRuleAssist.h"

static const std::string g_threadConfigName = "threadRuleConfig.json";

// parsing config to "InjectProcessNameArray"
const bool ConfigThreadJsonRuleParsing(std::string& strProcessNameList)
{
	if (!RuleEngineToos::IsFile(g_threadConfigName))
		return false;
	std::string strRet;
	if (!RuleEngineToos::GetCurrentExePath(strRet))
		return false;
	strRet.append("\\config\\");
	strRet.append(g_threadConfigName.c_str());

	const HANDLE FileHandle = CreateFileA(
		strRet.c_str(),
		GENERIC_READ,
		0,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL
	);
	if (!FileHandle)
		return false;

	DWORD dwGetSize = 0;
	const DWORD dwFileSize = GetFileSize(FileHandle, &dwGetSize);
	char* const data = new char[dwFileSize + 1];
	if (data)
		RtlSecureZeroMemory(data, dwFileSize + 1);
	else
	{
		CloseHandle(FileHandle);
		return false;
	}

	bool nRet = false;
	do {
		DWORD dwRead = 0;
		if (!ReadFile(FileHandle, data, dwFileSize, &dwRead, NULL))
			break;
		rapidjson::Document document;
		document.Parse<0>(data);
		if (document.HasParseError())
			break;
		if (!document.HasMember("InjectIpsProcessNameArray"))
			break;
		strProcessNameList = document["InjectIpsProcessNameArray"].GetString();
		nRet = true;
	} while (false);

	if (FileHandle)
		CloseHandle(FileHandle);
	if (data)
		delete[] data;

	return nRet;
}