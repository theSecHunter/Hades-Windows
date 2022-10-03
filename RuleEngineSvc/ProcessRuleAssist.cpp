#include "pch.h"
#include "ProcessRuleAssist.h"
#include "utiltools.h"
#include <string>
#include <memory>

const static std::string g_ProcConfigName = "processRuleConfig.json";

bool ConfigProcessJsonRuleParsing(unsigned int& imods, std::string& strProcessNameList)
{
	if (!RuleEngineToos::IsFile(g_ProcConfigName))
		return false;
	std::string strRet;
	if (!RuleEngineToos::GetCurrentExePath(strRet))
		return false;
	strRet.append("\\config\\");
	strRet.append(g_ProcConfigName.c_str());

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
	//std::shared_ptr<uint8_t> data{ new uint8_t[dwFileSize] };
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
		if (!document.HasMember("processRuleMod") && document.HasMember("processName"))
			break;
		imods = document["processRuleMod"].GetInt();
		strProcessNameList = document["processName"].GetString();
		nRet = true;
	} while (false);

	if (FileHandle)
		CloseHandle(FileHandle);
	if (data)
		delete[] data;

	return nRet;
}