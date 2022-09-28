#include "pch.h"
#include "RegisterRuleAssist.h"
#include "utiltools.h"

const static std::string g_RegConfigName = "registerRuleConfig.json";

bool ConfigRegisterJsonRuleParsing(std::string& strProcessNameList)
{
	if (!IsFile(g_RegConfigName))
		return false;
	std::string strRet;
	if (!GetCurrentExePath(strRet))
		return false;
	strRet.append("\\config\\");
	strRet.append(g_RegConfigName.c_str());

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
	std::set<std::string> setAllProcessName;
	static std::string processName;
	do {
		DWORD dwRead = 0;
		if (!ReadFile(FileHandle, data, dwFileSize, &dwRead, NULL))
			break;
		rapidjson::Document document;
		document.Parse<0>(data);
		if (document.HasParseError())
			break;
		const auto rArray = document.GetArray();
		for (int idx = 0 ;  idx < rArray.Size(); ++idx)
		{
			try
			{
				if (!rArray[idx].HasMember("registerRuleMod") || !rArray[idx].HasMember("processName") || !rArray[idx].HasMember("registerValuse") || !rArray[idx].HasMember("permissions"))
					continue;
				rArray[idx]["registerRuleMod"].GetInt();
				processName = rArray[idx]["processName"].GetString();
				SplitiStr(setAllProcessName, processName);
				rArray[idx]["registerValuse"].GetString();
				rArray[idx]["permissions"].GetInt();
			}
			catch (const std::exception&)
			{
				continue;
			}
		}
		nRet = true;
	} while (false);

	if (FileHandle)
		CloseHandle(FileHandle);
	if (data)
		delete[] data;

	if (setAllProcessName.empty())
		return false;
	for (const auto& iter : setAllProcessName)
		strProcessNameList.append(iter.c_str());
	if (strProcessNameList.empty())
		return false;
	return nRet;
}