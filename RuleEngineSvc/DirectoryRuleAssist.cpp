#include "pch.h"
#include "utiltools.h"
#include "DirectoryRuleAssist.h"

static const std::string g_DirectoryConfigName = "directoryRuleConfig.json";

const bool ConfigDirectoryJsonRuleParsing(std::string& strNameWhitelis, std::string& strNameBlacklis, std::string& strDirPathWhitelis, std::string& strDirPathBlacklis)
{
	if (!RuleEngineToos::InitDeviceDosPathToNtPath())
		return false;
	if (!RuleEngineToos::IsFile(g_DirectoryConfigName))
		return false;
	std::string strRet;
	if (!RuleEngineToos::GetCurrentExePath(strRet))
		return false;
	strRet.append("\\config\\");
	strRet.append(g_DirectoryConfigName.c_str());

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
	static std::string strStrings;
	do {
		DWORD dwRead = 0;
		if (!ReadFile(FileHandle, data, dwFileSize, &dwRead, NULL))
			break;
		rapidjson::Document document;
		document.Parse<0>(data);
		if (document.HasParseError())
			break;
		const auto rArray = document.GetArray();
		std::string strstrHex;
		// Add Flag
		strNameWhitelis.append("1");
		strDirPathWhitelis.append("2");
		strNameBlacklis.append("3");
		strDirPathBlacklis.append("4");
		for (rapidjson::SizeType idx = 0; idx < rArray.Size(); ++idx)
		{
			try
			{
				if (!rArray[idx].HasMember("FileIORuleMod") || !rArray[idx].HasMember("processName") || !rArray[idx].HasMember("Directory"))
					continue;
				const int Mods= rArray[idx]["FileIORuleMod"].GetInt();
				if (Mods == 1)
				{
					strNameWhitelis.append(rArray[idx]["processName"].GetString());
					RuleEngineToos::ReplayDeviceDosPathToNtPath(rArray[idx]["Directory"].GetString(), strDirPathWhitelis);
				}
				else if (Mods == 2)
				{
					strNameBlacklis.append(rArray[idx]["processName"].GetString());
					RuleEngineToos::ReplayDeviceDosPathToNtPath(rArray[idx]["Directory"].GetString(), strDirPathBlacklis);
				}
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
	return nRet;
}