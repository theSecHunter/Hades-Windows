#pragma once
#include <string>
#include <vector>
#include <set>

namespace RuleEngineToos
{
	bool IsFile(const std::string& fileName);
	bool GetCurrentExePath(std::string& Path);
	void SplitiStr(std::set<std::string>& vecProcesName, const std::string& sData);
	void SplitiStr(std::vector<std::string>& vecProcesName, const std::string& sData);
	std::string String_ToUtf8(const std::string& str);
	std::string UTF8_ToString(const std::string& str);
	std::wstring Str2WStr(const std::string& str);
	std::string WStr2Str(const std::wstring& wstr);
	const bool InitDeviceDosPathToNtPath();
	void ReplayDeviceDosPathToNtPath(_In_ const std::string& paths, _Out_ std::string& newpaths);
}
