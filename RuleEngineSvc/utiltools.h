#pragma once
#include <string>
#include <vector>
#include <set>

bool IsFile(const std::string& fileName);
bool GetCurrentExePath(std::string& Path);
void SplitiStr(std::set<std::string>& vecProcesName, const std::string& sData);
extern std::string String_ToUtf8(const std::string& str);
extern std::string UTF8_ToString(const std::string& str);
extern std::wstring Str2WStr(const std::string& str);
extern std::string WStr2Str(const std::wstring& wstr);