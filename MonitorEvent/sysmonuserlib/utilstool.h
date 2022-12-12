#pragma once
#include <string>

namespace UtilsTool
{
	const bool CGetCurrentDirectory(std::string& strDirpath);
	const bool WStr2Str(const std::wstring& wstr, std::string& converStr);
	const bool Str2WStr(const std::string& str, std::wstring& converStr);
	const bool GbkToUtf8(const char* src_str, std::string& strTostr);
	const bool Utf8ToGbk(const char* src_str, std::string& strTostr);
	const bool Utf8ToUnicode(const std::string& str, std::wstring& wstr);
}