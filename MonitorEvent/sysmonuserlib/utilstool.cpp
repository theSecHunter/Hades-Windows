#include "utilstool.h"
#include <iostream>
#include <atlconv.h>
#include <codecvt>

const bool UtilsTool::CGetCurrentDirectory(std::string& strDirpath)
{
	try
	{
		// 获取当前目录路径
		char szModule[1024] = { 0, };
		GetModuleFileNameA(NULL, szModule, sizeof(szModule) / sizeof(char));
		strDirpath = szModule;
		if (0 >= strDirpath.size())
			return 0;
		size_t offset = strDirpath.rfind("\\");
		if (0 >= offset)
			return 0;
		strDirpath = strDirpath.substr(0, offset + 1);
		return true;
	}
	catch (const std::exception&)
	{
		return false;
	}
}

const bool UtilsTool::Str2WStr(const std::string& str, std::wstring& converStr)
{
	try
	{
		USES_CONVERSION;
		converStr = A2W(str.c_str());
		return true;
	}
	catch (const std::exception&)
	{
		return false;
	}
}

const bool UtilsTool::WStr2Str(const std::wstring& wstr, std::string& converStr)
{
	try
	{
		USES_CONVERSION;
		converStr = W2A(wstr.c_str());
		return true;
	}
	catch (const std::exception&)
	{
		return false;
	}
}

const bool UtilsTool::Utf8ToGbk(const char* src_str, std::string& strTostr)
{
	try
	{
		int len = MultiByteToWideChar(CP_UTF8, 0, src_str, -1, NULL, 0);
		wchar_t* wszGBK = new wchar_t[len + 1];
		memset(wszGBK, 0, len * 2 + 2);
		MultiByteToWideChar(CP_UTF8, 0, src_str, -1, wszGBK, len);
		len = WideCharToMultiByte(CP_ACP, 0, wszGBK, -1, NULL, 0, NULL, NULL);
		char* szGBK = new char[len + 1];
		memset(szGBK, 0, len + 1);
		WideCharToMultiByte(CP_ACP, 0, wszGBK, -1, szGBK, len, NULL, NULL);
		strTostr = szGBK;
		if (wszGBK) delete[] wszGBK;
		if (szGBK) delete[] szGBK;
		return true;
	}
	catch (const std::exception&)
	{
		return false;
	}
}

const bool UtilsTool::Utf8ToUnicode(const std::string& str, std::wstring& wstr)
{
	try {
		std::wstring_convert<std::codecvt_utf8<wchar_t>> wcv;
		wstr = wcv.from_bytes(str);
	}
	catch (const std::exception& e) {
		std::cerr << e.what() << std::endl;
		return false;
	}
	return true;
}