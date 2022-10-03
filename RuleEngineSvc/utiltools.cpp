#include "pch.h"
#include "utiltools.h"
#include <string>
#include <direct.h>
#include <shlwapi.h>
#include <atlconv.h>
#pragma comment(lib ,"Shlwapi.lib")

bool RuleEngineToos::GetCurrentExePath(std::string& Path)
{
	char czFileName[1024] = { 0 };
	GetModuleFileNameA(NULL, czFileName, _countof(czFileName) - 1);
	PathRemoveFileSpecA(czFileName);
	Path = czFileName;
	if (Path.empty())
		return false;
	return true;
}
bool RuleEngineToos::IsFile(const std::string& fileName)
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
void RuleEngineToos::SplitiStr(std::set<std::string>& vecProcesName, const std::string& sData)
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
std::string RuleEngineToos::String_ToUtf8(const std::string& str)
{
    try
    {
        int nwLen = ::MultiByteToWideChar(CP_ACP, 0, str.c_str(), -1, NULL, 0);
        wchar_t* pwBuf = new wchar_t[nwLen + 1];
        ZeroMemory(pwBuf, nwLen * 2 + 2);
        ::MultiByteToWideChar(CP_ACP, 0, str.c_str(), str.length(), pwBuf, nwLen);
        int nLen = ::WideCharToMultiByte(CP_UTF8, 0, pwBuf, -1, NULL, NULL, NULL, NULL);
        char* pBuf = new char[nLen + 1];
        ZeroMemory(pBuf, nLen + 1);
        ::WideCharToMultiByte(CP_UTF8, 0, pwBuf, nwLen, pBuf, nLen, NULL, NULL);
        std::string retStr(pBuf);
        delete[]pwBuf;
        delete[]pBuf;
        pwBuf = NULL;
        pBuf = NULL;
        return retStr;
    }
    catch (const std::exception&)
    {
    }
    return "";
}
std::string RuleEngineToos::UTF8_ToString(const std::string& str)
{
    try
    {
        int nwLen = MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, NULL, 0);
        wchar_t* pwBuf = new wchar_t[nwLen + 1];
        memset(pwBuf, 0, nwLen * 2 + 2);
        MultiByteToWideChar(CP_UTF8, 0, str.c_str(), str.length(), pwBuf, nwLen);
        int nLen = WideCharToMultiByte(CP_ACP, 0, pwBuf, -1, NULL, NULL, NULL, NULL);
        char* pBuf = new char[nLen + 1];
        memset(pBuf, 0, nLen + 1);
        WideCharToMultiByte(CP_ACP, 0, pwBuf, nwLen, pBuf, nLen, NULL, NULL);
        std::string retStr = pBuf;
        delete[]pBuf;
        delete[]pwBuf;
        pBuf = NULL;
        pwBuf = NULL;
        return retStr;
    }
    catch (const std::exception&)
    {
    }
    return "";
}
std::wstring RuleEngineToos::Str2WStr(const std::string& str)
{
    USES_CONVERSION;
    return A2W(str.c_str());
}
std::string RuleEngineToos::WStr2Str(const std::wstring& wstr)
{
    USES_CONVERSION;
    return W2A(wstr.c_str());
}
