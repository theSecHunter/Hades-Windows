#include "pch.h"
#include "utiltools.h"
#include <map>
#include <set>
#include <string>
#include <direct.h>
#include <shlwapi.h>
#include <atlconv.h>
#pragma comment(lib ,"Shlwapi.lib")

static std::map<const std::string, std::string> g_DevDosMap;

namespace
{
	template <typename Container>
	void SplitWithDelimiterSuffix(Container& output, const std::string& input)
	{
		size_t start = 0;
		while (start < input.size())
		{
			size_t end = input.find('|', start);
			const bool hasDelimiter = (end != std::string::npos);
			if (!hasDelimiter)
				end = input.size();

			if (end > start)
			{
				std::string token = input.substr(start, end - start);
				token.push_back('|');
				output.insert(output.end(), token);
			}

			if (!hasDelimiter)
				break;
			start = end + 1;
		}
	}
}

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
		GENERIC_READ,
		FILE_SHARE_READ,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL
	);
	if (FileHandle != INVALID_HANDLE_VALUE)
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
		SplitWithDelimiterSuffix(vecProcesName, sData);
	}
	catch (const std::exception&)
	{
	}
}
void RuleEngineToos::SplitiStr(std::vector<std::string>& vecProcesName, const std::string& sData)
{
	try
	{
		SplitWithDelimiterSuffix(vecProcesName, sData);
	}
	catch (const std::exception&)
	{
	}
}
std::string RuleEngineToos::String_ToUtf8(const std::string& str)
{
	try
	{
		wchar_t* pwBuf = nullptr;
		char* pBuf = nullptr;
		do
		{
			const int nwLen = ::MultiByteToWideChar(CP_ACP, 0, str.c_str(), -1, NULL, 0);
			if (nwLen <= 0)
				break;
			pwBuf = new wchar_t[nwLen + 1];
			if (!pwBuf)
				break;
			RtlSecureZeroMemory(pwBuf, sizeof(wchar_t) * (nwLen + 1));
			if (::MultiByteToWideChar(CP_ACP, 0, str.c_str(), -1, pwBuf, nwLen) <= 0)
				break;
			const int nLen = ::WideCharToMultiByte(CP_UTF8, 0, pwBuf, -1, NULL, 0, NULL, NULL);
			if (nLen <= 0)
				break;
			pBuf = new char[nLen + 1];
			if (!pBuf)
				break;
			RtlSecureZeroMemory(pBuf, nLen + 1);
			if (::WideCharToMultiByte(CP_UTF8, 0, pwBuf, -1, pBuf, nLen, NULL, NULL) <= 0)
				break;
		} while (false);
		std::string retStr = "";
		if (pBuf)
			retStr = pBuf;
		if (pwBuf)
			delete[] pwBuf;
		if (pBuf)
			delete[] pBuf;
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
		wchar_t* pwBuf = nullptr;
		char* pBuf = nullptr;
		do
		{
			const int nwLen = MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, NULL, 0);
			if (nwLen <= 0)
				break;
			pwBuf = new wchar_t[nwLen + 1];
			if (!pwBuf)
				break;
			memset(pwBuf, 0, sizeof(wchar_t) * (nwLen + 1));
			if (MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, pwBuf, nwLen) <= 0)
				break;
			const int nLen = WideCharToMultiByte(CP_ACP, 0, pwBuf, -1, NULL, 0, NULL, NULL);
			if (nLen <= 0)
				break;
			pBuf = new char[nLen + 1];
			if (!pBuf)
				break;
			memset(pBuf, 0, nLen + 1);
			if (WideCharToMultiByte(CP_ACP, 0, pwBuf, -1, pBuf, nLen, NULL, NULL) <= 0)
				break;
		} while (false);
		std::string retStr = "";
		if (pBuf)
			retStr = pBuf;
		if (pBuf)
			delete[] pBuf;
		if (pwBuf)
			delete[] pwBuf;
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
const bool RuleEngineToos::InitDeviceDosPathToNtPath()
{
	try
	{
		g_DevDosMap.clear();
		static TCHAR    szDriveStr[MAX_PATH] = { 0 };
		static TCHAR    szDevName[MAX_PATH] = { 0 };
		TCHAR            szDrive[3];
		INT             i;
		//获取本地磁盘字符串  
		ZeroMemory(szDriveStr, ARRAYSIZE(szDriveStr));
		ZeroMemory(szDevName, ARRAYSIZE(szDevName));
		if (GetLogicalDriveStrings(sizeof(szDriveStr), szDriveStr))
		{
			for (i = 0; szDriveStr[i]; i += 4)
			{
				if (!lstrcmpi(&(szDriveStr[i]), L"A:\\") || !lstrcmpi(&(szDriveStr[i]), L"B:\\"))
					continue;
				szDrive[0] = szDriveStr[i];
				szDrive[1] = szDriveStr[i + 1];
				szDrive[2] = '\0';
				if (!QueryDosDevice(szDrive, szDevName, MAX_PATH))//查询 Dos 设备名  
					return false;
				//cchDevName = lstrlen(szDevName);
				g_DevDosMap[WStr2Str(szDrive)] = WStr2Str(szDevName);
			}
			return true;
		}
		return false;
	}
	catch (...)
	{
		return false;
	}

}
void RuleEngineToos::ReplayDeviceDosPathToNtPath(_In_ const std::string& paths, _Out_ std::string& newpaths)
{
	// 切割
	std::vector<std::string> setDirPath;
	SplitiStr(setDirPath, paths);
	if (setDirPath.empty())
		return;
	size_t iIdex = 0; std::string strDevName;
	for (auto& vIter : setDirPath)
	{
		iIdex = vIter.find("\\");
		if (iIdex == std::string::npos)
			continue;
		strDevName = vIter.substr(0, iIdex);
		if (strDevName.empty())
			continue;
		const auto& iters = g_DevDosMap.find(strDevName);
		if (g_DevDosMap.end() == iters)
			continue;
		// 这里一定是开头0_否则规则配置错误
		vIter.replace(0, strDevName.size(), iters->second);
		newpaths.append(vIter.c_str());
	}
}
