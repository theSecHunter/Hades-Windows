#include <sysinfo.h>
#include "FileDetailReader.h"
#include <vector>
#pragma comment(lib, "Version.lib")

bool FileDetailReader::QueryValue(const std::string& ValueName, const std::string& szModuleName, std::string& RetStr)
{
	bool bSuccess = FALSE;
	DWORD m_dwLangCharset = 0;

	do
	{
		if (!ValueName.size() || !szModuleName.size())
			break;

		DWORD dwHandle = 0;
		// 判断系统能否检索到指定文件的版本信息
		DWORD dwDataSize = ::GetFileVersionInfoSizeA(szModuleName.c_str(), &dwHandle);
		if (dwDataSize == 0)
			break;

		std::vector<BYTE> versionData(dwDataSize);

		// 检索信息
		if (!::GetFileVersionInfoA(szModuleName.c_str(), 0, dwDataSize, versionData.data()))
			break;

		UINT nQuerySize = 0;
		DWORD* pTransTable = nullptr;
		// 设置语言
		if (!::VerQueryValueA(versionData.data(), "\\VarFileInfo\\Translation", (void **)&pTransTable, &nQuerySize) ||
			!pTransTable || nQuerySize < sizeof(DWORD))
			break;

		m_dwLangCharset = MAKELONG(HIWORD(pTransTable[0]), LOWORD(pTransTable[0]));
		CHAR tmpstr[128] = { 0 };
		sprintf_s(tmpstr, "\\StringFileInfo\\%08lx\\%s", m_dwLangCharset, ValueName.c_str());
		LPVOID lpData = nullptr;

		// 调用此函数查询前需要先依次调用函数GetFileVersionInfoSize和GetFileVersionInfo
		if (::VerQueryValueA(versionData.data(), tmpstr, &lpData, &nQuerySize) && lpData)
			RetStr = (char*)lpData;

		bSuccess = TRUE;
	} while (FALSE);

	return bSuccess;
}
bool FileDetailReader::GetFileDescription(const std::string& szModuleName, std::string& RetStr)
{
	return QueryValue("FileDescription", szModuleName, RetStr);
}

bool FileDetailReader::GetFileVersion(const std::string& szModuleName, std::string& RetStr)
{
	return QueryValue("FileVersion", szModuleName, RetStr);
}

bool FileDetailReader::GetInternalName(const std::string& szModuleName, std::string& RetStr)
{
	return QueryValue("InternalName", szModuleName, RetStr);
}

bool FileDetailReader::GetCompanyName(const std::string& szModuleName, std::string& RetStr)
{
	return QueryValue("CompanyName", szModuleName, RetStr);
}

bool FileDetailReader::GetLegalCopyright(const std::string& szModuleName, std::string& RetStr)
{
	return QueryValue("LegalCopyright", szModuleName, RetStr);
}

bool FileDetailReader::GetOriginalFilename(const std::string& szModuleName, std::string& RetStr)
{
	return QueryValue("OriginalFilename", szModuleName, RetStr);
}

bool FileDetailReader::GetProductName(const std::string& szModuleName, std::string& RetStr)
{
	return QueryValue("ProductName", szModuleName, RetStr);
}

bool FileDetailReader::GetProductVersion(const std::string& szModuleName, std::string& RetStr)
{
	return QueryValue("ProductVersion", szModuleName, RetStr);
}

bool FileDetailReader::GetOEM(const std::string& szModuleName, std::string& RetStr)
{
	return QueryValue("oem", szModuleName, RetStr);
}
