#include <sysinfo.h>
#include "FileDetailReader.h"
#pragma comment(lib, "Version.lib")

bool FileDetailReader::QueryValue(const std::string& ValueName, const std::string& szModuleName, std::string& RetStr)
{
	bool bSuccess = FALSE;
	BYTE* m_lpVersionData = NULL;
	DWORD m_dwLangCharset = 0;
	CHAR *tmpstr = NULL;

	do
	{
		if (!ValueName.size() || !szModuleName.size())
			break;

		DWORD dwHandle = 0;
		// �ж�ϵͳ�ܷ������ָ���ļ��İ汾��Ϣ
		DWORD dwDataSize = ::GetFileVersionInfoSizeA(szModuleName.c_str(), &dwHandle);
		if ((dwDataSize == 0) || !dwHandle)
			break;

		m_lpVersionData = new (std::nothrow) BYTE[dwDataSize];// ���仺����
		if (NULL == m_lpVersionData)
			break;

		// ������Ϣ
		if (!::GetFileVersionInfoA(szModuleName.c_str(), dwHandle, dwDataSize,
			(void*)m_lpVersionData))
			break;

		UINT nQuerySize;
		DWORD* pTransTable;
		// ��������
		if (!::VerQueryValueA(m_lpVersionData, "\\VarFileInfo\\Translation", (void **)&pTransTable, &nQuerySize))
			break;

		m_dwLangCharset = MAKELONG(HIWORD(pTransTable[0]), LOWORD(pTransTable[0]));
		if (m_lpVersionData == NULL)
			break;

		tmpstr = new (std::nothrow) CHAR[128];// ���仺����
		if (NULL == tmpstr)
			break;
		sprintf_s(tmpstr, 128, "\\StringFileInfo\\%08lx\\%s", m_dwLangCharset, ValueName.c_str());
		LPVOID lpData;

		// ���ô˺�����ѯǰ��Ҫ�����ε��ú���GetFileVersionInfoSize��GetFileVersionInfo
		if (::VerQueryValueA((void *)m_lpVersionData, tmpstr, &lpData, &nQuerySize))
			RetStr = (char*)lpData;

		bSuccess = TRUE;
	} while (FALSE);

	// ���ٻ�����
	if (m_lpVersionData)
	{
		delete[] m_lpVersionData;
		m_lpVersionData = NULL;
	}
	if (tmpstr)
	{
		delete[] tmpstr;
		tmpstr = NULL;
	}

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
