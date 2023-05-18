#pragma once
class UFile
{
public:
	UFile();
	~UFile();

	bool uf_GetFileInfo(char* pFilePath, LPVOID pData);
	bool uf_GetDirectoryFile(char* pDriPath, LPVOID pData);
};
