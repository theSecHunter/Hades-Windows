#pragma once
class UFile
{
public:
	UFile();
	~UFile();

	bool uf_GetFileInfo(char* filePath, LPVOID outbuf);
	bool uf_GetDirectoryFile(char* DriPath, LPVOID outbuf);

private:

};
