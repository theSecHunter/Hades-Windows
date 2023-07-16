#pragma once

#ifdef __cplusplus
extern "C" {
#endif

	class __declspec(dllexport) UFile
	{
	public:
		UFile();
		~UFile();

		const bool uf_GetFileInfo(char* pFilePath, LPVOID pData);
		const bool uf_GetDirectoryFile(char* pDriPath, LPVOID pData);
	};

#ifdef __cplusplus
}
#endif
