#pragma once
class UServerSoftware
{
public:
	UServerSoftware();
	~UServerSoftware();
	bool uf_EnumAll(LPVOID outbuf);
private:
	const DWORD EnumService(LPVOID pData);
	const DWORD EnumSoftware(LPVOID pData);
	const DWORD EnumSoftwareWo64(LPVOID pData, const int iCount);
	const UINT DetermineContextForAllProducts();
};

