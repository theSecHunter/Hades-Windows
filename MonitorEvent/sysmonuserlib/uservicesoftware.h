#pragma once
class UServerSoftware
{
public:
	UServerSoftware();
	~UServerSoftware();
	bool uf_EnumAll(LPVOID outbuf);
private:
	const DWORD EnumService(LPVOID outbuf);
	const DWORD EnumSoftware(LPVOID outbuf);
	const DWORD EnumSoftwareWo64(LPVOID outbuf, const int icount);
	const UINT DetermineContextForAllProducts();
};

