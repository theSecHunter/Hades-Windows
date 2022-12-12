#pragma once
class UServerSoftware
{
public:
	UServerSoftware();
	~UServerSoftware();
	bool uf_EnumAll(LPVOID outbuf);
private:
	DWORD EnumService(LPVOID outbuf);
	DWORD EnumSoftware(LPVOID outbuf);
};

