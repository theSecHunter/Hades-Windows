#pragma once
class UServerSoftware
{
public:
	UServerSoftware();
	~UServerSoftware();

	bool EnumAll(LPVOID outbuf);
	DWORD EnumService(LPVOID outbuf);
	DWORD EnumSoftware(LPVOID outbuf);

private:

};

