#pragma once
class ArkNetwork
{
public:
	ArkNetwork();
	~ArkNetwork();

	int nf_GetNteworkProcessInfo(LPVOID pData, const DWORD64 NetworkinfoSize);
};

