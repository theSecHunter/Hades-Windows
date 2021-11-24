#pragma once
class ArkNetwork
{
public:
	ArkNetwork();
	~ArkNetwork();

	int nf_GetNteworkProcessInfo(LPVOID outBuf, const DWORD64 Networkinfosize);
};

