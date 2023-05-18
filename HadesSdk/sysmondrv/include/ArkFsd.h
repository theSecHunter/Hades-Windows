#pragma once
class ArkFsd
{
public:
	ArkFsd();
	~ArkFsd();

	bool nf_GetFsdInfo(LPVOID pData, const DWORD FsdinfoSize);
};

