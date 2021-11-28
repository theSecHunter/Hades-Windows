#pragma once
class ArkFsd
{
public:
	ArkFsd();
	~ArkFsd();

	bool nf_GetFsdInfo(LPVOID outBuf, const DWORD Fsdinfosize);
};

