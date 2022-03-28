#pragma once
class ArkDpcTimer
{
public:
	ArkDpcTimer();
	~ArkDpcTimer();

	bool nf_GetDpcTimerData(LPVOID outBuf, const DWORD DpcTimerinfosize);
};

