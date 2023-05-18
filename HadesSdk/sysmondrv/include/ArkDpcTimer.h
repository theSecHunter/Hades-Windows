#pragma once
class ArkDpcTimer
{
public:
	ArkDpcTimer();
	~ArkDpcTimer();

	bool nf_GetDpcTimerData(LPVOID pData, const DWORD DpcTimerinfoSize);
};

