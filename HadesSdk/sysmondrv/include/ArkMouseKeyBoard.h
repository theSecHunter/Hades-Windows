#pragma once
class ArkMouseKeyBoard
{
public:
	ArkMouseKeyBoard();
	~ArkMouseKeyBoard();

	int nf_GetMouseKeyInfoData(LPVOID pData, const DWORD MouseKeyboardinfoSize);
};

