#pragma once
class ArkMouseKeyBoard
{
public:
	ArkMouseKeyBoard();
	~ArkMouseKeyBoard();

	int nf_GetMouseKeyInfoData(LPVOID outBuf, const DWORD MouseKeyboardinfosize);
};

