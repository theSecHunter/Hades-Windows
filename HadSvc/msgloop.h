#pragma once
class WinMsgLoop
{
public:
	WinMsgLoop();
	~WinMsgLoop();

	bool setKmsgLib(LPVOID ptrlib);
	bool setUmsgLib(LPVOID ptrlib);
};