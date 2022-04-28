#pragma once

class HlprServerPip
{
	HlprServerPip();
	~HlprServerPip();

private:
	

public:
	int StartServerPip();
	int PipSendMsg(wchar_t* buf, const int bufLen);
	void PipClose();
};

