#pragma once
#include <Windows.h>

class HlprMiniPortIpc
{
public:
	HlprMiniPortIpc();
	~HlprMiniPortIpc();

	// 等待驱动创建端口 - 连接
	void GetMsgNotifyWork();
	void StartMiniPortWaitConnectWork();
	bool SetRuleProcess(PVOID64 rulebuffer, unsigned int buflen, unsigned int processnamelen);

private:
};


