#pragma once

class KNetWork
{
public:
	KNetWork();
	~KNetWork();

	const bool NetNdrInit();
	void NetNdrClose();
	const bool GetNetNdrStus();

public:
	void ReLoadDnsRule();
	void ReLoadIpPortConnectRule();
};