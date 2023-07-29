#pragma once
#include "nfevents.h"

class EventHandler : public NF_EventHandler
{
public:

	virtual void threadStart()
	{
	}
	virtual void threadEnd()
	{
	}

	void EstablishedPacket(const char* buf, int len) override;
	void DatalinkPacket(const char* buf, int len) override;
	void TcpredirectPacket(const char* buf, int len) override;
};