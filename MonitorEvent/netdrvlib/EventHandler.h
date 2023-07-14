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

	void establishedPacket(const char* buf, int len) override;
	void datalinkPacket(const char* buf, int len) override;
	void tcpredirectPacket(const char* buf, int len) override;
};