//
// 	NetFilterSDK 
// 	Copyright (C) 2014 Vitaly Sidorov
//	All rights reserved.
//
//	This file is a part of the NetFilter SDK.
//	The code and information is provided "as-is" without
//	warranty of any kind, either expressed or implied.
//

#pragma once

#include "threadpool.h"
#include <map>
#include <set>
#include <list>
#include "mempool.h"

typedef __int64 ENDPOINT_ID;

enum eEndpointType
{
	ET_UNKNOWN,
	ET_TCP,
	ET_UDP
};

//static NF_EventHandler* g_nfeventhandler = NULL;
//DevctrlIoct g_ctrobj;

inline eEndpointType getEndpointType(int code)
{
	return ET_UNKNOWN;
}
inline int getEventFlag(int code)
{
	return 1 << code;
}
inline bool isEventFlagEnabled(int flags, int code)
{
	return (flags & (1 << code)) != 0;
}

bool nf_pushInEvent(ENDPOINT_ID id, int code);
bool nf_pushOutEvent(ENDPOINT_ID id, int code);

class NFEvent : public ThreadJob
{
public:

	NFEvent(eEndpointType et, ENDPOINT_ID id, int flags)
	{
		m_et = et;
		m_id = id;
		m_flags = flags;
	}

	~NFEvent()
	{
	}

	virtual void execute()
	{
		NF_STATUS status;
		if (ET_TCP == m_et)
		{

		}
		else if (ET_UDP == m_et)
		{

		}
	}

	eEndpointType	m_et;
	ENDPOINT_ID		m_id;
	unsigned long	m_flags;
};
class NFEventOut : public ThreadJob
{
public:

	NFEventOut(eEndpointType et, ENDPOINT_ID id, int flags)
	{
		m_et = et;
		m_id = id;
		m_flags = flags;
	}

	~NFEventOut()
	{
	}

	virtual void execute()
	{
		NF_STATUS status;
		if (ET_TCP == m_et)
		{

		}
		else if (ET_UDP == m_et)
		{

		}
	}

	eEndpointType	m_et;
	ENDPOINT_ID		m_id;
	unsigned long	m_flags;
};

template <class EventType>
class EventQueue : public ThreadJobSource
{
public:
	EventQueue()
	{
		m_nThreads = 1;
		m_pending = false;

	}

	~EventQueue()
	{
	}

	bool init(int nThreads)
	{
		m_nThreads = nThreads;
		m_pending = false;
		return m_pool.init(nThreads, this);
	}

	void free()
	{
		m_pool.free();
	}

	void suspend(bool suspend)
	{
		AutoLock lock(m_cs);
		m_pending = suspend;
	}

	bool push(PNF_DATA pData)
	{
		AutoLock lock(m_cs);
		eEndpointType et = getEndpointType(pData->code);

		if (et == ET_TCP)
		{
			tEventFlags::iterator it = m_tcpEventFlags.find(pData->id);
			if (it != m_tcpEventFlags.end())
			{
				it->second |= getEventFlag(pData->code);
			} 
			else
			{
				m_tcpEventFlags[pData->id] = getEventFlag(pData->code);
				EventListItem eli = { pData->id, ET_TCP };
				m_eventList.push_back(eli);
			}
		} 
		else if (et == ET_UDP)
		{
			tEventFlags::iterator it = m_udpEventFlags.find(pData->id);
			if (it != m_udpEventFlags.end())
			{
				it->second |= getEventFlag(pData->code);
			} else
			{
				m_udpEventFlags[pData->id] = getEventFlag(pData->code);
				EventListItem eli = { pData->id, ET_UDP };
				m_eventList.push_back(eli);
			}
		}
		return true;
	}

	void processEvents()
	{
		if (!m_pending)
		{
			m_pool.jobAvailable();
		}
	}

	void wait(size_t maxQueueSize)
	{
		for (;;)
		{
			{
				AutoLock lock(m_cs);
				if ((m_eventList.size() + m_busyTCPEndpoints.size() + m_busyUDPEndpoints.size()) <= maxQueueSize)
					return;
			}

			WaitForSingleObject(m_jobCompletedEvent, 10 * 1000);
		}
	}

	virtual ThreadJob * getNextJob()
	{
		AutoLock lock(m_cs);

		EventType * pEvent = NULL;
		tEventFlags::iterator itf;
		int flags = 0;

		return NULL;
	}

	virtual void jobCompleted(ThreadJob * pJob)
	{
		AutoLock lock(m_cs);

		EventType * pEvent = (EventType*)pJob;

		if (pEvent->m_et == ET_TCP)
		{
			m_busyTCPEndpoints.erase(pEvent->m_id);
		} 
		else if (pEvent->m_et == ET_UDP)
		{
			m_busyUDPEndpoints.erase(pEvent->m_id);
		}

		mp_free(pEvent);
		SetEvent(m_jobCompletedEvent);

		if (!m_pending && !m_eventList.empty())
		{
			m_pool.jobAvailable();
		}
	}

	virtual void threadStarted()
	{
		g_pEventHandler->threadStart();
	}

	virtual void threadStopped()
	{
		g_pEventHandler->threadEnd();
	}

private:
	struct EventListItem
	{
		ENDPOINT_ID		id;
		eEndpointType	type;
	};

	typedef std::list<EventListItem> tEventList;
	tEventList m_eventList;

	typedef std::map<ENDPOINT_ID, int> tEventFlags;
	tEventFlags m_tcpEventFlags;
	tEventFlags m_udpEventFlags;

	typedef std::set<ENDPOINT_ID> tBusyEndpoints;
	tBusyEndpoints m_busyTCPEndpoints;
	tBusyEndpoints m_busyUDPEndpoints;

	AutoEventHandle m_jobCompletedEvent;
	bool m_pending;

	ThreadPool m_pool;

	int m_nThreads;

	AutoCriticalSection m_cs;
};