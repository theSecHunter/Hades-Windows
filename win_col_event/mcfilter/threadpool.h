#ifndef _THREADPOOL_H
#define _THREADPOOL_H
#include "sync.h"
#include <Windows.h>
#include <vector>
#include <process.h>

class ThreadJob
{
public:
	virtual void execute() = 0;
};

class ThreadJobSource
{
public:
	virtual ThreadJob* getNextJob() = 0;
	virtual void jobCompleted(ThreadJob* pJob) = 0;
	virtual void threadStarted() = 0;
	virtual void threadStopped() = 0;
};

class ThreadPool
{
public:
	ThreadPool()
	{
		m_stopEvent.Attach(CreateEvent(NULL, TRUE, FALSE, NULL));
		m_pJobSource = NULL;
	}

	~ThreadPool()
	{
		free();
	}

	bool init(int threadCount, ThreadJobSource* pJobSource)
	{
		HANDLE hThread;
		unsigned threadId;
		int i;

		ResetEvent(m_stopEvent);

		m_pJobSource = pJobSource;

		if (threadCount <= 0)
		{
			SYSTEM_INFO sysinfo;
			GetSystemInfo(&sysinfo);

			threadCount = sysinfo.dwNumberOfProcessors;
			if (threadCount == 0)
			{
				threadCount = 1;
			}
		}

		for (i = 0; i < threadCount; i++)
		{
			hThread = (HANDLE)_beginthreadex(0, 0,
				_threadProc,
				(LPVOID)this,
				0,
				&threadId);

			if (hThread != 0 && hThread != (HANDLE)(-1L))
			{
				m_threads.push_back(hThread);
			}
		}

		return true;
	}

	void free()
	{
		SetEvent(m_stopEvent);

		for (tThreads::iterator it = m_threads.begin();
			it != m_threads.end();
			it++)
		{
			WaitForSingleObject(*it, INFINITE);
			CloseHandle(*it);
		}

		m_threads.clear();
	}

	void jobAvailable()
	{
		SetEvent(m_jobAvailableEvent);
	}

protected:

	void threadProc()
	{
		HANDLE handles[] = { m_jobAvailableEvent, m_stopEvent };
		ThreadJob* pJob;

		m_pJobSource->threadStarted();

		for (;;)
		{
			DWORD res = WaitForMultipleObjects(2, handles, FALSE, INFINITE);

			if (res == (WAIT_OBJECT_0 + 1))
				break;

			pJob = m_pJobSource->getNextJob();
			if (!pJob)
				continue;

			pJob->execute();

			m_pJobSource->jobCompleted(pJob);
		}

		m_pJobSource->threadStopped();
	}

	static unsigned WINAPI _threadProc(void* pData)
	{
		(reinterpret_cast<ThreadPool*>(pData))->threadProc();
		return 0;
	}

private:
	ThreadJobSource* m_pJobSource;

	typedef std::vector<HANDLE> tThreads;
	tThreads m_threads;

	AutoEventHandle m_jobAvailableEvent;
	AutoHandle m_stopEvent;
};


#endif // !_THREADPOOL_H
