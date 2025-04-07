#pragma once
#include <fstream>

class DataHandler
{
public:
	DataHandler();
	~DataHandler();

	bool PipInit();
	void PipFree();
	bool PipInitAnonymous();
	void PipFreeAnonymous();
	void DebugTaskInterface(const int taskid);

	bool ThreadPool_Init();
	bool ThreadPool_Free();

	// Recv PipCommand
	void OnPipMessageNotify(const std::shared_ptr<uint8_t>& data, size_t size);

	// Sub Data Handle
	void KerSublthreadProc();
	void EtwSublthreadProc();
	bool PTaskHandlerNotify(const DWORD taskid);

	// Set ExitEvent
	void SetExitSvcEvent(HANDLE& hexitEvent);

	// Check Drver
	const bool DrvCheckStatus();
	const bool NetCheckStatus();

private:
	typedef std::vector<HANDLE> tThreads;
	tThreads m_ker_subthreads;
	tThreads m_etw_subthreads;
	tThreads m_threads_write;

	HANDLE m_jobAvailableEvnet_WriteTask = NULL;
};

typedef struct _THREADPA_PARAMETER_NODE
{
	int nTaskId;
	DataHandler* pDataHandler;
	void clear()
	{
		nTaskId = 0;
		pDataHandler = nullptr;
	}
}THREADPA_PARAMETER_NODE, * PTHREADPA_PARAMETER_NODE;
