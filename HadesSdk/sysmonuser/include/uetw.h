#ifndef _UETW_H
#define _UETW_H
#include <functional>

class UEtw
{
public:
	UEtw();
	~UEtw();

	bool uf_init();
	bool uf_close();
	bool uf_init(const bool flag);
	bool uf_close(const bool flag);
	void set_on_processMonitor(const std::function<void(const PROCESSINFO&)>& on_processinfo_data);

public:
	void uf_setqueuetaskptr(std::queue<UPubNode*>& qptr);
	void uf_setqueuelockptr(std::mutex& qptrcs);
	void uf_setqueueeventptr(HANDLE& eventptr);


protected:
	bool uf_RegisterTraceFile();
	bool uf_RegisterTrace(const int dwEnableFlags);
	unsigned long uf_setmonitor(const unsigned __int64 hSession, PVOID64 m_traceconfig, const int ioct);

private:
	TRACEHANDLE m_hFileSession;
};

#endif // !_UETW_H
