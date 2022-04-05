#ifndef _UETW_H
#define _UETW_H

class UEtw
{
public:
	UEtw();
	~UEtw();

	bool uf_init();
	bool uf_close();
	bool uf_RegisterTrace(const int dwEnableFlags);
	void uf_setqueuetaskptr(std::queue<UEtwBuffer*>& qptr);
	void uf_setqueuelockptr(std::mutex& qptrcs);
	void uf_setqueueeventptr(HANDLE& eventptr);
	unsigned long uf_setmonitor(const unsigned __int64 hSession, PVOID64 m_traceconfig, const int ioct);
};

#endif // !_UETW_H
