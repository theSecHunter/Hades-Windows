#ifndef _UETW_H
#define _UETW_H

class UEtw
{
public:
	UEtw();
	~UEtw();


	bool uf_RegisterTrace(const int dwEnableFlags);
	bool uf_close();
	unsigned long uf_setmonitor(const unsigned __int64 hSession, PVOID64 m_traceconfig, const int ioct);

private:

};

#endif // !_UETW_H
