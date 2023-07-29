#ifndef _DEVCTRL_H
#define _DEVCTRL_H

typedef USHORT ADDRESS_FAMILY;
#define FWP_BYTE_ARRAY6_SIZE 6

class DevctrlIoct
{
public:
	DevctrlIoct();
	~DevctrlIoct();

	int devctrl_init();
	int devctrl_opendeviceSylink(const char* devSylinkName);
	int devctrl_workthread();
	int devctrl_waitSingeObject();
	void devctrl_clean();
	int devctrl_InitshareMem();
	int devctrl_OnMonitor();
	PVOID64 get_Driverhandler();
	PVOID64 get_nfBufferPtr();

public:
	const HANDLE GetDrvHandle();

private:
	DWORD  m_dwthreadid = 0;
	DWORD  m_dwthreadid1 = 0;
	HANDLE m_devhandler = NULL;
	HANDLE m_threadobjhandler = NULL;
	HANDLE m_alpcthreadobjhandler = NULL;
	HANDLE m_listthreadobjhandler = NULL;

	// ·¢ËÍ¿ØÖÆÂë
	int devctrl_sendioct(const int ioctcode);
	int devctrl_writeio();
};
#endif // !_DEVCTRL_H