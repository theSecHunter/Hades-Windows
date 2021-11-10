#ifndef _DEVCTRL_H
#define _DEVCTRL_H

extern HANDLE g_deviceHandle;

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
	// int devctrl_Alpcworkthread();
	int devctrl_waitSingeObject();
	void devctrl_clean();
	int devctrl_InitshareMem();
	void nf_setWfpCheckEventHandler(PVOID64 pHandler);
	int devctrl_OnMonitor();

private:
	HANDLE m_devhandler;
	HANDLE m_threadobjhandler;
	HANDLE m_alpcthreadobjhandler;
	HANDLE m_listthreadobjhandler;
	DWORD  m_dwthreadid;
	DWORD  m_dwthreadid1;

	// ·¢ËÍ¿ØÖÆÂë
	int devctrl_sendioct(const int ioctcode);
	int devctrl_writeio();
	PVOID get_eventhandler();

};

#endif // !_DEVCTRL_H