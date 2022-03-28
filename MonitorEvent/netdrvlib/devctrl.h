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
	int devctrl_waitSingeObject();
	void devctrl_clean();
	int devctrl_InitshareMem();
	int devctrl_OnMonitor();
	PVOID64 get_Driverhandler();
	PVOID64 get_nfBufferPtr();

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

};

#endif // !_DEVCTRL_H