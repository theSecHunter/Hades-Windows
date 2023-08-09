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
	HANDLE get_Driverhandler();
	PVOID64 get_nfBufferPtr();
	// Write Packet Data
	int devctrl_writeio(PNF_DATA pData);

private:
	DWORD  m_dwthreadid = 0;
	DWORD  m_dwthreadid1 = 0;
	HANDLE m_devhandler = NULL;
	HANDLE m_threadobjhandler = NULL;
	HANDLE m_alpcthreadobjhandler = NULL;
	HANDLE m_listthreadobjhandler = NULL;

	// Send Control Code
	int devctrl_sendioct(const int ioctcode);
};
#endif // !_DEVCTRL_H