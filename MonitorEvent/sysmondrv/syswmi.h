#ifndef _SYSWMI_H
#define _SYSWMI_H

typedef struct _WMIINFO
{
	int processid;
}WMIINFO, * PWMIINFO;

typedef struct _WMIBUFFER
{
	LIST_ENTRY			pEntry;
	ULONG				dataLength;
	char*				dataBuffer;
}WMIBUFFER, * PWMIRBUFFER;

typedef struct _WMIDATA
{
	KSPIN_LOCK wmi_lock;
	LIST_ENTRY wmi_pending;
}WMIDATA, * PWMIDATA;

NTSTATUS Wmi_Init();
void Wmi_Free(void);
void Wmi_Clean(void);
void Wmi_SetMonitor(BOOLEAN code);
void Wmi_SetIpsMonitor(BOOLEAN code);

WMIBUFFER* Wmi_PacketAllocate(int lens);
void Wmi_PacketFree(WMIBUFFER* packet);

WMIDATA* wmictx_get();

#endif // !_SYSWMI_H
