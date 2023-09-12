#ifndef  _DEVCTRL_H
#define  _DEVCTRL_H

#define CTL_DEVCTRL_ENABLE_MONITOR \
	CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_NEITHER, FILE_ANY_ACCESS)
#define CTL_DEVCTRL_STOP_MONITOR \
	CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_NEITHER, FILE_ANY_ACCESS)
#define CTL_DEVCTRL_OPEN_SHAREMEM \
	CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_NEITHER, FILE_ANY_ACCESS)
#define CTL_DEVCTRL_DISENTABLE_MONITOR \
	CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_NEITHER, FILE_ANY_ACCESS)

#define NF_TCP_PACKET_BUF_SIZE 8192
#define NF_UDP_PACKET_BUF_SIZE (2 * 65536)
#define PEND_LIMIT		(4 * NF_TCP_PACKET_BUF_SIZE)
#define UDP_PEND_LIMIT	(100 * NF_TCP_PACKET_BUF_SIZE)

DRIVER_DISPATCH devctrl_dispatch;
NTSTATUS devctrl_dispatch(IN PDEVICE_OBJECT DeviceObject, IN PIRP irp);

NTSTATUS devctrl_init();
VOID devctrl_free();
VOID devctrl_clean();
VOID devctrl_setShutdown();
void devctrl_sleep(UINT ttw);
UINT64 devctrl_fillBuffer();
NTSTATUS devctrl_setmonitor(int flag);
NTSTATUS devtrl_popDataLinkData(UINT64* pOffset);
NTSTATUS devctrl_pushEventQueryLisy(int code);

HANDLE devctrl_GetUdpInjectionHandle();
HANDLE devctrl_GetUdpNwV4InjectionHandle();
HANDLE devctrl_GetUdpNwV6InjectionHandle();

#endif // ! _DEVCTRL_H
