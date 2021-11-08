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

DRIVER_DISPATCH devctrl_dispatch;
NTSTATUS devctrl_dispatch(IN PDEVICE_OBJECT DeviceObject, IN PIRP irp);

NTSTATUS devctrl_init();
VOID devctrl_free();
VOID devctrl_clean();
VOID devctrl_setShutdown();
UINT64 devctrl_fillBuffer();
NTSTATUS devctrl_setmonitor(int flag);
NTSTATUS devtrl_popDataLinkData(UINT64* pOffset);
NTSTATUS devctrl_pushDataLinkCtxBuffer(int code);
NTSTATUS devctrl_pushFlowCtxBuffer(int code);
NTSTATUS devctrl_pushTcpCtxBuffer(int code);

#endif // ! _DEVCTRL_H
