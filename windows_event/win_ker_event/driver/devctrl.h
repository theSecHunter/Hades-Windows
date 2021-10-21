#ifndef _DEVCTRL_H
#define _DEVCTRL_H

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

void devctrl_ioThread(void* StartContext);
NTSTATUS devctrl_ioInit(PDRIVER_OBJECT DriverObject);

VOID devctrl_free();
VOID devctrl_clean();
void devctrl_ioThreadFree();
VOID devctrl_setShutdown();
VOID devctrl_setMonitor(BOOLEAN code);

void devctrl_pushversion(BOOLEAN code);
void devctrl_pushinfo(int code);

#endif // !_DEVCTRL_H
