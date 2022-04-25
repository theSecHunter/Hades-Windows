#ifndef _MINIFILTER_H
#define _MINIFILTER_H

NTSTATUS FsMini_Init(PDRIVER_OBJECT DriverObject);
NTSTATUS FsMini_Free();
NTSTATUS Mini_StartFilter();

#endif // !_MINIFILTER_H
