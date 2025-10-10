#ifndef _MINIFILTER_H
#define _MINIFILTER_H

NTSTATUS FsMiniInitialize(PDRIVER_OBJECT DriverObject);
NTSTATUS FsMiniCleanup();
NTSTATUS FsMiniFree();
NTSTATUS FsMiniStartFilter();

void	 FsFltSetDirectoryIpsMonitor(const BOOLEAN code);

#endif // !_MINIFILTER_H
