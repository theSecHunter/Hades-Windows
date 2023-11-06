#ifndef _RTHREAD_H
#define _RTHREAD_H

void rThrInject_IpsInit();
void rThrInject_IpsClean();
BOOLEAN rThrInject_IsIpsProcessNameInList(const PWCHAR path);
NTSTATUS rThrInject_SetIpsProcessName(PIRP irp, PIO_STACK_LOCATION irpSp);

#endif