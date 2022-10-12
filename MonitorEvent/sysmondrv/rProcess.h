#ifndef _RPROCESS_H
#define _RPROCESS_H

void rProcess_IpsInit();
void rProcess_IpsClean();
BOOLEAN rProcess_IsIpsProcessNameInList(const PWCHAR path);
NTSTATUS rProcess_SetIpsProcessName(PIRP irp, PIO_STACK_LOCATION irpSp);

#endif