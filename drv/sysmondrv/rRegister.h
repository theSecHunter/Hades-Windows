#ifndef _RREGISTER_H
#define _RREGISTER_H

void rRegister_IpsInit();
void rRegister_IpsClean();
BOOLEAN rRegister_IsIpsProcessNameInList(const PWCHAR path);
NTSTATUS rRegister_SetIpsProcessName(PIRP irp, PIO_STACK_LOCATION irpSp);

#endif // !_RREGISTER_H
