#ifndef _RDIRECTORY_H
#define _RDIRECTORY_H

void rDirectory_IpsInit();
void rDirectory_IpsClean();
BOOLEAN rDirectory_IsIpsDirectNameInList(_In_ const PWCHAR FileDirectPath, _Out_ int* mods);
BOOLEAN rDirectory_IsIpsProcessNameInList(const PWCHAR path, const int mods);
NTSTATUS rDirectory_SetIpsProcessName(PIRP irp, PIO_STACK_LOCATION irpSp);

#endif
