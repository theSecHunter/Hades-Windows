#ifndef _RDIRECTORY_H
#define _RDIRECTORY_H

void rDirectory_IpsInit();
void rDirectory_IpsClean();
void rDirectory_IpsCleanEx(const int flag);
BOOLEAN rDirectory_IsIpsProcessNameInList(const PWCHAR path, _In_ const BOOLEAN bModswhite, _In_ const BOOLEAN bModsblack, BOOLEAN* const bDProNameModsWhite, BOOLEAN* const bProNameModsBlack);
BOOLEAN rDirectory_IsIpsDirectNameInList(_In_ const PWCHAR FileDirectPath, BOOLEAN* bModswhite, BOOLEAN* bModsblack);
NTSTATUS rDirectory_SetIpsDirectRule(PIRP irp, PIO_STACK_LOCATION irpSp);

#endif
