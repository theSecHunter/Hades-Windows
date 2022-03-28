#ifndef _SYSDRIVERINFO_H
#define _SYSDRIVERINFO_H

int nf_EnumSysDriver(PDEVICE_OBJECT pDevObj, PPROCESS_MOD ModBffer);
int nf_StopDriver();
int nf_UnDriver();
int nf_DumpDriverMemory();

#endif // !_SYSDRIVERINFO_H
