#ifndef _SYSSSDT_H
#define _SYSSSDT_H

typedef struct _SSDTINFO
{
	short			ssdt_id;
	ULONGLONG		sstd_memaddr;
	LONG			sstd_memoffset;
}SSDTINFO, * PSSDTINFO;

typedef struct _SYSTEM_SERVICE_TABLE {
	PVOID  		ServiceTableBase;
	PVOID  		ServiceCounterTableBase;
	ULONGLONG  	NumberOfServices;
	PVOID  		ParamTableBase;
} SYSTEM_SERVICE_TABLE, * PSYSTEM_SERVICE_TABLE;

PSYSTEM_SERVICE_TABLE KeServiceDescriptorTable;

int Sstd_Init();
int Sstd_GetTableIndex();

#endif // !_SYSSSDT_H

