#ifndef _SYSSSDT_H
#define _SYSSSDT_H

typedef struct _SSDTINFO
{
	short			ssdt_id;
	ULONGLONG		sstd_memaddr;
	LONG			sstd_memoffset;
	// 地址是否有效
	BOOLEAN			ssdt_addrstatus;
}SSDTINFO, * PSSDTINFO;

#ifndef _WIN64
typedef  struct  _KSYSTEM_SERVICE_TABLE
{
	PULONG  ServiceTableBase;           // 函数地址表的首地址
	PULONG  ServiceCounterTableBase;    // 函数表中每个函数被调用的次数
	ULONG   NumberOfService;            // 服务函数的个数, NumberOfService * 4 就是整个地址表的大小
	UCHAR* ParamTableBase;				// 参数个数表首地址
} KSYSTEM_SERVICE_TABLE, * PKSYSTEM_SERVICE_TABLE;
#else
/*x64 UINT64*/
typedef  struct  _KSYSTEM_SERVICE_TABLE
{
	UINT64  ServiceTableBase;           // 函数地址表的首地址
	UINT64  ServiceCounterTableBase;    // 函数表中每个函数被调用的次数
	UINT64  NumberOfService;            // 服务函数的个数, NumberOfService * 4 就是整个地址表的大小
	UCHAR* ParamTableBase;				// 参数个数表首地址
} KSYSTEM_SERVICE_TABLE, * PKSYSTEM_SERVICE_TABLE;
#endif // !_WIN64

extern PKSYSTEM_SERVICE_TABLE KeServiceDescriptorTable;

int Sstd_Init();
int Sstd_GetTableInfo(SSDTINFO* MemBuffer);

#endif // !_SYSSSDT_H

