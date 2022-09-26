/*
	三种枚举方式 - 可以数据都统一采集
		1. 基于内核api(本质和2一样)
		2. 基于进程链表
		3. 基于句柄表
		4. 基于内存枚举
*/
#ifndef _SYSPROCESSINFO_H
#define _SYSPROCESSINFP_H

typedef struct _KERNEL_COPY_MEMORY_OPERATION
{
	INT32 targetProcessId;
	PVOID targetAddress;
	PVOID bufferAddress;
	INT32 bufferSize;
} KERNEL_COPY_MEMORY_OPERATION, * PKERNEL_COPY_MEMORY_OPERATION;

typedef struct _HANDLE_INFO {
	ULONG_PTR	ObjectTypeIndex;
	ULONG_PTR	HandleValue;
	ULONG_PTR	ReferenceCount;
	ULONG_PTR	GrantedAccess;
	ULONG_PTR	CountNum;
	ULONG_PTR	Object;
	ULONG		ProcessId;
	WCHAR		ProcessName[256 * 2];
	WCHAR		ProcessPath[256 * 2];
	//WCHAR		TypeName[256 * 2];
	//WCHAR		HandleName[256 * 2];
} HANDLE_INFO, * PHANDLE_INFO;

ULONG_PTR nf_GetProcessInfo(int Enumbool, HANDLE pid, PHANDLE_INFO pOutBuffer);
VOID nf_EnumModuleByPid(ULONG pid, PPROCESS_MOD ModBuffer);
int nf_DumpProcess(PKERNEL_COPY_MEMORY_OPERATION request);
NTSTATUS nf_KillProcess(ULONG hProcessId);

#endif