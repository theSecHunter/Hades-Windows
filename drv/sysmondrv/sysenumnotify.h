/*
* Minifilter_Notify
* WFP_Notify
* Process_Notify
* Thread_Notify
* Image_Notify
* ObCall_Notify
* Register_Nofity
*/
#ifndef _SYSENUMNOTIFY_H
#define _SYSENUMNOTIFY_H

#define MAX_PATH		260

typedef struct
{
	PVOID section;
	PVOID MappedBase;
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT PathLength;
	char ImageName[MAXIMUM_FILENAME_LENGTH];
}SYSTEM_MODULE, * PSYSTEM_MODULE;

typedef struct _NOTIFY_INFO
{
	ULONG	Count; // 0号索引存放个数
	ULONG	CallbackType;
	ULONG64	CallbacksAddr;
	ULONG64	Cookie; // just work to cmpcallback
	CHAR	ImgPath[MAX_PATH];
}NOTIFY_INFO, * PNOTIFY_INFO;

//typedef struct _FLT_OPERATION_REGISTRATION
//{
//	UCHAR	MajorFunction;
//	ULONG	Flags;
//	PVOID	PreOperation;
//	PVOID	PostOperation;
//	PVOID	Reserved1;
//} FLT_OPERATION_REGISTRATION, * PFLT_OPERATION_REGISTRATION;

//typedef struct _FLT_FILTER
//{
//	UCHAR buffer[1024];
//} FLT_FILTER, * PFLT_FILTER;

typedef struct _MINIFILTER_INFO
{
	ULONG	FltNum;	//过滤器的个数
	ULONG	IrpCount; // Irp的总数
	ULONG	Irp;
	ULONG64	Object;
	ULONG64	PreFunc;
	ULONG64	PostFunc;
	CHAR	PreImgPath[MAX_PATH];
	CHAR	PostImgPath[MAX_PATH];
}MINIFILTER_INFO, * PMINIFILTER_INFO;

//extern	NTSTATUS
//__fastcall
//FltEnumerateFilters
//(
//	PFLT_FILTER* FilterList,
//	ULONG FilterListSize,
//	PULONG NumberFiltersReturned
//);

//extern	NTSTATUS
//__fastcall
//FltObjectDereference
//(
//	PVOID FltObject
//);

VOID Enum_ProcessNotify(PNOTIFY_INFO pNotify);
VOID Enum_ThreadNotify(PNOTIFY_INFO pNotify);
VOID Enum_ResiterNotify(PNOTIFY_INFO pNotify);
VOID Enum_ObCalloutNotify(PNOTIFY_INFO pNotify);
VOID Enum_ImageModNotify(PNOTIFY_INFO pNotify);
VOID Enum_MinifilterNotify(PMINIFILTER_INFO pFltInfo);


#endif // !_SYSENUMNOTIFY_H
