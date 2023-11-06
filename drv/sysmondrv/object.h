#ifndef _OBJECT_H
#define _OBJECT_H

#include <ntddk.h>

typedef struct _OBJECT_TYPE_INITIALIZER
{
	USHORT Length;
	USHORT type;
	PVOID ObjectTypeCode;
	PVOID InvalidAttributes;
	GENERIC_MAPPING GenericMapping;
	PVOID ValidAccessMask;
	PVOID RetainAccess;
	POOL_TYPE PoolType;
	PVOID DefaultPagedPoolCharge;
	PVOID DefaultNonPagedPoolCharge;
	PVOID DumpProcedure;
	PVOID OpenProcedure;
	PVOID CloseProcedure;
	PVOID DeleteProcedure;
	PVOID ParseProcedure;
	PVOID SecurityProcedure;
	PVOID QueryNameProcedure;
	USHORT OkayToCloseProcedure;
} OBJECT_TYPE_INITIALIZER, *POBJECT_TYPE_INITIALIZER;

typedef struct _OBJECT_TYPE
{
	LIST_ENTRY TypeList;         //         : _LIST_ENTRY
	UNICODE_STRING Name;         //             : _UNICODE_STRING
	PVOID DefaultObject;         //    : Ptr32 Void
	ULONG Index;         //            : UChar
	ULONG TotalNumberOfObjects;         // : Uint4B
	ULONG TotalNumberOfHandles;         // : Uint4B
	ULONG HighWaterNumberOfObjects;         // : Uint4B
	ULONG HighWaterNumberOfHandles;         // : Uint4B
	OBJECT_TYPE_INITIALIZER TypeInfo;         //         : _OBJECT_TYPE_INITIALIZER
	PVOID TypeLock;         //         : _EX_PUSH_LOCK
	ULONG Key;         //              : Uint4B
	LIST_ENTRY CallbackList;         //     : _LIST_ENTRY
} OBJECT_TYPE, *POBJECT_TYPE;

typedef struct _OBJECT_CREATE_INFORMATION
{
	ULONG Attributes;
	HANDLE RootDirectory;
	KPROCESSOR_MODE ProbeMode;
	ULONG PagedPoolCharge;
	ULONG NonPagedPoolCharge;
	ULONG SecurityDescriptorCharge;
	PVOID SecurityDescriptor;
	PSECURITY_QUALITY_OF_SERVICE SecurityQos;
	SECURITY_QUALITY_OF_SERVICE SecurityQualityOfService;
} OBJECT_CREATE_INFORMATION, *POBJECT_CREATE_INFORMATION;

typedef struct _OBJECT_HEADER
{
	//对象头部的指针计数，对对象头指针引用的计数
	LONG_PTR PointerCount;
	union
	{
		//句柄引用计数
		LONG_PTR HandleCount;
		PVOID NextToFree;
	};
	POBJECT_TYPE Type;
	//OBJECT_HEADER_NAME_INFO相对于此结构的偏移
	UCHAR NameInfoOffset;
	//OBJECT_HEADER_HANDLE_INFO相对于此结构的偏移
	UCHAR HandleInfoOffset;
	//OBJECT_HEADER_QUOTA_INFO相对于此结构的偏移
	UCHAR QuotaInfoOffset;
	UCHAR Flags;

	union
	{
		//创建对象是用于创建对象附加头的结构
		//里面保存了和附加对象头类似的信息
		PVOID ObjectCreateInfo;
		PVOID QuotaBlockCharged;
	};
	PSECURITY_DESCRIPTOR SecurityDescriptor;
	QUAD Body;
} OBJECT_HEADER, *POBJECT_HEADER;

#endif