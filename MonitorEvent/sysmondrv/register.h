#ifndef _REGISTER_H
#define _REGISTER_H

// RegNtPreCreateKeyEx XP
// RegNtPreOpenKeyEx XP
typedef struct _REG_CREATE_KEY_INFORMATION {
	PUNICODE_STRING CompleteName;
	PVOID           RootObject;
	PVOID           ObjectType;
	ULONG           CreateOptions;
	PUNICODE_STRING Class;
	PVOID           SecurityDescriptor;
	PVOID           SecurityQualityOfService;
	ACCESS_MASK     DesiredAccess;
	ACCESS_MASK     GrantedAccess;
	PULONG          Disposition;
	PVOID* ResultObject;
	PVOID           CallContext;
	PVOID           RootObjectContext;
	PVOID           Transaction;
	PVOID           Reserved;
} REG_CREATE_KEY_INFORMATION, REG_OPEN_KEY_INFORMATION, * PREG_CREATE_KEY_INFORMATION, * PREG_OPEN_KEY_INFORMATION;

// RegNtPreCreateKeyEx >= Win7
// RegNtPreOpenKeyEx >= Win7
typedef struct _REG_CREATE_KEY_INFORMATION_V1 {
	PUNICODE_STRING CompleteName;
	PVOID           RootObject;
	PVOID           ObjectType;
	ULONG           Options;
	PUNICODE_STRING Class;
	PVOID           SecurityDescriptor;
	PVOID           SecurityQualityOfService;
	ACCESS_MASK     DesiredAccess;
	ACCESS_MASK     GrantedAccess;
	PULONG          Disposition;
	PVOID* ResultObject;
	PVOID           CallContext;
	PVOID           RootObjectContext;
	PVOID           Transaction;
	ULONG_PTR       Version;
	PUNICODE_STRING RemainingName;
	ULONG           Wow64Flags;
	ULONG           Attributes;
	KPROCESSOR_MODE CheckAccessMode;
} REG_CREATE_KEY_INFORMATION_V1, REG_OPEN_KEY_INFORMATION_V1, * PREG_CREATE_KEY_INFORMATION_V1, * PREG_OPEN_KEY_INFORMATION_V1;

// RegNtPreCreateKey
// RegNtPreOpenKey
typedef struct _REG_PRE_CREATE_KEY_INFORMATION {
	PUNICODE_STRING CompleteName;
} REG_PRE_CREATE_KEY_INFORMATION, REG_PRE_OPEN_KEY_INFORMATION, * PREG_PRE_CREATE_KEY_INFORMATION, * PREG_PRE_OPEN_KEY_INFORMATION;

// RegNtSetValueKey
typedef struct _REG_SET_VALUE_KEY_INFORMATION {
	PVOID           Object;
	PUNICODE_STRING ValueName;
	ULONG           TitleIndex;
	ULONG           Type;
	PVOID           Data;
	ULONG           DataSize;
	PVOID           CallContext;
	PVOID           ObjectContext;
	PVOID           Reserved;
} REG_SET_VALUE_KEY_INFORMATION, * PREG_SET_VALUE_KEY_INFORMATION;

// RegNtPreDeleteKey
typedef struct _REG_DELETE_KEY_INFORMATION {
	PVOID Object;
	PVOID CallContext;
	PVOID ObjectContext;
	PVOID Reserved;
} REG_DELETE_KEY_INFORMATION, * PREG_DELETE_KEY_INFORMATION, REG_FLUSH_KEY_INFORMATION, * PREG_FLUSH_KEY_INFORMATION;

// RegNtPostRenameKey
typedef struct _REG_POST_OPERATION_INFORMATION {
	PVOID    Object;
	NTSTATUS Status;
	PVOID    PreInformation;
	NTSTATUS ReturnStatus;
	PVOID    CallContext;
	PVOID    ObjectContext;
	PVOID    Reserved;
} REG_POST_OPERATION_INFORMATION, * PREG_POST_OPERATION_INFORMATION;
// RegNtRenameKey
typedef struct _REG_RENAME_KEY_INFORMATION {
	PVOID           Object;
	PUNICODE_STRING NewName;
	PVOID           CallContext;
	PVOID           ObjectContext;
	PVOID           Reserved;
} REG_RENAME_KEY_INFORMATION, * PREG_RENAME_KEY_INFORMATION;

// RegNtEnumerateKey
typedef struct _REG_ENUMERATE_KEY_INFORMATION {
	PVOID                 Object;
	ULONG                 Index;
	KEY_INFORMATION_CLASS KeyInformationClass;
	PVOID                 KeyInformation;
	ULONG                 Length;
	PULONG                ResultLength;
	PVOID                 CallContext;
	PVOID                 ObjectContext;
	PVOID                 Reserved;
} REG_ENUMERATE_KEY_INFORMATION, * PREG_ENUMERATE_KEY_INFORMATION;

typedef struct _REGISTERINFO
{
	int				processid;
	int				threadid;
	int				opeararg;
	wchar_t			ProcessPath[260 * 2];
	wchar_t			CompleteName[260 * 2];
}REGISTERINFO, * PREGISTERINFO;

typedef struct _REGISTERBUFFER
{
	LIST_ENTRY			pEntry;
	ULONG				dataLength;
	char*				dataBuffer;
}REGISTERBUFFER, * PREGISTERBUFFER;

typedef struct _REGISTERDATA
{
	KSPIN_LOCK register_lock;
	LIST_ENTRY register_pending;
}REGISTERDATA, * PREGISTERDATA;

NTSTATUS Register_Init(PDRIVER_OBJECT pDriverObject);
void Register_Free(void);
void Register_Clean(void);
void Register_SetMonitor(BOOLEAN code);
void Register_SetIpsMonitor(BOOLEAN code);
BOOLEAN Register_IsIpsProcessNameInList(const PWCHAR path);
NTSTATUS Register_SetIpsProcessName(PIRP irp, PIO_STACK_LOCATION irpSp);

REGISTERBUFFER* Register_PacketAllocate(int lens);
void Register_PacketFree(REGISTERBUFFER* packet);

REGISTERDATA* registerctx_get();

#endif // !_REGISTER_H
