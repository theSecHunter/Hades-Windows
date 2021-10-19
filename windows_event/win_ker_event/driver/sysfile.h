#ifndef _SYSFILE_H
#define _SYSFILE_H

typedef struct _FILEINFO
{
	int				processid;
	int				threadid;

	// Msdn: https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_file_object
	unsigned char	LockOperation;
	unsigned char	DeletePending;
	unsigned char	ReadAccess;
	unsigned char	WriteAccess;
	unsigned char	DeleteAccess;
	unsigned char	SharedRead;
	unsigned char	SharedWrite;
	unsigned char	SharedDelete;
	unsigned long	flag;

	// DosName 
	wchar_t DosName[260];
	// FileName
	wchar_t FileName[260];

}FILEINFO, * PFILEINFO;

typedef struct _FILEBUFFER
{
	LIST_ENTRY			pEntry;
	ULONG				dataLength;
	char* dataBuffer;
}FILEBUFFER, * PFILEBUFFER;

typedef struct _FILEDATA
{
	KSPIN_LOCK file_lock;
	LIST_ENTRY file_pending;
}FILEDATA, * PFILEDATA;

typedef struct _LDR_DATA_TABLE_ENTRY64
{
    LIST_ENTRY64    InLoadOrderLinks;
    LIST_ENTRY64    InMemoryOrderLinks;
    LIST_ENTRY64    InInitializationOrderLinks;
    PVOID            DllBase;
    PVOID            EntryPoint;
    ULONG            SizeOfImage;
    UNICODE_STRING    FullDllName;
    UNICODE_STRING     BaseDllName;
    ULONG            Flags;
    USHORT            LoadCount;
    USHORT            TlsIndex;
    PVOID            SectionPointer;
    ULONG            CheckSum;
    PVOID            LoadedImports;
    PVOID            EntryPointActivationContext;
    PVOID            PatchInformation;
    LIST_ENTRY64    ForwarderLinks;
    LIST_ENTRY64    ServiceTagLinks;
    LIST_ENTRY64    StaticLinks;
    PVOID            ContextInformation;
    ULONG64            OriginalBase;
    LARGE_INTEGER    LoadTime;
} LDR_DATA_TABLE_ENTRY64, * PLDR_DATA_TABLE_ENTRY64;

NTSTATUS File_Init(PDRIVER_OBJECT pDriverObject);
void File_Free(void);
void File_Clean(void);
void File_SetMonitor(BOOLEAN code);

FILEBUFFER* File_PacketAllocate(int lens);
void File_PacketFree(FILEBUFFER* packet);

FILEDATA* filectx_get();

#endif