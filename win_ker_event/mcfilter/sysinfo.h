#ifndef _SYSINFO_H
#define _SYSINFO_H

typedef struct _PROCESSINFO
{
	int processid;
	int endprocess;
	wchar_t processpath[260 * 2];
	wchar_t commandLine[260 * 2];
	wchar_t queryprocesspath[260 * 2];
}PROCESSINFO, * PPROCESSINFO;

typedef struct _THREADINFO
{
	int processid;
	int threadid;
	int createid;
}THREADINFO, * PTHREADINFO;

typedef struct _IMAGEMODINFO
{
    int		processid;
    __int64 imagebase;
    __int64	imagesize;
    int		systemmodeimage;
    wchar_t	imagename[260 * 2];
}IMAGEMODINFO, * PIMAGEMODINFO;

typedef enum _USER_REG_NOTIFY_CLASS {
    RegNtDeleteKey,
    RegNtPreDeleteKey = RegNtDeleteKey,
    RegNtSetValueKey,
    RegNtPreSetValueKey = RegNtSetValueKey,
    RegNtDeleteValueKey,
    RegNtPreDeleteValueKey = RegNtDeleteValueKey,
    RegNtSetInformationKey,
    RegNtPreSetInformationKey = RegNtSetInformationKey,
    RegNtRenameKey,
    RegNtPreRenameKey = RegNtRenameKey,
    RegNtEnumerateKey,
    RegNtPreEnumerateKey = RegNtEnumerateKey,
    RegNtEnumerateValueKey,
    RegNtPreEnumerateValueKey = RegNtEnumerateValueKey,
    RegNtQueryKey,
    RegNtPreQueryKey = RegNtQueryKey,
    RegNtQueryValueKey,
    RegNtPreQueryValueKey = RegNtQueryValueKey,
    RegNtQueryMultipleValueKey,
    RegNtPreQueryMultipleValueKey = RegNtQueryMultipleValueKey,
    RegNtPreCreateKey,
    RegNtPostCreateKey,
    RegNtPreOpenKey,
    RegNtPostOpenKey,
    RegNtKeyHandleClose,
    RegNtPreKeyHandleClose = RegNtKeyHandleClose,
    //
    // .Net only
    //    
    RegNtPostDeleteKey,
    RegNtPostSetValueKey,
    RegNtPostDeleteValueKey,
    RegNtPostSetInformationKey,
    RegNtPostRenameKey,
    RegNtPostEnumerateKey,
    RegNtPostEnumerateValueKey,
    RegNtPostQueryKey,
    RegNtPostQueryValueKey,
    RegNtPostQueryMultipleValueKey,
    RegNtPostKeyHandleClose,
    RegNtPreCreateKeyEx,
    RegNtPostCreateKeyEx,
    RegNtPreOpenKeyEx,
    RegNtPostOpenKeyEx,
    //
    // new to Windows Vista
    //
    RegNtPreFlushKey,
    RegNtPostFlushKey,
    RegNtPreLoadKey,
    RegNtPostLoadKey,
    RegNtPreUnLoadKey,
    RegNtPostUnLoadKey,
    RegNtPreQueryKeySecurity,
    RegNtPostQueryKeySecurity,
    RegNtPreSetKeySecurity,
    RegNtPostSetKeySecurity,
    //
    // per-object context cleanup
    //
    RegNtCallbackObjectContextCleanup,
    //
    // new in Vista SP2 
    //
    RegNtPreRestoreKey,
    RegNtPostRestoreKey,
    RegNtPreSaveKey,
    RegNtPostSaveKey,
    RegNtPreReplaceKey,
    RegNtPostReplaceKey,
    //
    // new to Windows 10
    //
    RegNtPreQueryKeyName,
    RegNtPostQueryKeyName,

    MaxRegNtNotifyClass //should always be the last enum
} USER_REG_NOTIFY_CLASS;
typedef struct _REGISTERINFO
{
	int processid;
    int threadid;
	int opeararg;
}REGISTERINFO, * PREGISTERINFO;

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

#define IO_SESSION_MAX_PAYLOAD_SIZE             256L

typedef enum _IO_SESSION_STATE {
    IoSessionStateCreated = 1,
    IoSessionStateInitialized,          // 2
    IoSessionStateConnected,            // 3
    IoSessionStateDisconnected,         // 4
    IoSessionStateDisconnectedLoggedOn, // 5
    IoSessionStateLoggedOn,             // 6
    IoSessionStateLoggedOff,            // 7
    IoSessionStateTerminated,           // 8
    IoSessionStateMax
} IO_SESSION_STATE, * PIO_SESSION_STATE;

typedef struct _IO_SESSION_STATE_INFORMATION {
    ULONG            SessionId;
    IO_SESSION_STATE SessionState;
    BOOLEAN          LocalSession;
} IO_SESSION_STATE_INFORMATION, * PIO_SESSION_STATE_INFORMATION;

typedef struct _SESSIONINFO
{
    int             processid;
    int             threadid;
    unsigned long	evens;
    char            iosessioninfo[sizeof(IO_SESSION_STATE_INFORMATION)];
}SESSIONINFO, * PSESSIONINFO;


enum AnRootkitId
{
    NF_SSDT_ID,                     // 0
    NF_IDT_ID,                      // 1
    NF_GDT_ID,                      // 2
    NF_DPC_ID,                      // 3
    NF_SYSCALLBACK_ID,              // 4
    NF_SYSPROCESSTREE_ID,           // 5
    NF_OBJ_ID,                      // 6
    NF_IRP_ID,                      // 7
    NF_FSD_ID,                      // 8
    NF_MOUSEKEYBOARD_ID,            // 9
    NF_NETWORK_ID,                  // 10
    NF_PROCESS_ENUM,                // 11
    NF_PROCESS_KILL,                // 12
    NF_PROCESS_INFO,                // 13
    NF_PE_DUMP,                     // 14
    NF_SYSMOD_ENUM,                 // 15
    NF_DRIVER_DUMP,                 // 16
    NF_EXIT = 100       
};

typedef struct _SSDTINFO
{
    short			ssdt_id;
    ULONGLONG		sstd_memaddr;
    LONG			sstd_memoffset;
}SSDTINFO, * PSSDTINFO;

typedef struct _IDTINFO
{
    int			    idt_id;
    ULONGLONG		idt_isrmemaddr;
}IDTINFO, * PIDTINFO;

#endif // !_SYSINFO_H
