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

#endif // !_SYSINFO_H
