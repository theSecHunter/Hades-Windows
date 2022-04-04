#ifndef _SYSINFO_H
#define _SYSINFO_H

#include <string>
using namespace std;


// kernel id
enum KIoctCode
{
    NF_PROCESS_INFO = 150,
    NF_THREAD_INFO,
    NF_IMAGEGMOD_INFO,
    NF_REGISTERTAB_INFO,
    NF_FILE_INFO,
    NF_SESSION_INFO
};
// rootkit id
enum KAnRootkitId
{
    NF_SSDT_ID = 100,               // 100 + 0
    NF_IDT_ID,                      // 100 + 1
    NF_GDT_ID,                      // 100 + 2
    NF_DPC_ID,                      // 100 + 3
    NF_SYSCALLBACK_ID,              // 100 + 4
    NF_SYSPROCESSTREE_ID,           // 100 + 5
    NF_OBJ_ID,                      // 100 + 6
    NF_IRP_ID,                      // 100 + 7
    NF_FSD_ID,                      // 100 + 8
    NF_MOUSEKEYBOARD_ID,            // 100 + 9
    NF_NETWORK_ID,                  // 100 + 10
    NF_PROCESS_ENUM,                // 100 + 11
    NF_PROCESS_KILL,                // 100 + 12
    NF_PROCESS_MOD,                 // 100 + 13
    NF_PE_DUMP,                     // 100 + 14
    NF_SYSMOD_ENUM,                 // 100 + 15
    NF_DRIVER_DUMP,                 // 100 + 16
    NF_EXIT = 1000
};
// user id
enum USystemCollId
{
    UF_PROCESS_ENUM = 200,
    UF_PROCESS_PID_TREE,
    UF_SYSAUTO_START,
    UF_SYSNET_INFO,
    UF_SYSSESSION_INFO,
    UF_SYSINFO_ID,
    UF_SYSLOG_ID,
    UF_SYSUSER_ID,
    UF_SYSSERVICE_SOFTWARE_ID,
    UF_SYSFILE_ID,
    UF_FILE_INFO,
    UF_ROOTKIT_ID
};
// etw id
enum UEtwId
{

};

//======================register kernel caloutback============================
// NF_PROCESS_INFO
typedef struct _PROCESSINFO
{
	int processid;
	int endprocess;
	wchar_t processpath[260 * 2];
	wchar_t commandLine[260 * 2];
	wchar_t queryprocesspath[260 * 2];
}PROCESSINFO, * PPROCESSINFO;
// NF_THREAD_INFO
typedef struct _THREADINFO
{
	int processid;
	int threadid;
	int createid;
}THREADINFO, * PTHREADINFO;
// NF_IMAGEGMOD_INFO
typedef struct _IMAGEMODINFO
{
    int		processid;
    __int64 imagebase;
    __int64	imagesize;
    int		systemmodeimage;
    wchar_t	imagename[260 * 2];
}IMAGEMODINFO, * PIMAGEMODINFO;
// NF_REGISTERTAB_INFO
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
// NF_FILE_INFO
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
// NF_SESSION_INFO
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

//============================rootkit struct============================
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
typedef struct _DPC_TIMERINFO
{
    ULONG_PTR	dpc;
    ULONG_PTR	timerobject;
    ULONG_PTR	timeroutine;
    ULONG		period;
}DPC_TIMERINFO, * PDPC_TIMERINFO;
typedef struct _NSI_STATUS_ENTRY
{
    ULONG  dwState;
    char bytesfill[8];
}NSI_STATUS_ENTRY, * PNSI_STATUS_ENTRY;
typedef struct _INTERNAL_TCP_TABLE_SUBENTRY
{
    char	bytesfill0[2];
    USHORT	Port;
    ULONG	dwIP;
    char	bytesfill[20];
}INTERNAL_TCP_TABLE_SUBENTRY, * PINTERNAL_TCP_TABLE_SUBENTRY;
typedef struct _INTERNAL_TCP_TABLE_ENTRY
{
    INTERNAL_TCP_TABLE_SUBENTRY localEntry;
    INTERNAL_TCP_TABLE_SUBENTRY remoteEntry;
}INTERNAL_TCP_TABLE_ENTRY, * PINTERNAL_TCP_TABLE_ENTRY;
typedef struct _NSI_PROCESSID_INFO
{
    ULONG dwUdpProId;
    ULONG UnknownParam2;
    ULONG UnknownParam3;
    ULONG dwTcpProId;
    ULONG UnknownParam5;
    ULONG UnknownParam6;
    ULONG UnknownParam7;
    ULONG UnknownParam8;
}NSI_PROCESSID_INFO, * PNSI_PROCESSID_INFO;
typedef struct _INTERNAL_UDP_TABLE_ENTRY
{
    char bytesfill0[2];
    USHORT Port;
    ULONG dwIP;
    char bytesfill[20];
}INTERNAL_UDP_TABLE_ENTRY, * PINTERNAL_UDP_TABLE_ENTRY;
typedef struct _SYSTPCINFO
{
    NSI_STATUS_ENTRY			socketStatus;
    NSI_PROCESSID_INFO			processinfo;
    INTERNAL_TCP_TABLE_ENTRY	TpcTable;
}SYSTPCINFO;
typedef struct _SYSUDPINFO
{
    NSI_PROCESSID_INFO			processinfo;
    INTERNAL_UDP_TABLE_ENTRY	UdpTable;
}SYSUDPINFO;
typedef struct _SYSNETWORKINFONODE
{
    DWORD			tcpcout;
    DWORD			udpcout;
    SYSTPCINFO		systcpinfo[1000];
    SYSUDPINFO		sysudpinfo[1000];
}SYSNETWORKINFONODE, * PSYSNETWORKINFONODE;
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
typedef struct _PROCESS_MOD
{
    ULONG	DllBase;
    ULONG	EntryPoint;
    ULONG	SizeOfImage;
    WCHAR	FullDllName[260];
    WCHAR	BaseDllName[260];
}PROCESS_MOD, * PPROCESS_MOD;
typedef struct _NOTIFY_INFO
{
    ULONG	Count; // 0号索引存放个数
    ULONG	CallbackType;
    ULONG64	CallbacksAddr;
    ULONG64	Cookie; // just work to cmpcallback
    CHAR	ImgPath[MAX_PATH];
}NOTIFY_INFO, * PNOTIFY_INFO;
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

//======================user struct============================
// u_autorun
typedef struct _URegRun
{
    CHAR szValueName[MAXBYTE];
    CHAR szValueKey[MAXBYTE];
}RegRun, * PURegRun;
typedef struct _UTaskSchedulerRun
{
    WCHAR szValueName[MAXBYTE];
    ULONG State;
    ULONG LastTime;
    ULONG NextTime;
    WCHAR TaskCommand[1024];
}UTaskSchedulerRun, *PUTaskSchedulerRun;
typedef struct _UAutoStartNode
{
    ULONG   regnumber;
    RegRun  regrun[1000];
    ULONG   taskrunnumber;
    UTaskSchedulerRun   taskschrun[1000];
}UAutoStartNode, * PUAutoStartNode;
// u_network
typedef struct _UNetTcpNode
{
    char  szrip[32];
    char  szlip[32];
    char  PidString[20];
    char  TcpState[32];
}UNetTcpNode, * PUNetTcpNode;
typedef struct _UNetUdpNode
{
    char  szrip[32];
    char  PidString[20];
}UNetUdpNode, * PUNetUdpNode;
typedef struct _UNetNode
{
    ULONG		tcpnumber;
    UNetTcpNode tcpnode[0x1024];
    ULONG		udpnumber;
    UNetUdpNode udpnode[0x1024];
}UNetNode, * PUNetNode;
// u_user
typedef struct _USysUserNode
{
    wchar_t serveruser[MAX_PATH];
    wchar_t servername[MAX_PATH];
    PSID    serverusid;
    DWORD   serveruflag;
}USysUserNode, * PUSysUserNode;
typedef struct _UUserNode
{
    ULONG usernumber;
    USysUserNode usernode[30];
}UUserNode, *PUUserNode;
// u_process
typedef struct _UProcessEnum
{
    int pid;
    int th32ParentProcessID;
    wchar_t szExeFile[MAX_PATH];
    char priclassbase[50];
    int threadcout;
    wchar_t fullprocesspath[MAX_PATH];
}UProcessEnum, * PUProcessEnum;
typedef struct _UProcessNode
{
    int processcount;
    UProcessEnum sysprocess[0x1024];
}UProcessNode, * PUProcessNode;
// u_software_service
typedef struct _USOFTINFO
{
    WCHAR szSoftName[50];				// 软件名称 
    WCHAR szSoftVer[50];				// 软件版本号
    WCHAR szSoftDate[20];				// 软件安装日期
    WCHAR szSoftSize[MAX_PATH];			// 软件大小
    WCHAR strSoftInsPath[MAX_PATH];		// 软件安装路径
    WCHAR strSoftUniPath[MAX_PATH];		// 软件卸载路径
    WCHAR strSoftVenRel[50];			// 软件发布厂商
    WCHAR strSoftIco[MAX_PATH];			// 软件图标路径
}USOFTINFO, * PUSOFTINFO;
typedef struct _UServicesNode
{
    wchar_t lpDisplayName[MAX_PATH];
    wchar_t lpServiceName[MAX_PATH];
    wchar_t lpBinaryPathName[MAX_PATH];
    wchar_t lpDescription[MAX_PATH];
    char dwCurrentState[50];
}UServicesNode, * PUServicesNode;
typedef struct _UAllServerSoftware {
    ULONG softwarenumber;
    USOFTINFO uUsoinfo[0x100];
    ULONG servicenumber;
    UServicesNode uSericeinfo[0x500];
}UAllServerSoftware, *PUAllServerSoftware;
// u_file
typedef struct _UFileInfo
{
    WCHAR cFileName[MAX_PATH];
    TCHAR seFileCreate[100];
    TCHAR seFileModify[100];
    TCHAR seFileAccess[100];
    TCHAR dwFileAttributes[20];
    TCHAR m_seFileSizeof[20];
    TCHAR dwFileAttributesHide[20];
    TCHAR md5[40];
}UFileInfo, * PUFileInfo;
typedef struct _UDriectFile
{
    ULONG filesize;
    wchar_t filename[MAX_PATH];
    wchar_t filepath[MAX_PATH * 2];
}UDriectFile, * PUDriectFile;
typedef struct _UDriectInfo
{
    DWORD   DriectAllSize;
    DWORD   FileNumber;
    UDriectFile fileEntry[0xffff];
}UDriectInfo, *PUDriectInfo;

//======================user etw============================
// u_etw_process
typedef struct _UEtwProcessInfo
{
    WCHAR  processPath[MAX_PATH * 2];
    UINT64 processId;
}UEtwProcessInfo, * PUEtwProcessInfo;
// u_etw_network
typedef USHORT ADDRESS_FAMILY;
#define FWP_BYTE_ARRAY6_SIZE 6
typedef struct FWP_BYTE_ARRAY16_
{
    UINT8 byteArray16[16];
} 	FWP_BYTE_ARRAY16;
typedef struct _UEtwNetWork
{
    ADDRESS_FAMILY addressFamily;
#pragma warning(push)
#pragma warning(disable: 4201) //NAMELESS_STRUCT_UNION
    union
    {
        FWP_BYTE_ARRAY16 localAddr;
        UINT32 ipv4LocalAddr;
    };
#pragma warning(pop)
    UINT16 toLocalPort;

    UINT8 protocol;

#pragma warning(push)
#pragma warning(disable: 4201) //NAMELESS_STRUCT_UNION
    union
    {
        FWP_BYTE_ARRAY16 RemoteAddr;
        UINT32 ipv4toRemoteAddr;
    };
#pragma warning(pop)
    UINT16 toRemotePort;

    WCHAR  processPath[MAX_PATH * 2];
    int	   processPathSize;
    ULONG  processId;
}UEtwNetWork, * PUEtwNetWork;


//======================public function============================
// wchar to string
void Wchar_tToString(std::string& szDst, wchar_t* wchar);

#endif // !_SYSINFO_H
