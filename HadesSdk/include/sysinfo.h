#ifndef _SYSINFO_H
#define _SYSINFO_H
#include <Windows.h>
#include <string>
#include <vector>
#include <memory>

using namespace std;
// kernel id
enum KIoctCode
{
    NF_PROCESS_INFO = 150,
    NF_THREAD_INFO,
    NF_IMAGEGMOD_INFO,
    NF_REGISTERTAB_INFO,
    NF_FILE_INFO,
    NF_SESSION_INFO,
    NF_INJECT_INFO
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
    UF_PROCESS_PID_TREE,		    // 201
    UF_SYSAUTO_START,			    // 202
    UF_SYSNET_INFO,				    // 203
    UF_SYSSESSION_INFO,			    // 204
    UF_SYSINFO_ID,				    // 205
    UF_SYSLOG_ID,				    // 206
    UF_SYSUSER_ID,				    // 207
    UF_SYSSERVICE_SOFTWARE_ID,	    // 208
    UF_SYSFILE_ID,				    // 209
    UF_FILE_INFO,				    // 210
    UF_ROOTKIT_ID				    // 211
};
// etw id
enum UEtwId
{
    UF_ETW_PROCESSINFO = 300,       
    UF_ETW_THREADINFO,              // 301
    UF_ETW_IMAGEMOD,                // 302
    UF_ETW_NETWORK,                 // 303
    UF_ETW_REGISTERTAB,             // 304
    UF_ETW_FILEIO                   // 305
};

//======================register kernel calloutnotify============================
// NF_PROCESS_INFO
typedef struct _PROCESSINFO
{
    int parentprocessid;
    int pid;
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
    ULONG			processid;
    ULONG			threadid;
    ULONG			opeararg;
    PVOID			RootObject;
    PVOID           Object;
    ULONG			Type;
    ULONG			Attributes;
    ULONG			DesiredAccess;
    PULONG			Disposition;
    ULONG			GrantedAccess;
    ULONG           Options;
    ULONG           Wow64Flags;
    ULONG			KeyInformationClass;
    ULONG			Index;
    ULONG		    Status;
    wchar_t			ProcessPath[260 * 2];
    wchar_t			CompleteName[260 * 2];
    char			SetData[260 * 2];
    ULONG			DataSize;
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
typedef struct _INJECTINFO
{
    int             srcPid;
    int             dstPid;
    wchar_t			srcProcessPath[260 * 2];
    wchar_t			dstProcessPath[260 * 2];
}INJECTINFO, *PINJECTINFO;
//=======================rootkit struct===========================================
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
    ULONG	Count; // 0��������Ÿ���
    ULONG	CallbackType;
    ULONG64	CallbacksAddr;
    ULONG64	Cookie; // just work to cmpcallback
    CHAR	ImgPath[MAX_PATH];
}NOTIFY_INFO, * PNOTIFY_INFO;
typedef struct _MINIFILTER_INFO
{
    ULONG	FltNum;	//�������ĸ���
    ULONG	IrpCount; // Irp������
    ULONG	Irp;
    ULONG64	Object;
    ULONG64	PreFunc;
    ULONG64	PostFunc;
    CHAR	PreImgPath[MAX_PATH];
    CHAR	PostImgPath[MAX_PATH];
}MINIFILTER_INFO, * PMINIFILTER_INFO;

//======================user struct==================================================
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
    WCHAR szSoftName[MAX_PATH];			// ������� 
    WCHAR szSoftVer[50];				// ����汾��
    WCHAR szSoftDate[20];				// �����װ����
    WCHAR szSoftSize[MAX_PATH];			// �����С
    WCHAR strSoftInsPath[MAX_PATH];		// �����װ·��
    WCHAR strSoftUniPath[MAX_PATH];		// ���ж��·��
    WCHAR strSoftVenRel[50];			// �����������
    WCHAR strSoftIco[MAX_PATH];			// ���ͼ��·��
    void clear()
    {
        RtlZeroMemory(szSoftName, MAX_PATH);
        RtlZeroMemory(szSoftVer, 50);
        RtlZeroMemory(szSoftDate, 20);
        RtlZeroMemory(szSoftSize, MAX_PATH);
        RtlZeroMemory(strSoftInsPath, MAX_PATH);
        RtlZeroMemory(strSoftUniPath, MAX_PATH);
        RtlZeroMemory(strSoftVenRel, 50);
        RtlZeroMemory(strSoftIco, MAX_PATH);
    }
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
    USOFTINFO uUsoinfo[0x1000];
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
    void clear()
    {
        filesize = 0;
        RtlSecureZeroMemory(filename, MAX_PATH);
        RtlSecureZeroMemory(filepath, MAX_PATH * 2);
    }
}UDriectFile, * PUDriectFile;
typedef struct _UDriectInfo
{
    DWORD   DriectAllSize;
    DWORD   FileNumber;
    UDriectFile fileEntry[0x4096];
    void clear()
    {
        DriectAllSize = 0;
        FileNumber = 0;
    }
}UDriectInfo, *PUDriectInfo;

// ===================Topic============================
// pub head : ��Ϣ������ to Topic�ṹ
typedef struct _UPubNode
{
    int taskid;
    // ��������c99
    //char data[0];
    char data[1];
}UPubNode, * PUPubNode;
// Sub head : Topic to ������
typedef struct _USubNode
{
    int taskid;
    // �����л�����ָ��
    std::shared_ptr<std::string> data; 
}USubNode, * PUSubNode;

//======================User etw=======================
// u_etw_process
typedef struct _UEtwProcessInfo
{
    wchar_t         EventName[50];
    wchar_t         processName[MAX_PATH];		// ������
    wchar_t         processPath[MAX_PATH * 2];
    UINT64          processId;
    UINT64          parentId;
    bool            processStatus;		        // ����״̬(����/�˳�)
    void clear()
    {
        RtlSecureZeroMemory(EventName, sizeof(EventName));
        RtlSecureZeroMemory(processName, sizeof(processName));
        RtlSecureZeroMemory(processPath, sizeof(processPath));
        processId = 0;
        parentId = 0;
        processStatus = 0;
    }
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
    UINT16  toRemotePort;

    wchar_t     processPath[MAX_PATH * 2];
    int	        processPathSize;
    ULONG       processId;
    wchar_t     EventName[50];
    void clear()
    {
        toLocalPort = 0;
        protocol = 0;
        addressFamily = 0;
        ipv4LocalAddr = 0;
        ipv4toRemoteAddr = 0;
        toRemotePort = 0;
        processId = 0;
        processPathSize = 0;
        RtlSecureZeroMemory(processPath, sizeof(processPath));
        RtlSecureZeroMemory(EventName, sizeof(EventName));
    }
}UEtwNetWork, * PUEtwNetWork;
// u_etw_dns
#define WIN7_QUERY_START     1001
#define WIN7_QUERY_FAILED    1015
#define WIN7_CONFIG_CHANGE   1016
#define WIN7_RESPONSE_RECV   1019
#define WIN10_QUERY_START    3008
#define WIN10_RESPONSE_RECV  3009
#define WIN10_CONFIG_CHANGE  3020
typedef struct _UEwtDns {
    std::wstring    EventName;

    // ������Ϣ
    std::wstring    processPath;
    ULONG           processId;

    // Windows 7 �ض��ֶ�
    std::wstring Interface;
    std::wstring TotalServerCount;
    std::wstring Index;
    std::wstring DynamicAddress;
    std::wstring AddressLength;
    std::wstring Address;
    std::wstring Location;
    std::wstring Context;

    // Windows 10 ͨ���ֶ�
    std::wstring QueryName;
    std::wstring QueryType;
    std::wstring QueryOptions;
    std::wstring IsNetworkQuery;
    std::wstring NetworkQueryIndex;
    std::wstring InterfaceIndex;
    std::wstring IsAsyncQuery;
    std::wstring QueryStatus;
    std::wstring QueryResults;
    std::wstring IsParallelNetworkQuery;
    std::wstring NetworkIndex;
    std::wstring InterfaceCount;
    std::wstring AdapterName;
    std::wstring LocalAddress;
    std::wstring DNSServerAddress;
    std::wstring Status;

    void clear() {
        processId = 0;
        processPath.clear();
        EventName.clear();
        Interface.clear();
        TotalServerCount.clear();
        Index.clear();
        DynamicAddress.clear();
        AddressLength.clear();
        Address.clear();
        Location.clear();
        Context.clear();
        QueryName.clear();
        QueryType.clear();
        QueryOptions.clear();
        IsNetworkQuery.clear();
        NetworkQueryIndex.clear();
        InterfaceIndex.clear();
        IsAsyncQuery.clear();
        QueryStatus.clear();
        QueryResults.clear();
        IsParallelNetworkQuery.clear();
        NetworkIndex.clear();
        InterfaceCount.clear();
        AdapterName.clear();
        LocalAddress.clear();
        DNSServerAddress.clear();
        Status.clear();
    }
} UEwtDns;
// u_etw_image
typedef struct _UEtwImageInfo {
    UINT64 ImageBase;
    UINT64 ImageSize;
    UINT64 ProcessId;
    UINT64 SignatureLevel;
    UINT64 SignatureType;
    UINT64 ImageChecksum;
    UINT64 TimeDateStamp;
    UINT64 DefaultBase;
    wchar_t     FileName[MAX_PATH * 2];
    wchar_t     EventName[50];
    void clear()
    {
        ImageBase = 0;
        ImageSize = 0;
        ProcessId = 0;
        SignatureLevel = 0;
        SignatureType = 0;
        ImageChecksum = 0;
        TimeDateStamp = 0;
        DefaultBase = 0;
        RtlSecureZeroMemory(FileName, sizeof(FileName));
        RtlSecureZeroMemory(EventName, sizeof(EventName));
    }
}UEtwImageInfo, * PUEtwImageInfo;
// u_etw_thread
typedef struct _UEtwThreadInfo {
    UINT64 processId;
    UINT64 threadId;
    UINT64 Win32StartAddr;
    UINT64 ThreadFlags;
    wchar_t EventName[50];
    void clear()
    {
        processId = 0;
        threadId = 0;
        Win32StartAddr = 0;
        ThreadFlags = 0;
        RtlSecureZeroMemory(EventName, sizeof(EventName));
    }
}UEtwThreadInfo, * PUEtwThreadInfo;
// u_etw_register
typedef struct _UEtwRegisterTabInfo {
    UINT64 InitialTime;
    UINT64 Status;
    UINT64 Index;
    UINT64 KeyHandle;
    wchar_t     KeyName[MAX_PATH * 2];
    wchar_t     EventName[50];
    void clear()
    {
       InitialTime = 0;
       Status = 0;
       Index = 0;
       KeyHandle = 0;
       RtlSecureZeroMemory(KeyName, sizeof(KeyName));
       RtlSecureZeroMemory(EventName, sizeof(EventName));
    }
}UEtwRegisterTabInfo, * PUEtwRegisterTabInfo;
// u_etw_file_io
typedef struct _UEtwFileIoTabInfo {
    UINT64 Offset;
    UINT64 IrpPtr;
    UINT64 FileObject;
    UINT64 FileKey;
    UINT64 TTID;
    UINT64 PID;
    UINT64 CreateOptions;
    UINT64 ShareAccess;
    UINT64 FileAttributes;
    WCHAR  FileName[MAX_PATH];
    WCHAR  FilePath[MAX_PATH * 2];
    WCHAR  EventName[50];
    void clear()
    {
        Offset = 0;
        IrpPtr = 0;
        FileObject = 0;
        FileKey = 0;
        TTID = 0;
        PID = 0;
        CreateOptions = 0;
        ShareAccess = 0;
        FileAttributes = 0;
        RtlSecureZeroMemory(FileName, sizeof(FileName));
        RtlSecureZeroMemory(FilePath, sizeof(FilePath));
        RtlSecureZeroMemory(EventName, sizeof(EventName));
    }
}UEtwFileIoTabInfo, * PUEtwFileIoTabInfo;

//======================public function============================
// wchar to string
void Wchar_tToString(std::string& szDst, const wchar_t* wchar);


//======================Etw GUID===================================
DEFINE_GUID( /* 3d6fa8d0-fe05-11d0-9dda-00c04fd7ba7c */
    ProcessGuid,
    0x3d6fa8d0,
    0xfe05,
    0x11d0,
    0x9d, 0xda, 0x00, 0xc0, 0x4f, 0xd7, 0xba, 0x7c
);
DEFINE_GUID( /* 3d6fa8d1-fe05-11d0-9dda-00c04fd7ba7c */
    ThreadGuid,
    0x3d6fa8d1,
    0xfe05,
    0x11d0,
    0x9d, 0xda, 0x00, 0xc0, 0x4f, 0xd7, 0xba, 0x7c
);
DEFINE_GUID( /* 3d6fa8d2-fe05-11d0-9dda-00c04fd7ba7c */ /* Not used */
    HardFaultGuid,
    0x3d6fa8d2,
    0xfe05,
    0x11d0,
    0x9d, 0xda, 0x00, 0xc0, 0x4f, 0xd7, 0xba, 0x7c
);
DEFINE_GUID( /* 3d6fa8d3-fe05-11d0-9dda-00c04fd7ba7c */
    PageFaultGuid,
    0x3d6fa8d3,
    0xfe05,
    0x11d0,
    0x9d, 0xda, 0x00, 0xc0, 0x4f, 0xd7, 0xba, 0x7c
);
DEFINE_GUID( /* 3d6fa8d4-fe05-11d0-9dda-00c04fd7ba7c */
    DiskIoGuid,
    0x3d6fa8d4,
    0xfe05,
    0x11d0,
    0x9d, 0xda, 0x00, 0xc0, 0x4f, 0xd7, 0xba, 0x7c
);
DEFINE_GUID( /* 90cbdc39-4a3e-11d1-84f4-0000f80464e3 */
    FileIoGuid,
    0x90cbdc39,
    0x4a3e,
    0x11d1,
    0x84, 0xf4, 0x00, 0x00, 0xf8, 0x04, 0x64, 0xe3
);
DEFINE_GUID( /* 9a280ac0-c8e0-11d1-84e2-00c04fb998a2 */
    TcpIpGuid,
    0x9a280ac0,
    0xc8e0,
    0x11d1,
    0x84, 0xe2, 0x00, 0xc0, 0x4f, 0xb9, 0x98, 0xa2
);
DEFINE_GUID( /* bf3a50c5-a9c9-4988-a005-2df0b7c80f80 */
    UdpIpGuid,
    0xbf3a50c5,
    0xa9c9,
    0x4988,
    0xa0, 0x05, 0x2d, 0xf0, 0xb7, 0xc8, 0x0f, 0x80
);

DEFINE_GUID( /* 2cb15d1d-5fc1-11d2-abe1-00a0c911f518 */
    ImageLoadGuid,
    0x2cb15d1d,
    0x5fc1,
    0x11d2,
    0xab, 0xe1, 0x00, 0xa0, 0xc9, 0x11, 0xf5, 0x18
);

DEFINE_GUID( /* AE53722E-C863-11d2-8659-00C04FA321A1 */
    RegistryGuid,
    0xae53722e,
    0xc863,
    0x11d2,
    0x86, 0x59, 0x0, 0xc0, 0x4f, 0xa3, 0x21, 0xa1
);

//
// Special WMI events
//
DEFINE_GUID( /* 398191dc-2da7-11d3-8b98-00805f85d7c6 */
    TraceErrorGuid,
    0x398191dc,
    0x2da7,
    0x11d3,
    0x8b, 0x98, 0x00, 0x80, 0x5f, 0x85, 0xd7, 0xc6
);

typedef enum _MINI_COMMAND {
    SET_PROCESSNAME = 0,
    IPS_PROCESSSTART,
    IPS_REGISTERTAB,
    IPS_IMAGEDLL
}MIN_COMMAND;
const int WM_IPS_PROCESS = WM_USER + 600;

#endif // !_SYSINFO_H
