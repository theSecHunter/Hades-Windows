// 命令下发rootkit id
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
// 命令下发user id
enum USystemCollId
{
    UF_PROCESS_ENUM = 200,
    UF_PROCESS_PID_TREE,		    //201
    UF_SYSAUTO_START,			    //201
    UF_SYSNET_INFO,				    //203
    UF_SYSSESSION_INFO,			    //204
    UF_SYSINFO_ID,				    //205
    UF_SYSLOG_ID,				    //206
    UF_SYSUSER_ID,				    //207
    UF_SYSSERVICE_SOFTWARE_ID,	    //208
    UF_SYSFILE_ID,				    //209
    UF_FILE_INFO,				    //210
    UF_ROOTKIT_ID				    //211
};
// 主动上报kernel id
enum KIoctCode
{
    NF_PROCESS_INFO = 150,
    NF_THREAD_INFO,
    NF_IMAGEGMOD_INFO,
    NF_REGISTERTAB_INFO,
    NF_FILE_INFO,
    NF_SESSION_INFO
};
// 主动上报etw id
enum UEtwId
{
    UF_ETW_PROCESSINFO = 300,
    UF_ETW_THREADINFO,
    UF_ETW_IMAGEMOD,
    UF_ETW_NETWORK,
    UF_ETW_REGISTERTAB,
    UF_ETW_FILEIO
};
hboat可以测试下发指令:
Kernel：
100 - SSDT数据
101 - IDT数据
103 - DPC数据(有硬编码可能蓝屏 - 先别测试)
108 - FSD数据(IRP)
109 - MOUSEKEYBOARD(IRP)
110 - NETWORK 网络六元组，类似于应用层netstata -an
111 - PROCESS 进程
113 - PROCESSMOD 下发PID-检测进程加载的DLL，用于发掘应用层隐藏DLL
115 - SYSMOD 系统已加载模块DLL
User:
200 - 枚举系统进程
202 - 计划任务和自动启动项目(注册表)
203 - 系统存在的网络
207 - 系统存在的全部用户
208 - 系统存在的服务和安装的软件
209 - 文件目录路径，遍历文件(后面会有内核nfds)
210 - 文件绝对路径，获取文件完整属性
管理：
401 - ETW采集开启
402 - ETW采集关闭
403 - 内核采集开启
404 - 内核采集关闭
405 - 恶意行为拦截开启
406 - 恶意行为拦截关闭
407 - 进程规则重载
408 - 注册表规则重载
409 - 目录规则重载
410 - 线程注入规则重载
411 - 网络主防开启
412 - 网络主防关闭
413 - 网络规则重载
188 - 关闭HadesSvc