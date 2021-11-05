# win_ker_event

#### 监控回调：

###### 进程事件

API: PsSetCreateProcessNotifyRoutineEx

**See Code: process.h process.c**

###### 线程事件

API: PsSetCreateThreadNotifyRoutine|PsRemoveCreateThreadNotifyRoutine

See Code: thread.h thread.c

###### 注册表事件

API: CmRegisterCallbackEx|CmUnRegisterCallback

**See Code: register.h register.c**

###### 模块事件

API: PsSetLoadImageNotifyRoutine|PsRemoveLoadImageNotifyRoutine

**See Code: imagemod.h imagemod.c**

###### Boot(未监控)

API: IoRegisterBootDriverCallback|SeRegisterImageVerificationCallback

###### Session

API: IoRegisterContainerNotification|IoUnregisterContainerNotification

**See Code: syssession.h syssession.c**

###### NMI(未监控)

API: KeRegisterNmiCallback

###### 关机(未监控)

API:IoRegisterShutdownNotification

###### 电源管理(未监控)

API:PoRegisterPowerSettingCallback

###### WMI

API: IoWMISetNotificationCallback

**See Code: syswmi.h syswmi.c**

###### 对象回调事件

API: ObRegisterCallbacks|ObUnRegisterCallbacks

**See Code:  sysfile.h sysfile.c   -- ObjectType: IoFileObjectType**

###### 其他(未监控)

ExRegisterCallback(Callback\ProcessorAdd)

KeRegisterBoundCallback

FsRtlRegisterFileSystemFilterCallbacks

IoRegisterFsRegistrationChange

KeRegisterProcessorChangeCallback

应用层系统数据采集：https://github.com/TimelifeCzy/Windows-emergency-servicetools



#### ArkTools

###### SSDT

- x64读取SSDTBase：Start: __readmsr(0xC0000082)   End: Start+0x500 
- 细节：准确说msr开启隔离模式读取出来是KiSystemCall64Shadow ，否则是KiSystemCall64，所以Shadow函数寻找SsdtBase需要其他处理，详细见代码。
- 枚举找到机器码标识：Call64: 4c8d15 & Call64Shadow：c3e9e35ce9ff
- 枚举当前系统内存已加载SSDT数据和重新加载MySSDT或PE文件偏移对比

**See Code:  sysssdt.h sysssdt.c**

###### IDT

- __sidt获取IDTR Struct
- 枚举Base IDT_ENTRY

**See Code:  sysidt.h sysidt.c**

###### MouseKeyBoard

- 	RtlInitUnicodeString(&kbdysName, L"\\Driver\\Kbdclass");
    	RtlInitUnicodeString(&i8042sysName, L"\\Driver\\i8042ptr");
    	RtlInitUnicodeString(&mousysName, L"\\Driver\\Mouclass");

**See Code:  sysenumnotify.h sysenumnotify.c**

###### FSD

- 	RtlInitUnicodeString(&fatsysName, L"\\FileSystem\\FastFat");
    	RtlInitUnicodeString(&ntfssysName, L"\\FileSystem\\Ntfs");

**See Code:  sysmousekeyboard.h sysmousekeyboard.c**

###### DpcTimer

- 老版本可以通过KeUpdateSystemTime拿到KiTimerTableListHead链表，枚举遍历，WIN7以上使用KPRCB结构或者readmsr(0xC0000101) + 0x20拿到KPRCB。
- x64 DPCBase有加密需要通过硬编码获取，详细见Code。

**See Code:  sysdpctimer.h sysdpctimer.c**

###### SysNotify

- Process_Notify

- Thread_Notify

- Minifilter_Notify

- Image_Notify

- Regsiter_Notify

- ObCall_Notify

- WFPCallout_Nofity

**See Code:  sysenumnotify.h sysenumnotify.c**

###### Process_Tree:

- process thread
- process image
- process memory
- process scan inliehook - iathook
- process dump

**See Code: sysprocesstree.h  sysprocesstree.c**

###### Hive

**See Code: syshive.h syshive.c**

###### SysNetwork

- xp:  tpc/udp查询IOCTL_TCP_QUERY_INFORMATION_EX，这里只是提供思路。
- win7/win10: 获取Nsi.sys对象，发送IOCTL_NSI_GETALLPARAM，原因如下：

```c++
IPHLPAPI.DLL:
GetExtendedTcpTable|GetExtendedUdpTable --> NsiAllocateAndGetTable --> NtDeviceIoControlFile("\\\\.\\Nsi.dll")
```

**See Code: sysnetwork.c sysnetwork.h**

