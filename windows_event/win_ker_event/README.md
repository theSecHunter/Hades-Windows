# win_ker_event

#### 监控回调：

###### 进程事件

API: PsSetCreateProcessNotifyRoutineEx

See Code: process.h process.c

###### 线程事件

API: PsSetCreateThreadNotifyRoutine|PsRemoveCreateThreadNotifyRoutine

See Code: thread.h thread.c

###### 注册表事件

API: CmRegisterCallbackEx|CmUnRegisterCallback

See Code: register.h register.c

###### 模块事件

API: PsSetLoadImageNotifyRoutine|PsRemoveLoadImageNotifyRoutine

See Code: imagemod.h imagemod.c

###### Boot(未监控)

API: IoRegisterBootDriverCallback|SeRegisterImageVerificationCallback

###### Session

API: IoRegisterContainerNotification|IoUnregisterContainerNotification

See Code: syssession.h syssession.c

###### NMI(未监控)

API: KeRegisterNmiCallback

###### 关机(未监控)

API:IoRegisterShutdownNotification

###### 电源管理(未监控)

API:PoRegisterPowerSettingCallback

###### WMI

API: IoWMISetNotificationCallback

See Code: syswmi.h syswmi.c

###### 对象回调事件

API: ObRegisterCallbacks|ObUnRegisterCallbacks

See Code:  sysfile.h sysfile.c   -- ObjectType: IoFileObjectType

###### 其他(未监控)

ExRegisterCallback(Callback\ProcessorAdd)

KeRegisterBoundCallback

FsRtlRegisterFileSystemFilterCallbacks

IoRegisterFsRegistrationChange

KeRegisterProcessorChangeCallback

应用层系统数据采集：https://github.com/TimelifeCzy/Windows-emergency-servicetools



#### Ark

###### SSDT:

- x64读取SSDTBase：Start: __readmsr(0xC0000082)   End: Start+0x500 
- 枚举找到机器码标识：4c8d15
- 枚举系统已加载SSDT每个函数偏移
- 重新加载MySSDT获取真实的偏移或者解析PE获取偏移

See Code:  sysssdt.h sysssdt.c

###### IDT

- 

###### OBJ

###### Callback

###### IRP

###### FSD

###### PROCESSTREE

###### TIME

###### DPC
