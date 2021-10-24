# win_ker_event

#### 监控回调：

###### 进程事件

PsSetCreateProcessNotifyRoutineEx:

###### 线程事件

PsSetCreateThreadNotifyRoutineEx

###### 注册表事件

CmRegisterCallbackEx

###### 模块事件

PsSetLoadImageNotifyRoutineEx

###### Boot

IoRegisterBootDriverCallback|SeRegisterImageVerificationCallback

###### Session

IoRegisterContainerNotification

###### NMI

KeRegisterNmiCallback

###### 关机

IoRegisterShutdownNotification

###### 电源管理

PoRegisterPowerSettingCallback

###### WMI

IoWMISetNotificationCallback

###### 其他

ObRegisterCallbacks、ObUnRegisterCallbacks

ExRegisterCallback(Callback\ProcessorAdd)

KeRegisterBoundCallback

FsRtlRegisterFileSystemFilterCallbacks

IoRegisterFsRegistrationChange

KeRegisterProcessorChangeCallback

应用层系统数据采集：https://github.com/TimelifeCzy/Windows-emergency-servicetools



#### Ark

###### SSDT

###### IDT

###### OBJ

###### Callback

###### IRP

###### FSD

###### PROCESSTREE

###### TIME

###### DPC
