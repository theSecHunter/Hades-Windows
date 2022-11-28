![image](https://github.com/theSecHunter/Hades-Windows/blob/main/Image/HadesWin_v2.0.png)
![image](https://github.com/theSecHunter/Hades-Windows/blob/main/Image/HadesWin_v2.0_Response.jpg)

**适用Win7/Win11 x32/x64用户态和内核态数据采集，XP未做兼容测试.**

### v1.0： 

单独引擎版本.

### v2.x： 
v1.0引擎重构，采集器分离用户态和内核态lib，HadesSvc数据引擎消费lib生产数据，组织格式(json和protobuf)。Duilib界面完善，WWin7/Win11系统兼容性完善。

Hboat支持Windows插件上报数据解析，GoAgent统一管理和上报，可作为插件下发。

GoAgent负责GRPC和WIN下插件管理(跨平台)：https://github.com/theSecHunter/Hades-Linux/tree/main

GoServer已合并新项目Hboat(跨平台): https://github.com/theSecHunter/Hboat

## 方案：
### Kernel

&emsp;&emsp;x64内核探针粗糙分为两类技术方案：

- 基于Intel-x/d虚拟化技术，绕过PG保护做花式Hook，功能强大-系统无痕。
- 基于微型过滤框架和注册回调，兼容性好/快速开发/接口完善。

&emsp;&emsp;项目采用过滤驱动+注册回调,方案中规中矩。有想过将VT Hook移植进来,不可控因素较多(不完善),有兴趣的可以跳转：https://github.com/TimelifeCzy/kHypervisorBasic

### User

&emsp;&emsp;System数据采集和ETW事件采集。

### 文档

| 文档             | 文件名                             | 版本|
| ---------------- | ---------------------------------- |----|
| 内核文档         | win_kernel_event.md                	|v2.0|
| 应用层文档       | win_user_event.md                  	|v2.0|
| ETW文档       | etw_event_struct.md                  	|v2.0|
| WFP文档          | win_wfp_event.md                   	|v1.0|
| 传输结构(c) | windows struct_c.md(see sysinfo.h) 		|v2.0|
| Hboat插件管理指令(Windows) | HboatCommand.md 			|v2.0|

### 框架:
![image](https://github.com/theSecHunter/Hades-Windows/blob/main/Image/image-windows.png)

<center><h2>v2.0</h2></center>

### 内核回调上抛事件 v2.0

| 事件   | 描述  |  进度  | 
| :----- | :---- | :----  |
| 进程   | 进程创建 - 销毁 - 进程数据 | 完成 |
| 线程   | 线程创建 - 销毁 - 线程数据  | 完成 |
| 注册表 | 删除 -  修改 - 枚举 - 重命名等 | 完成 |
| 模块 | DLL -  驱动 | 完成 |
| 会话 | 用户登录/退出/Session切换 | 完成 |
| 文件 | 文件读写访问  OS <= Windows7  (Windows8以上修改IoFileObjectType会触发PG) | 完成 |

### 内核接口采集事件 v2.0

| 事件       | 描述  |  进度  | 
| :----------- | :-------------------------- | :---- |
| 进程 - 线程 - 模块 - 内存 | 系统已运行的进程 - 线程 - 模块(DLL/SYS) | 完成 |
| IDT | 系统IDT  | 完成 |
| GDT | 系统GDT  | 完成 |
| SSDT/SSSDT | 系统SSDT | 完成 |
| FSD | FastFat/NTFS - 派遣函数内核地址 | 完成 |
| MouseKeyBoard | 鼠标键盘 - 派遣函数内核地址 | 完成 |
| DpcTimer | 遍历系统 DpcTimer | 完成 |
| Network | NSI提取IP:PORT | 完成 |
| - |  |  |
| 内核回调   | 进程/线程/映像/关机/MINIFILTER/WFP 通知| 开发中 |
| - |  |  |
| HIVE | hive注册表 - 开发中 | 未开发 |
| NTFS | ntfs文件解析 - 开发中 | 未开发 |

**注：Dpc硬编码，兼容性还未处理.**

### 应用接口采集事件 v2.0

前身：https://github.com/TimelifeCzy/Windows-emergency-servicetools 已集成该项目.

| 事件         | 描述 | 进度  | 
| :------------ | :--------------------------------- |:------------ | 
| 启动项       | 计划任务、注册表提取| 完成 |
| 网络连接     | 活跃TCP/UDP| 完成 |
| 进程树       | 活跃进程（线程、模块)| 完成 |
| 系统信息     | 系统基础信息(软/硬件信息等)| 完成 |
| 系统日志     | 应用程序日志、安全日志、系统日志数据| 待定 |
| 系统用户     | 系统用户| 完成 |
| 系统软件服务 | 已安装软件/服务| 完成 |
| - |  |  | 
| Rootkit_PE   | Rootkit相关PE文件地址解析,提取数据源Offset.| 开发中 |
| - |  |  | 
| 文件         | 列举指定目录下文件,可与NTFS数据对比.| 未开发 |

### 用户态ETW事件上抛 v2.0

| 事件     | 描述                            | 进度  | 
| :-------- | :------------------------------- |:-------- |
| 文件     | 创建、删除、读写                | 完成 |
| 注册表   | 创建、删除、读写                | 完成 |
| 进程树   | 进程、线程 - 创建/销毁/模块加载 | 完成 |
| 网络     | tcp/udp五要素                   | 完成 |

**Etw事件结构See: etw_event_struct.md**

### Duilib界面展示 v2.0
| 事件     | 描述                            | 进度  | 
| :-------- | :------------------------------- |:-------- |
| Cpu利用率|  动态刷新 |完成|
| 系统内存| 动态刷新|完成|
| 处理器详细|静态展示 |完成|
| 操作系统版本|静态展示 |完成|
| 当前用户|静态展示 |完成|
| 主板型号|静态展示 |完成|
| 显示器型号|静态展示 |完成|
| 电池|静态展示 |完成|
| 摄像头| 静态展示 |完成|
| 蓝牙| 静态展示|完成|
| - |  | |
| 麦克风| 静态展示|未开发|
| - |  | |
| GPU| 动态刷新|未开发|
| 磁盘I/O|动态刷新 |未开发|
| CPU温度| 动态刷新|未开发|
| 主板温度| 动态刷新|未开发|
| 显卡温度| 动态刷新|未开发|
| 硬盘温度| 动态刷新|未开发|
| 流量上传/下载|动态刷新 |未开发|

**Duilib展示数据不会上报, GoAgent上报CurrentSystemInfo**

### 驱动行为拦截 v2.0：
| 事件     | 描述                            | 进度  | 描述 | 引用代码 |
| -------- | ------------------------------- |-------- | -------- |-------- |
| 进程拦截|  自定义进程 | 完成| 基于回调 | |
| 注册表拦截|  自定义注册表 | 完成| 基于回调 | |
| 目录保护|  目录和子目录/文件 | 完成| 基于MiniFilter| |
| - |  | | |
| 注入检测 |  CreteRemote/内存 | 进行中| 基于回调 | https://bbs.pediy.com/thread-193437.htm <br> https://github.com/huoji120/CobaltStrikeDetected/ |


### HIPS

**服务端管理规则随着插件下发,HadesSvc.exe解析规则写入内核. 支持规则热更新(Hboat下发). 开发中预计v2.4之前全部完成。**

**白名单模式：启动规则后(不包含已存在进程)，只允许白名单定义的规则操作。**

**黑名单模式：启动规则后(不包含已存在进程)，不允许黑名单定义的规则操作。**

#### 进程黑白名单模式(内核规则匹配)
```
{
	// 1白名单,2黑名单
	"processRuleMod": 2,
	// 白名单: 生效后只允许执行cmd.exe|powershell.exe等进程
	// 黑名单: 生效后不允许执行cmd.exe|powershell.exe等进程
	"processName": "cmd.exe|powershell.exe|vbs.exe|wscript.exe"
}
```
**See Rule: config/processRuleConfig.json**

#### 注册表黑白名单模式(应用规则匹配)
**引擎工作方式：匹配processName和registerValuse二元组,多组规则情况下,命中某条成功后不继续匹配,命中规则为准。**

 - 举例1) 2) cmd.exe配置冲突，1) 允许cmd.exe访问Run, 2) 不允许cmd.exe规则访问 Run，配置冲突，冲突时顺序靠前为准(1为准)。

 - 举列2) 3) cmd.exe既可以是白名单-又可以是黑名单，比如Run注册表不允许cmd.exe访问(黑名单)，Settings允许cmd.exe访问(白名单),registerValuse键值不冲突即可。

 - 注：打开是 "删除-创建-设置-查询-重命名操作" 前提，比如修改，必须配置成打开修改(1000100)，删除则是打开删除(1010000),如果open为0意味着这个过程中有key_access or key_read标志都会失败。

```
{

	{ 1) 
		// 仅允许cmd.exe|powershell.exe对regusterValuse打开和修改.
		"registerRuleMod": 1,
		"processName": "cmd.exe|powershell.exe",
		"registerValuse": "\REGISTRY\MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run|\REGISTRY\MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOne",
		// 1000000打开(Create/Open)，100000关闭(Close)，10000删除(Delete)，1000创建(CreteNew), 100设置(SetValue)，10查询(QueryValue)，1重命名(Rename)
		"permissions": 1000100(打开和修改)
	}
	{ 2)
		// 不允许cmd.exe|vbs.exe|wscript.exe对regusterValuse进行全部操作, 也可以只配禁止打开,这样修改 删除 查询都不可用.
		"registerRuleMod": 2,
		"processName": "cmd.exe|vbs.exe|wscript.exe",
		"registerValuse": "\REGISTRY\MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run|\REGISTRY\MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOne",
		"permissions": 1111111(判定KEY_ALL_ACCESS)
	}

	{  3)
		// 仅允许svhost.exe|cmd.exe对regusterValuse修改重命名操作
		"registerRuleMod": 1,
		"processName": "cmd.exe|svhost.exe.exe",
		"registerValuse": "\Registry\Machine\Software\WOW6432Node\Policies\Microsoft\MUI\Settings",
		"permissions": 1000101(打开修改重命名操作)
	}
}
```
**See Rule: config/registerRuleConfig.json**

#### 目录访问黑白名单模式(内核规则匹配)
```
{
	{
		// 仅允许word.exe|wps.exe访问Directory
		"FileIORuleMod": 1,
		"processName": "word.exe|wps.exe",
		"Directory": "D:\\Document|C:\\System\\AppData",
	}
	{
		// 不允许word.exe|wps.exe访问Directory
		"FileIORuleMod": 2,
		"processName": "word.exe|wps.exe",
		"Directory": "D:\\Document1|C:\\System\\AppData1",
	}
}
```
**See Rule: config/DirectoryRuleConfig.json**


**应用规则匹配：内核先会根据模式对进程过滤，过滤后上抛至应用层规则逻辑处理，根据引擎结果内核做出拦截或放行。处理方式会牺牲性能，不过对于系统来说可以忽略不计。**

### GRPC/Protobuf v2.0

**考虑GRPC编译复杂性和移植编码比较麻烦，v2.0 HadesSvc将Grpc剔除，Go Agent负责Grpc统一管理，Protobuf协议沿用c++ lib链接。**

Windows对于很多第三方生态逐步容纳，Grpc github cmake编译会出现很多问题，如果使用推荐方式:

```
vcpkg install grpc
```

配置vs2019 工具 --> 选项 --> NuGet管理即可，详细可以参考网上教程，连接程序使用MD编译。

C++ Grpc请参考官方文档：https://grpc.io/docs/languages/cpp/basics/

**GRPC配置文件: config/client_config**

**See Code: grpc.h grpc.cpp**

### 规划：

#### v2.x

|版本 | 任务                                                      | 优先级         | 状态         |
|--------| --------------------------------------------------------- | -------------- |-------------- |
|v2.0~v2.3| Duilib终端界面| 中|完成 |
|v2.0~v2.3| ETW和内核态回调监控兼容Win7/Win11 x32/x64版本，稳定性测试|高|完成 |
|v2.0~v2.3| 采集Lib接口更改为订阅-发布者模式 | 中     |完成|
|v2.0~v2.3| 插件模式改造 | 高     |完成|
|v2.3.2| 数据采集粒度完善 | 高     |完成|
|v2.3.4| 进程保护 | 高 |完成|
|v2.3.4| 注册表键值保护 | 高 |完成|
|v2.3.5| 目录访问保护|高 |完成|
|- |  |  | |
|v2.3.6| 注入拦截|高 |进行中|
|v2.3.7| 内核回调枚举|高 |进行中|
|v2.3.8| 内核钩子检测|高 |进行中|
|- |  |  | |
|v2.x| ETW GUID LOG方式注册，非"NT KERNEL LOG"，复杂环境注册冲突被覆盖 | 中     |待定|


**从v3.0开始，流量和文件不局限于监控分析，有更多的玩法扩展。**

#### Minifilter v3.x

| 任务                                                         | 优先级 |状态|
| ------------------------------------------------------------ | ------ |------|
| 文件备份： 进程文件落地隔离，脚本命令和IE下载文件备份.<br>不局限于curl/cmd/powershell/vbs/js等形式. | 中  |待定|
| 勒索病毒行为检测：minifilter监控, 诱饵 + 访问控制 + 行为判定 |  高 |待定|

#### WFP v3.x

| 网络层        | 描述            |
| :------------ | :-------------- |
| Established层 | ProcessInfo     |
| 传输层        | TCP - UDP       |
| 网络层        | IP              |
| 数据链路层    | OS >= Windows10 |

**v3.0基于WFP流量隔离**
| 任务                                                         | 优先级 |状态|
| ------------------------------------------------------------ | ------ |------|
| 进程/IP:PORT重定向和bypass,win自带防火墙也可以 |  中  |待定|
| DNS访问控制               | 高     |待定|

Json配置流量规则(未生效):

```
(流量规则)
Json:
 {
 Bypass:
	1 - 单要素：目标 port 或者 ip 
	2 - 双要素：目标 ip:port  
	3 - 重定向标志位 - 暂时不开启(流量隔离)
 }
```
&emsp;&emsp;**致力于稳定健壮深度，插件形式提供lib/dll集成至Windows终端三方产品，提升软件的安全能力和质量。**

### 历史版本：
#### v1.0 实现：主要实现引擎探针和上层数据-上报流程打通。

#### v2.0 重构：代码质量优化，包括win7 - win11等平台的兼容性，局部Edr。

### 参考：
- 看雪论坛 & OpenEdr & Netfilter SDK & Sandboxie
- 项目将零散代码组织在一起，业余投入精力有限。 部分cpp早期学习编写，也有引用代码cpp中有标注。