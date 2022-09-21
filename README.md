![image](https://github.com/theSecHunter/Hades-Windows/blob/main/Image/HadesWin_v2.0.png)
![image](https://github.com/theSecHunter/Hades-Windows/blob/main/Image/HadesWin_v2.0_Response.jpg)

**适用Win7/Win11 x32/x64用户态和内核态数据采集，XP未做兼容测试.**

### v1.0： 

单独引擎版本.

### v2.0： 
v1.0引擎重构，采集器分离用户态和内核态lib，HadesSvc数据引擎消费lib生产数据，组织格式(json和protobuf)。Duilib界面完善，Win7/Win8/WIn10系统兼容性完善。

Hboat支持Windows插件上报数据解析，GoAgent统一管理和上报(部分数据未清洗)，可作为插件下发。

GoAgent负责GRPC和WIN下插件管理(跨平台)：https://github.com/theSecHunter/Hades-Linux/tree/main

GoServer已合并新项目Hboat(跨平台): https://github.com/theSecHunter/Hboat

## 方案：
### Kernel

&emsp;&emsp;x64内核探针粗糙分为两类技术方案：

- 第一种基于Intel-x/d虚拟化技术，绕过PG保护做花式Hook，功能强大-系统无痕。
- 第二种基于微型过滤框架和注册回调，兼容性好/快速开发/接口完善。

&emsp;&emsp;项目采用过滤驱动+注册回调，这种方案中规中矩。有想过将以前写的VT Hook移植进来，但是不可控因素较多(不完善)，有兴趣的可以跳转：https://github.com/TimelifeCzy/kHypervisorBasic

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
| 注册表 | 删除 -  修改 - 枚举 - 重命名等（缺少具体的包解析） | 数据未清洗 |
| 模块 | DLL -  驱动 |完成 |
| 会话 | 用户登录/退出/Session切换 |完成 |
| WMI    | 待定(应用层etw实现) |ETW实现 |
| 文件 | 文件读写访问  OS <= Windows7  (Windows10 对象回调(文件对象)会有几率触发PG) |完成 |

### 内核接口采集事件 v2.0

| 事件       | 描述  |  进度  | 
| :----------- | :---- | :---- |
| 进程 - 线程 - 模块 - 内存 | 系统已运行的进程 - 线程 - 模块(DLL/SYS) | 完成 |
| 进程详细 | VAD - 内存 | 未开发 |
| IDT     | 系统IDT - 内存加载地址 | 完成 |
| MouseKeyBoard | 鼠标键盘 - 派遣函数内核地址 | 完成 |
| DpcTimer | 遍历系统 DpcTimer |完成 |
| Hive | hive注册表 - 开发中 |未开发 |
| Ntfs | ntfs文件解析 - 开发中 |未开发 |
| Network | Nsi提取IP:PORT | 完成 |
| Fsd | FastFat/ntfs - 派遣函数内核地址 | 完成 |
| SSDT     | 系统SSDT | 完成 |
| GDT | 系统GDT  | 完成 |
| 回调检测   | 枚举系统注册的回调 |开发中 |

**注：Dpc硬编码，兼容性还未处理.**

### 应用接口采集事件 v2.0

前身：https://github.com/TimelifeCzy/Windows-emergency-servicetools 已集成该项目.

| 事件         | 描述                                                         |进度  | 
| ------------ | ------------------------------------------------------------ |------------ | 
| 启动项       | 计划任务、注册表提取| 完成 |
| 网络连接     | 活跃TCP/UDP|完成 |
| Session      | 用户登录| 开发中|
| 进程树       | 活跃进程（线程、模块)|完成 |
| 系统信息     | 系统基础信息(软/硬件信息等) -- 考虑上线发送非被动|完成 |
| 系统日志     | 应用程序日志、安全日志、系统日志数据|ETW|
| 系统用户     | 系统用户|完成 |
| 系统软件服务 | 已安装软件/服务|完成 |
| 摄像头         | 监控，如果状态改变上报数据 |开发中|
| 麦克风         | 监控，如果状态改变上报数据|开发中|
| 蓝牙         | 监控，如果状态改变上报数据|开发中|
| 文件         | 列举指定目录下文件，可与ntfs数据对比.|未开发|
| Rootkit_PE   | Rootkit相关PE文件地址解析，提取数据源Offset.|未开发 - 数据用于和内核提取地址匹配|

### 用户态ETW事件上抛 v2.0

| 事件     | 描述                            |进度  | 
| -------- | ------------------------------- |-------- |
| 文件     | 创建、删除、读写                |事件数据未完全解析|
| 注册表   | 创建、删除、读写                |事件数据未完全解析|
| 进程树   | 进程、线程 - 创建/销毁/模块加载 |完成|
| 网络     | tcp/udp五要素                   |完成|

**Etw事件结构See: etw_event_struct.md**

### Duilib界面展示 v2.0
| 事件     | 描述                            |进度  | 
| -------- | ------------------------------- |-------- |
| Cpu利用率|  动态刷新 |完成|
| 系统内存| 动态刷新|完成|
| GPU| 动态刷新|开发中|
| 磁盘I/O|动态刷新 |开发中|
| CPU温度| 动态刷新|开发中|
| 主板温度| 动态刷新|开发中|
| 显卡温度| 动态刷新|开发中|
| 硬盘温度| 动态刷新|开发中|
| 流量上传/下载|动态刷新 |开发中|
| 处理器详细|静态展示 |完成|
| 操作系统版本|静态展示 |完成|
| 当前用户|静态展示 |完成|
| 主板型号|静态展示 |完成|
| 显示器型号|静态展示 |完成|
| 电池|静态展示 |完成|

**Duilib展示数据不会上报**

### 恶意行为拦截 v2.0：
| 事件     | 描述                            |进度  | 描述 | 引用代码 |
| -------- | ------------------------------- |-------- | -------- |-------- |
| 进程拦截|  自定义进程 |完成| 基于回调过滤| |
| 注册表拦截|  自定义注册表 |完成| 基于回调过滤 | |
| 远程注入检测 |  远程线程注入 |完成| 基于回调过滤 | https://bbs.pediy.com/thread-193437.htm |
| 非远程线程注入检测 |  映射内存或非CreteRemote方式执行 |开发中| 回调中VAD | https://github.com/huoji120/CobaltStrikeDetected/ |

**基于回调简单行为拦截,拦截进程配置文件： config/client_config. (规则配置未生效)**

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
|v2.0~v2.3| ETW和内核态回调监控兼容Win7/Win10 x32/x64版本，稳定性测试|高|完成 |
|v2.0~v2.3| 采集Lib接口更改为订阅-发布者模式 | 中     |完成|
|v2.0~v2.3| 插件模式改造 | 高     |完成|
|v2.4| 数据采集粒度可用性完善 | 高     |进行中|
|v2.4| HIPS规则配置，进程(黑名单) - 注册表(特殊键值保护_进程白名单) - 进程目录访问保护(进程白名单) | 高 |进行中|
|v2.5| ETW GUID LOG方式注册，非"NT KERNEL LOG"，很多环境下容易冲突，注册被覆盖 | 中     |待定|

#### v3.x

**从v3.0开始，流量和文件不局限于监控分析，有更多的玩法扩展。**

| 任务                                                         | 优先级 |状态|
| ------------------------------------------------------------ | ------ |------|
| 流量隔离：基于WFP对进程/IP:PORT重定向和bypass.               | 高     |未开始|
| 文件备份：基于Minfilter对进程文件rwx隔离，对脚本命令和IE下载文件备份.<br>命令不局限于curl/cmd/powershell/vbs/js等形式. | 高     |未开始|
| 指定进程授权非隔离分析 - 类沙箱做inlinehook来监控运行周期(待定) | 中 |未开发 |
| Rootkit优化/完善| 中|进行中 |
| 勒索病毒行为检测 |  minifilter监控,设置诱饵文件来判定 |待定|

#### WFP v3.0

| 网络层        | 描述            |
| :------------ | :-------------- |
| Established层 | ProcessInfo     |
| 传输层        | TCP - UDP       |
| 网络层        | IP              |
| 数据链路层    | OS >= Windows10 |

**v3.0引入WFP流量隔离**

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

&emsp;&emsp;**项目处于入门级，很多设计需要时间打磨和重构。关于WFP/Minifilter驱动，仅流量文件监控不会引入，应用层ETW日志弥补。**

&emsp;&emsp;**灵活健壮稳定，以插件提供lib/dll，集成至任意终端产品，包括办公软件 - 游戏音频，提供更多终端软件第三方安全建设/检测的能力。**

### 历史版本：
#### v1.0 实现：主要实现引擎探针和上层数据-上报流程打通。

#### v2.0 重构：代码质量优化，包括win7 - win10等平台的兼容性，局部edr。

### 参考：

- Github开源Rootkit工具，但不局限于工具。
- 看雪论坛帖子
- OpenEdr & Netfilter SDK & Sandboxie

```c++
std::cout << "项目将零散代码组织到一起，业余投入精力并不多。部分cpp可能以前学习中编写，遗憾的是时间太久，忘记了具体引用的项目，部分代码中有参考github_url，有兴趣可以去学习一番。" << std::endl
```
