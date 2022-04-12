![image](https://github.com/theSecHunter/Hades-Windows/blob/main/Image/HadesWin_v2.0.jpg)
#### 方案：
##### Kernel

&emsp;&emsp;x64内核探针粗糙分为两类技术方案：

- 第一种基于Intel-x/d虚拟化技术，绕过PG保护做花式Hook，功能强大-系统无痕。
- 第二种基于微型过滤框架和注册回调，兼容性好/快速开发/接口完善。

&emsp;&emsp;项目采用过滤驱动+注册回调，这种方案中规中矩。有想过将以前写的VT Hook移植进来，但是不可控因素较多(不完善)，有兴趣的可以跳转：https://github.com/TimelifeCzy/kHypervisor_MsrEpt_Hook

**适用Win7/Win10 x32/x64用户态和内核态数据采集，XP未做兼容测试.**

&emsp;&emsp;v1.0单独引擎版本，存在许多问题，Rootkit接口Win10 1909进行测试。

&emsp;&emsp;v2.0开发中，对v1.0的引擎重构，采集器构建用户态和内核态lib，Svc业务剥离灵活，后期即使支持非grpc如epoll/asio接口也可以灵活多接口推送采集数据。修正v1.0存在的诸多问题，添加Duilib界面和完善Win7/Win8/WIn10系统兼容性。Hades_Win兼容Linux数据上报，添加Go_Server完整数据格式解析处理，采集数据通过Grpc上报至go_server进行解析即可，未引入主分支，详细见: https://github.com/theSecHunter/Hades-Linux

##### User

&emsp;&emsp;System数据采集和ETW事件采集。

#### 文档

| 文档             | 文件名                             |
| ---------------- | ---------------------------------- |
| 内核文档         | win_kernel_event.md                |
| 应用层文档       | win_user_event.md                  |
| WFP文档          | win_wfp_event.md                   |
| Grpc 传输结构(c) | windows struct_c.md(see sysinfo.h) |

#### 框架:
![image](https://github.com/theSecHunter/Hades-Windows/blob/main/Image/image-windows.png)

<center><h3>v1.0</h3></center>

##### 内核回调上抛事件 v1.0

| 事件   | 描述  |
| :----- | :---- |
| 进程   | 进程创建 - 销毁 - 进程数据 |
| 线程   | 线程创建 - 销毁 - 线程数据  |
| 注册表 | 删除 -  修改 - 枚举 - 重命名等（缺少具体的包解析） |
| 模块 | DLL -  驱动 |
| 会话 | 用户登录/退出/Session切换 |
| WMI    | 待定(应用层etw实现) |
| 文件 | 文件读写访问  OS <= Windows7  (Windows10 对象回调(文件对象)会有几率触发PG) |

Json配置内核上抛事件管理(未生效):

```
{
    1. 添加进程白名单，允许从内核态过滤控某进程数据
    2. xxxxx
}
```

##### 内核接口采集事件 v1.0

| 事件       | 描述  |
| :----------- | :---- |
| 进程 - 线程 - 模块 - 内存 | 系统已运行的进程 - 线程 - 模块(DLL/SYS) -  内存 |
| 进程树 | 进程 - 线程 - DLL - VAD |
| IDT     | 系统IDT - (原始偏移 - 内存已加载偏移)  HOOK检测 |
| MouseKeyBoard | 鼠标键盘 Hook检测 |
| DpcTimer | 遍历系统 DpcTimer |
| Hive | hive注册表 - 开发中 |
| Ntfs | ntfs文件解析 - 开发中 |
| Network | Nsi提取IP:PORT |
| Fsd | FastFat/ntfs HOOK检测 |
| SSDT     | 系统SSDT - (原始偏移 - 内存已加载偏移) HOOK检测 |
| GDT | 系统GDT - (原始偏移 - 内存已加载偏移) HOOK检测 |
| 回调检测   | 枚举系统注册的回调 |

**Win7上Rootkit接口未测试，接口Win10 1903测试**

##### 应用接口采集事件 v1.0

前身：https://github.com/TimelifeCzy/Windows-emergency-servicetools，集成至该项目.

| 事件         | 描述                                                         |
| ------------ | ------------------------------------------------------------ |
| 启动项       | 计划任务、注册表提取                                         |
| 网络连接     | 活跃TCP/UDP                                                  |
| Session      | 用户登录 -- v2.0                                             |
| 进程树       | 活跃进程（线程、模块、虚拟内存、Dump)                        |
| 系统信息     | 系统基础信息(软/硬件信息等) -- 考虑上线发送非被动            |
| 系统日志     | 应用程序日志、安全日志、系统日志数据 -- etw替代              |
| 系统用户     | 系统用户                                                     |
| 系统软件服务 | 已安装软件/服务                                              |
| 文件         | 列举指定目录下文件，可与ntfs数据对比.                        |
| Rootkit_PE   | Rootkit检测需要调用接口解析相关的PE文件，提取对比源. -- v2.0 |

##### ETW事件上抛 v1.0

| 事件     | 描述                            |
| -------- | ------------------------------- |
| 文件     | 创建、删除、读写                |
| 注册表   | 创建、删除、读写                |
| 进程树   | 进程、线程 - 创建/销毁/模块加载 |
| 网络     | tcp/udp五要素                   |
| 系统信息 | CPU、虚拟内存等数据 - 待定      |

**Etw事件结构See: etw_event_struct.md**

##### WFP v3.0

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

##### GRPC v1.0

Windows对于很多第三方生态逐步容纳，Grpc github cmake编译仍会出现很多问题，最好的办法:

```
vcpkg install grpc
```

&emsp;&emsp;配置vs2019 工具 --> 选项 --> NuGet管理即可，详细可以参考网上教程，注意vcpkg 安装的是release grpc，所以debug模式调试会有问题。

C++ Grpc请参考官方文档：https://grpc.io/docs/languages/cpp/basics/

**See Code: grpc.h grpc.cpp**

#### 规划：

&emsp;&emsp;**项目处于入门级，很多设计需要时间打磨和重构。关于WFP/Minifilter驱动，仅流量文件监控不会引入，应用层ETW日志弥补。**

&emsp;&emsp;**它并不是以产品形态诞生，起步扮演的角色是Hids，希望日后更灵活更健壮，以插件提供lib/dll，集成至任意终端产品，包括办公软件 - 游戏音频，提供更多终端软件第三方安全建设/检测的能力。**

##### v2.0

| 任务                                                      | 优先级         | 状态         |
| --------------------------------------------------------- | -------------- |-------------- |
| Rootkit优化/完善                                          | 高             |进行中 |
| Etw和内核态回调监控兼容Win7/Win10 x32/x64版本，稳定性测试          | 高             |完成 |
| 指定进程授权非隔离分析 - 类沙箱做inlinehook来监控运行周期 | 中(也可能v3.0) |-------------- |
| electron或者Duilib 终端界面                         | 中           |开发中 |

##### v3.0

**从v3.0开始，流量和文件不局限于监控分析，有更多的玩法扩展。**

| 任务                                                         | 优先级 |
| ------------------------------------------------------------ | ------ |
| 流量隔离：基于WFP对进程/IP:PORT重定向和bypass.               | 高     |
| 文件备份：基于Minfilter对进程文件rwx隔离，对脚本命令和IE下载文件备份.<br>命令不局限于curl/cmd/powershell/vbs/js等形式. | 高     |
| 优化通信：Win下目前使用Grpc，但是有诸多不变。引入IOCP模块，后续如果server使用Epoll，无缝对接。 | 中     |

#### 参考：

- Github开源Rootkit工具，但不局限于工具。
- 看雪论坛帖子
- OpenEdr & Netfilter SDK & Sandboxie

```c++
std::cout << "项目将零散代码组织到一起，业余投入精力并不多。部分cpp可能以前学习中编写，遗憾的是时间太久，忘记了具体引用的项目，部分代码中有参考github_url，有兴趣可以去学习一番。" << std::endl
```

#### 历史版本：
v1.0 实现：主要实现引擎探针和上层数据-上报流程打通。

v2.0 重构：设计模式mvp和代码质量优化，包括xp - win7 - win10等平台的兼容性。
