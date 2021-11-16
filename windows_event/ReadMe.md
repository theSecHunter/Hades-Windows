#### 方案：

&emsp;&emsp;x64内核探针粗糙分为两类技术方案：第一种基于Intel-x/d虚拟化技术，绕过PG保护做花式Hook，功能强大-系统无痕，第二种基于微型过滤框架和注册回调，兼容性好/快速开发/接口完善。

&emsp;&emsp;该项目采用过滤驱动+注册回调，这种方案中规中矩。后续可能会集成VT接口，但是支持有限，优先支持EPT HOOK和寄存器/内存数据探测，详细的技术实现请跳转具体项目查阅ReadMe。

&emsp;&emsp;示例适用Win7/Win10 x64下内核态数据采集，其他系统版本需要自行修改。

#### 框架:
![image](image-windows.png)

<center><h3>v1.0</h3></center>

##### WFP：

| 网络层       | 描述  |
| :--------- | :---- |
| Established层 | ProcessInfo |
| 传输层     | TCP - UDP |
| 网络层   | IP |
| 数据链路层 | OS >= Windows10 |

 ```
 (流量规则未生效)
 Json:
  {
  Bypass:
 	1 - 单要素：目标 port 或者 ip 
 	2 - 双要素：目标 ip:port  
 	3 - 重定向标志位 - 暂时不开启
  }
 ```

##### 内核回调上抛事件：

| 事件   | 描述  |
| :----- | :---- |
| 进程   | 进程创建 - 销毁 - 进程数据 - 签名 |
| 线程   | 线程创建 - 销毁 - 线程数据  |
| 注册表 | 删除 -  修改 - 枚举 - 重命名等（缺少具体的包解析） |
| 模块 | DLL -  驱动 |
| 会话 | 用户登录/退出/Session切换 |
| WMI    | 监控事件待定 |
| 文件 | 文件读写访问  OS <= Windows7 (Windows10 对象回调(文件对象)会有几率触发PG检测) |

可以使用json配置文件对内核上抛事件管理:

```
(内核采集规则未生效)
{
    1. 添加进程白名单，允许从内核态过滤控某进程数据
    2. xxxxx
}
```

##### 内核接口采集事件：

| 事件       | 描述  |
| :----------- | :---- |
| 进程 - 线程 - 模块 - 内存 | 系统已运行的进程 - 线程 - 模块 - 进程内存 - 应用层钩子检测(待定) |
| IDT     | 系统IDT - (原始偏移 - 内存已加载偏移)  HOOK检测 |
| MouseKeyBoard | 鼠标键盘 Hook检测 |
| DpcTimer | 遍历系统 DpcTimer |
| Hive | hive注册表 - 开发中 |
| Ntfs | ntfs文件解析 - 开发中 |
| Network | Nsi提取IP:PORT |
| Fsd | FastFat/ntfs HOOK检测 |
| SSDT     | 系统SSDT - (原始偏移 - 内存已加载偏移) HOOK检测 |
| GDT | 系统GDT - (原始偏移 - 内存已加载偏移) HOOK检测 |
| 驱动     | 系统已加载的驱动 |
| 回调检测   | 枚举系统注册的回调 |

##### GRPC：

Windows对于很多第三方生态逐步容纳，Grpc github cmake编译仍会出现很多问题，最好的办法:

```
vcpkg install grpc
```

&emsp;&emsp;配置vs2019 工具 --> 选项 --> NuGet管理即可，详细可以参考网上教程，注意vcpkg 安装的是release grpc，所以debug模式调试会有问题。

C++ Grpc请参考官方文档：https://grpc.io/docs/languages/cpp/basics/

**See Code: grpc.h grpc.cpp**

**详细技术请跳转子项目页面查看ReadMe即可**

#### 参考：

- Github开源Rootkit工具，但不局限于工具。
- 看雪论坛帖子
- OpenEdr & Netfilter SDK框架模型

```c++
std::cout << "项目将零散代码组织到一起，业余投入精力并不多。部分cpp可能以前学习中编写，遗憾的是时间太久，忘记了具体引用的项目，部分代码中有参考github_url，有兴趣可以去学习一番。" << std::endl
```
