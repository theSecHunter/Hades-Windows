# win_user_event

#### 应用层采集

| 功能          | API/描述                                         |
| ------------- | ------------------------------------------------ |
| 自启动        | 注册表、计划任务检测，gpedit.msc待定             |
| 网络          | GetExtendedTcpTable/GetExtendedUdpTable          |
| 系统用户      | NetUserEnum                                      |
| 系统软件/服务 |                                                  |
| 进程树        | CreateToolhelp32Snapshot \| EnumProcessModulesEx |

#### ETW

