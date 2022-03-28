# win_user_event v1.0

#### 应用层采集

| 功能          | 代码                            | API/描述                                                     |
| ------------- | :------------------------------ | ------------------------------------------------------------ |
| 自启动        | see code:uautostart.h/cpp       | 注册表、计划任务检测，gpedit.msc待定                         |
| 网络          | see code:unet.h/cpp             | GetExtendedTcpTable/GetExtendedUdpTable                      |
| 系统用户      | see code:usysuser.h/cpp         | NetUserEnum                                                  |
| 系统软件/服务 | see code:uservicesoftware.h/cpp | OpenSCManager <br>RegOpenKeyEx("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall") |
| 进程树        | see code:uprocesstree.h/cpp     | CreateToolhelp32Snapshot \| EnumProcessModulesEx             |
| 枚举目录文件  | see code:usysinfo.h/cpp         | 递归调用FindFirstFile                                        |
| 文件详细      | see code:usysinfo.h/cpp         | WIN32_FIND_DATA stFileData = { 0 };<br>HANDLE hFile = FindFirstFile(filestr, &stFileData); |
| 系统信息      | see code:usysinfo.h/cpp         |                                                              |



#### ETW

| 功能                 | 代码                 | TracGuid                                                     |
| -------------------- | -------------------- | ------------------------------------------------------------ |
| Process/Thread/Image | see code: uetw.h/cpp | EVENT_TRACE_FLAG_PROCESS<br>EVENT_TRACE_FLAG_THREAD<br>EVENT_TRACE_FLAG_IMAGE_LOAD |
| Network              | see code: uetw.h/cpp | EVENT_TRACE_FLAG_NETWORK_TCPIP                               |
| File                 | see code: uetw.h/cpp | EVENT_TRACE_FLAG_FILE_IO <br>EVENT_TRACE_FLAG_FILE_IO_INIT   |
| Register             | see code: uetw.h/cpp | EVENT_TRACE_FLAG_REGISTRY                                    |
| systemcall           | see code: uetw.h/cpp | EVENT_TRACE_FLAG_SYSTEMCALL                                  |

