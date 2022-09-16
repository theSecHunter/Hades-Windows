Duilib HadesWin界面说明：
1. 在启动界面的情况下，HpSocket用于HadesSvc.exe行为放行和拦截，但是HadesSvc通知界面优先级最低，以规则或者HadesAgent.exe为主。
2. 仅守护HadesAgent.exe进程, 不守护HadesSvc.exe，不负责HadesSvc管理，由HadesAgent管理。

编译选项：
1. HpSocket_Windows 使用中: https://github.com/ldcsaa/HP-Socket vs2019编译版uDebug/uRlease分别使用MTD、MT.