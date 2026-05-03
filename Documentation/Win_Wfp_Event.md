# win_net_event

#### WFP 驱动链路

WFP 驱动负责网络主防和流量事件采集，当前代码主要覆盖 TCP/UDP 建连、TCP 重定向、UDP 数据包处理、DNS 规则和基础数据链路事件。HadesSvc 通过 `KNetWork` 加载 yaml 规则，并下发到 `NetDrvlib`/WFP 驱动。

#### Established

###### ProcessInfo

记录 TCP/UDP flow established 上下文，关联进程路径、PID、本地地址和远端地址。

###### DNS

支持 DNS 域名规则，当前规则优先级高于普通 UDP 规则。

#### TCP/UDP

支持基于进程、IP、端口、协议的 DENY/REDIRECT 规则；TCP 支持连接重定向，UDP 支持发送/接收方向的包处理与阻断判定。

#### IP

###### ICMP

#### DATALINK

###### ARP

数据链路层事件当前以采集为主，规则控制仍以 TCP/UDP/DNS 为主。
