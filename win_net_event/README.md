# wfp_datalink_demo
最初方案wfp+ndis，后来请教Netfilter sdk2.0，思路一致但是给出了更优的方案(win8 - win10)：

If    you   have   callouts   on   FWPM_LAYER_ALE_AUTH_CONNECT_*   and
FWPM_LAYER_ALE_AUTH_LISTEN_* layers in the same binary, it is possible
to  match  process context from these layers with packets on MAC_FRAME
layers  by  local/remote IP:port. For example build a table with local
IP:port  pairs and process context for outgoing connections authorized
on  FWPM_LAYER_ALE_AUTH_CONNECT_*  layers  and  local  server  sockets
authorized  on  FWPM_LAYER_ALE_AUTH_LISTEN_*  layers.  Then search for
IP:port of each packet on MAC_FRAME layer in that table. If one of the
pairs  of  packet  local  or remote IP:port is found in table, use the
associated process context.

wfp做FWPM_LAYER_ALE_AUTH_CONNECT_、FWPM_LAYER_ALE_AUTH_LISTEN_映射IP - PORT - PID - ProcessPath等数据，wfp mac_frame 从端口数据关联wfp的映射表，从而关联数据链路层包和上层进程信息。

该代码方案：
通过established layer (tcp/udp)捕获processpath - pid - ip:port，数据上传应用层建立链路层查询表，mac_frame捕获链路层数据上传应用层。
应用层做关联，mac_frame通过ip:port来关联established layer的数据(查询表)，从而关联进程信息。
