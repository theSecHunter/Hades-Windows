#### 方案：

&emsp;&emsp;Win10 x64内核数据采集，Intel-x虚拟化可以绕过PG保护做花式Hook，风险高，功能强大-系统无痕。微型过滤框架能强大兼容性好，系统回调函数有一定限制，中规中矩。

&emsp;&emsp;方案使用Minifilter框架作为文件采集事件，系统回调采集内核事件，可以通过进程，线程，注册表等回调采集，网络采集使用WFP或NDIS驱动。

&emsp;&emsp;该示例适用Win7/Win8/Win10 x64下内核态数据采集，稍作修改就可以在Win7 x32下运行。

#### 框架:

Windows覆盖WFP，回调，Minifilter探针驱动，各自工作独立，通过数据库来完整监视系统安全状态。

![image-20210923092521040](C:\Users\zy.chen\AppData\Roaming\Typora\typora-user-images\image-20210923092521040.png)

##### WFP：

| 子层       | Are           | Cool  |
| :--------- | :------------ | :---- |
| 传输层     | righta-ligned | $1600 |
| 网络层     | centered      | $12   |
| 数据链路层 | are neat      | $1    |

##### 内核事件：

| 事件   | Are           | Cool  |
| :----- | :------------ | :---- |
| 进程   | righta-ligned | $1600 |
| 线程   | centered      | $12   |
| 注册表 | are neat      | $1    |

##### Minifilter：

| Tables       | Are           | Cool  |
| :----------- | :------------ | :---- |
| 文件读写创建 | righta-ligned | $1600 |
| 目录管控     | centered      | $12   |
| 数据探测     | are neat      | $1    |

