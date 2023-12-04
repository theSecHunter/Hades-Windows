### Tests Driven Development
&emsp;&emsp;hades win插件单元测试，方案与标准TDD模式有一定差异，UnitTest工程目的优化可测试，可维护，可理解等质量属性。方便单独调试lib/dll引擎组件，服务模块代码，针对局部功能添加，可快速模块化验证和关联性验证。

#### UntsControl.cpp
| Class | 测试工程 |函数|功能| 依赖单元| 备注 |
| ----------- | -----------| -----------|------------------------|-----------|-----------|
| UntsControl| app/HadesContrl| ||||

#### UntsSvc.cpp
| Class      | 测试工程 |函数|功能| 依赖单元| 备注 |
| ----------- | -----------| -----------|------------------------|-----------|-----------|
| UntsSvc| svc/HadesSvc | UnTs_NetCheckStatus | 驱动状态检测/安装| DriverManager | |

#### UntsRule.cpp
| Class | 测试工程 |函数|功能| 依赖单元| 备注 |
| ----------- | -----------| -----------|------------------------|-----------|-----------|
| UntsRule| lib/RuleEnginelib | UnTs_ReLoadIpPortConnectRule | 本地规则解析，结构映射正确性| / | x64可用|

#### UntsNetwork.cpp
| Class      | 测试工程 |函数|功能| 依赖单元| 备注 |
| ----------- | -----------| -----------|------------------------|-----------|-----------|
| UntsRule| lib/NetDrvlib| UnTs_NetworkInit | 初始化逻辑业务,规则读取设置，驱动启动 | UnTs_ReLoadIpPortConnectRule<br>UnTs_NetCheckStatus | x64可用|


