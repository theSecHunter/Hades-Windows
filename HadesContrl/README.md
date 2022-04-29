#### 网络选型
1. Boost:Asio/Asio
2. HpSocket_Windows 使用中: https://github.com/ldcsaa/HP-Socket vs2019编译版release
3. 自己开发基于IOCP的TCPSver 完善中，后续替代HpSocket_win，自己开发特点根据业务只需要编写短小代码就可以，方便维护和添加业务.
成熟的项目使用还是以asio为主，c++标准可能将Asio集成标准库。