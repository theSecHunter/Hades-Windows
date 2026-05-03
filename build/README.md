本机系统: Win10 x64 20H2

Debug 使用 MTD，Release 使用 MT 编译，工程依赖 lib 路径已修改成相对路径：..\HadesSdk\xx\include ..\HadesSdk\xx\lib

XP系统编译使用vs2013和vs2008或者vs2017的SDK

vs2008：Driver WDK 7600 (XP驱动)

vs2013：编译Windows XP，Visual Studio 2013 -  (v120_xp)

vs2017：编译Windows XP，Visual Studio 2017 or Visual Studio 2019 - (v141_xp)

XP 使用 SDK v120_xp:Duilib + HadesControl，编译构建过程友好(设置静态mfc)，界面x86编译可成功.

Win7 及更高版本推荐使用 vs2017/vs2019(包括驱动)

Win32 x86 编译时，去掉对 NetDrvlib 工程的依赖。

vs2019：编译 win7/win8/win10/win11，使用 Visual Studio 2019 (v142)。

vs2019：Driver WDK 10.0(可选择win7/win10运行平台)

HadesControl 有 HpSocket.lib 依赖，HadesSvc 有 Protobuf 依赖，HpSocket/Protobuf 编译文档:

```
Documentation/Protobuf_vs2019_build.md  & Documentation/HpSocket_vs2019_build.md
```

