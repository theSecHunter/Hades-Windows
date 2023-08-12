本机系统: Win10 x64 20H2

Debug使用MTD，Release使用MT编译，工程依赖lib路径已修改成相对路径：..\HadesSdk\xx\include ..\HadesSdk\xx\lib

XP系统编译使用vs2013和vs2008或者vs2017的SDK

vs2008：Driver WDK 7600 (XP驱动)

vs2013：编译Windows XP，Visual Studio 2013 -  (v120_xp)

vs2017：编译Windows XP，Visual Studio 2017 or Visual Studio 2019 - (v141_xp)

XP 使用 SDK v120_xp:Duilib + HadesControl，编译构建过程友好(设置静态mfc)，界面x86编译可成功.

Win7更高版本推荐使用vs2017/vs2019(包括驱动) 

Win32 x86编译，去掉依赖NetDrvlib工程.

vs2019：编译win7/win8/win10/win11  Visual Studio 2019 (SDK_142) 

vs2019：Driver WDK 10.0(可选择win7/win10运行平台)

HadesControl有HpSocket.lib依赖，HadesSvc有ProtoBuf依赖，Hpsocket/ProtoBuf与编译文档:

```
Documentation/Protobuf_vs2019_build.md  & Documentation/HpSocket_vs2019_build.md
```

