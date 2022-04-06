编译环境 Win10 x64 20H2

xp系统编译使用vs2013和vs2008或者vs2017的SDK
vs2008：Driver WDK 7600 (XP驱动)
vs2013：编译Windows XP，Visual Studio 2013 -  (v120_xp)
vs2017：编译Windows XP，Visual Studio 2017 or Visual Studio 2019 - (v141_xp)
注意：
使用SDK v120_xp:Duilib + HadesControl，编译构建过程友好(设置静态mfc)，界面x86编译可成功.
目前还没办法构建XP下构建x86/x64的lib和服务，有几点未做代码兼容，json库 grpc 及 c++等代码，后续可能单独拉一个分支专注xp代码兼容.


win7以上使用vs2019(包括驱动)
vs2019：编译win7/win8/win10/win11  Visual Studio 2019 (SDK_142) 
vs2019：Driver WDK 10.0(可选择win7/win10运行平台)