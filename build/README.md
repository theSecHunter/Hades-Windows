编译环境 Win10 x64 20H2

xp系统编译使用vs2013和vs2008或者vs2017的SDK
vs2008：Driver WDK 7600 (XP驱动)
vs2013：编译Windows XP，Visual Studio 2013 -  (v120_xp)
vs2017：编译Windows XP，Visual Studio 2017 or Visual Studio 2019 - (v141_xp)
注意：界面需要同打包msvcr120.dll，可能会有xp运行丢失该dll
推荐使用v141_xp(SDK)编译XP程序，可能会少很多报错问题，原代码基于SDK 142编写，所以相对v120，v141相对友好.

win7以上使用vs2019(包括驱动)
vs2019：编译win7/win8/win10/win11  Visual Studio 2019 (SDK_142) 
vs2019：Driver WDK 10.0(可选择win7/win10运行平台)