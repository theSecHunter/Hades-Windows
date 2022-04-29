// header.h: 标准系统包含文件的包含文件，
// 或特定于项目的包含文件
//

#pragma once

#include "targetver.h"
#define WIN32_LEAN_AND_MEAN             // 从 Windows 头文件中排除极少使用的内容

#include "StdAfx.h"

// Windows 头文件
#include <windows.h>
// C 运行时头文件
#include <stdlib.h>
#include <malloc.h>
#include <memory.h>
#include <tchar.h>

#ifdef _WIN64
#ifdef _DEBUG
#pragma comment(lib, "D:\\Hades\\Hades-Windows\\HadesSdk\\sysmonuser\\lib\\SysMonUserlib_d64.lib")
#pragma comment(lib, "D:\\Hades\\Hades-Windows\\HadesSdk\\hpsocket\\lib\\HPSocket_64D.lib")
#else
#pragma comment(lib, "D:\\Hades\\Hades-Windows\\HadesSdk\\sysmonuser\\lib\\SysMonUserlib64.lib")
#pragma comment(lib, "D:\\Hades\\Hades-Windows\\HadesSdk\\hpsocket\\lib\\HPSocket64.lib")
#endif
#else
#ifdef _DEBUG
#pragma comment(lib, "D:\\Hades\\Hades-Windows\\HadesSdk\\sysmonuser\\lib\\SysMonUserlib_d.lib")
#pragma comment(lib, "D:\\Hades\\Hades-Windows\\HadesSdk\\hpsocket\\lib\\HPSocket_D.lib")
#else
#pragma comment(lib, "D:\\Hades\\Hades-Windows\\HadesSdk\\sysmonuser\\lib\\SysMonUserlib.lib")
#pragma comment(lib, "D:\\Hades\\Hades-Windows\\HadesSdk\\hpsocket\\lib\\HPSocket.lib")
#endif
#endif

