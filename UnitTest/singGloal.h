#pragma once
#include <udrivermanager.h>
#include <SingletonHandler.h>
#include "UntsRule.h"
#include "UntsSvc.h"

#ifdef _X64
// using SingletonKNetWork = ustdex::Singleton<KNetWork>;
#endif
using SingletonUntsSvc = ustdex::Singleton<UntsSvc>;
using SingletonUntsRule = ustdex::Singleton<UntsRule>;
using SingletonDrvManage = ustdex::Singleton<DriverManager>;


