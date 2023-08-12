#pragma once
#include "kmsginterface.h"
#include "umsginterface.h"
#ifndef WIN32
#include "knetwork.h"
#endif
#include "DataHandler.h"
#include <udrivermanager.h>
#include <SingletonHandler.h>

#ifndef WIN32
using SingletonKNetWork = ustdex::Singleton<KNetWork>;
#endif
using SingletonDataHandler = ustdex::Singleton<DataHandler>;
using SingletonUMon = ustdex::Singleton<uMsgInterface>;
using SingletonKerMon = ustdex::Singleton<kMsgInterface>;
using SingletonDrvManage = ustdex::Singleton<DriverManager>;

