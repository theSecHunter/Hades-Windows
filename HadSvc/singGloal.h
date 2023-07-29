#pragma once
#include "kmsginterface.h"
#include "umsginterface.h"
#include "knetwork.h"
#include "DataHandler.h"
#include <SingletonHandler.h>

using SingletonKNetWork = ustdex::Singleton<KNetWork>;
using SingletonDataHandler = ustdex::Singleton<DataHandler>;
using SingletonUMon = ustdex::Singleton<uMsgInterface>;
using SingletonKerMon = ustdex::Singleton<kMsgInterface>;

