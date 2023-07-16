#pragma once
#include "ArkIdt.h"
#include "ArkFsd.h"
#include "ArkSsdt.h"
#include "ArkDrvlib.h"
#include "ArkNetwork.h"
#include "ArkDpcTimer.h"
#include "ArkProcessInfo.h"
#include "ArkMouseKeyBoard.h"
#include "ArkSysDriverDevInfo.h"
#include <SingletonHandler.h>

// 生产者单列
using SingletonKIdt = ustdex::Singleton<ArkIdt>;
using SingletonKFsd = ustdex::Singleton<ArkFsd>;
using SingletonKSSdt= ustdex::Singleton<ArkSsdt>;
using SingletonKNetWork = ustdex::Singleton<ArkNetwork>;
using SingletonKDpcTimer = ustdex::Singleton<ArkDpcTimer>;
using SingletonKDrvManage = ustdex::Singleton<DevctrlIoct>;
using SingletonKProcessInfo = ustdex::Singleton<ArkProcessInfo>;
using SingletonKMouseKeyBoard = ustdex::Singleton<ArkMouseKeyBoard>;
using SingletonKSysDriverDevInfo = ustdex::Singleton<AkrSysDriverDevInfo>;
