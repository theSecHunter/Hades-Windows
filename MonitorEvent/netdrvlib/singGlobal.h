#pragma once
#include "devctrl.h"
#include "EventHandler.h"
#include "NetRule.h"
#include <SingletonHandler.h>

using SingletonNetRule = ustdex::Singleton<NetRule>;
using SingletNetMonx = ustdex::Singleton<DevctrlIoct>;
using SingletonEventHandler = ustdex::Singleton<EventHandler>;