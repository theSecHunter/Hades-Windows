#include "UntsNetwork.h"
#include "singGloal.h"
#include <NetWorkRuleAssist.h>
#include <sysinfo.h>
#include <NetApi.h>


UntsNetwork::UntsNetwork()
{
}

UntsNetwork::~UntsNetwork()
{
}

// [依赖] 规则引擎 - 服务检测代码.
const bool UntsNetwork::UnTs_NetworkInit()
{
	// [exter] unts rule
	SingletonUntsRule::instance()->UnTs_ReLoadIpPortConnectRule();
	// [exter] unts svc -- checkout status
	if (SingletonUntsSvc::instance()->UnTs_NetCheckStatus()) {
		// NetApi.h --> [lib] --> [NetDrvlib]
		if (!GetNetNdrStusEx()) {
			NetNdrInitEx();
			return true;
		}
	}
	return false;
}