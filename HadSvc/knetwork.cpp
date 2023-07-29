#include "knetwork.h"
#include <NetWorkRuleAssist.h>
#include <sysinfo.h>

KNetWork::KNetWork()
{
}

KNetWork::~KNetWork()
{
}

const bool KNetWork::NetDrvInit()
{
	return NetInit();
}

void KNetWork::SetAllRule()
{
	NetWorkRuleNode NetRuleNode; NetRuleNode.clear();
	ConfigNetWorkYamlRuleParsing(NetRuleNode);
}

void KNetWork::ReLoadDnsRule()
{
}

void KNetWork::ReLoadTcpConnectRule()
{
}

