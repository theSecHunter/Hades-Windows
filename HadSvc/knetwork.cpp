#include "knetwork.h"
#include <NetWorkRuleAssist.h>
#include <sysinfo.h>
#include <NetApi.h>

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
	//NetSetRule();
}

void KNetWork::ReLoadDnsRule()
{
}

void KNetWork::ReLoadTcpConnectRule()
{
}

