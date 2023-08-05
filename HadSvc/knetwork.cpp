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

const bool KNetWork::NetNdrInit()
{
	return NetNdrInitEx();
}

void KNetWork::NetNdrClose()
{
	NetNdrCloseEx();
}

const bool KNetWork::GetNetNdrStus()
{
	return GetNetNdrStusEx();
}

void KNetWork::SetAllRule()
{
	std::vector<NetWorkRuleNode> NetRuleNode;
	ConfigNetWorkYamlRuleParsing(NetRuleNode);
}

void KNetWork::ReLoadDnsRule()
{
}

void KNetWork::ReLoadIpPortConnectRule()
{
	std::vector<NetWorkRuleNode> NetRuleNode;
	ConfigNetWorkYamlRuleParsing(NetRuleNode);
}

