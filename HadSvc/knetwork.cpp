#include "knetwork.h"
#include <NetWorkRuleAssist.h>
#include <sysinfo.h>
#include <NetApi.h>

// Rule每个类型最大100条
static const int g_MaxRuleCounter = 100;

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

void KNetWork::ReLoadDnsRule()
{
}

void KNetWork::ReLoadIpPortConnectRule()
{
	PDENY_RULE pDenyRule = nullptr;
	PREDIRECT_RULE pConnectRule = nullptr;
	pDenyRule = (PDENY_RULE)new DENY_RULE[g_MaxRuleCounter];
	pConnectRule = (PREDIRECT_RULE)new REDIRECT_RULE[g_MaxRuleCounter];

	if (!pDenyRule || !pConnectRule)
		return;
	RtlSecureZeroMemory(pDenyRule, sizeof(DENY_RULE) * g_MaxRuleCounter);
	RtlSecureZeroMemory(pConnectRule, sizeof(PREDIRECT_RULE) * g_MaxRuleCounter);

	int iDenyCounter = 0;	int iConnectCounter = 0;
	ConfigNetWorkYamlRuleParsing(pDenyRule, &iDenyCounter, pConnectRule, &iConnectCounter, g_MaxRuleCounter);

	// Clear
	NetNdrRuleClear();

	// DENY
	{
		for (int i = 0; i < iDenyCounter; ++i)
			NetNdrSetDenyRule(pDenyRule[i].strRuleName, pDenyRule[i].strIpAddress, pDenyRule[i].strProtocol, pDenyRule[i].strPorts, pDenyRule[i].strAction);
	}

	// REDIRECT
	{
		for (int i = 0; i < iConnectCounter; ++i)
			NetNdrSetRediRectRule(pConnectRule[i].strRuleName, pConnectRule[i].strRedirectIp, pConnectRule[i].RedrectPort, pConnectRule[i].strProtocol, pConnectRule[i].strProcessName);
	}

	if (pDenyRule) {
		delete[] pDenyRule;
		pDenyRule = nullptr;
	}
	if (pConnectRule) {
		delete[] pConnectRule;
		pConnectRule = nullptr;
	}
}

