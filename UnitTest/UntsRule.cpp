#include "UntsRule.h"
#include <NetWorkRuleAssist.h>
#include <sysinfo.h>
#include <NetApi.h>

static const int g_MaxRuleCounter = 100;

UntsRule::UntsRule()
{
}

UntsRule::~UntsRule()
{
}

void UntsRule::UnTs_ReLoadIpPortConnectRule()
{
	PDENY_RULE pDenyRule = nullptr;
	PREDIRECT_RULE pConnectRule = nullptr;
	PDNS_RULE pDnsRule = nullptr;

	pDenyRule = (PDENY_RULE)new DENY_RULE[g_MaxRuleCounter];
	pConnectRule = (PREDIRECT_RULE)new REDIRECT_RULE[g_MaxRuleCounter];
	pDnsRule = (PDNS_RULE)new DNS_RULE[g_MaxRuleCounter];

	if (!pDenyRule || !pConnectRule || !pDnsRule)
		return;

	// Clear
	NetNdrRuleClear();
	RtlSecureZeroMemory(pDenyRule, sizeof(DENY_RULE) * g_MaxRuleCounter);
	RtlSecureZeroMemory(pConnectRule, sizeof(REDIRECT_RULE) * g_MaxRuleCounter);
	RtlSecureZeroMemory(pDnsRule, sizeof(DNS_RULE) * g_MaxRuleCounter);

	int iDenyCounter = 0;	int iConnectCounter = 0; int iDnsCounter = 0;
	ConfigNetWorkYamlRuleParsing(pDenyRule, &iDenyCounter, pConnectRule, &iConnectCounter, g_MaxRuleCounter);
	ConfigNetWorkYamlDnsRuleParsing(pDnsRule, &iDnsCounter, g_MaxRuleCounter);

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

	// DNS
	{
		for (int i = 0; i < iDnsCounter; ++i)
			NetNdrSetDnsRule(pDnsRule[i].strRuleName, pDnsRule[i].strProtocol, pDnsRule[i].sDnsName.c_str(), pDnsRule[i].strAction);
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