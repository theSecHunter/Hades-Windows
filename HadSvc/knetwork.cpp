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

void KNetWork::ReLoadDnsRule()
{
}

void KNetWork::ReLoadIpPortConnectRule()
{
	PDENY_RULE pDenyRule = nullptr;
	PTCPCONNECT_RULE pConnectRule = nullptr;
	pDenyRule = (PDENY_RULE)new DENY_RULE[100];
	pConnectRule = (PTCPCONNECT_RULE)new TCPCONNECT_RULE[100];

	if (!pDenyRule || !pConnectRule)
		return;
	RtlSecureZeroMemory(pDenyRule, sizeof(DENY_RULE) * 100);
	RtlSecureZeroMemory(pConnectRule, sizeof(TCPCONNECT_RULE) * 100);

	int iDenyCounter = 0;	int iConnectCounter = 0;
	ConfigNetWorkYamlRuleParsing(pDenyRule, &iDenyCounter, pConnectRule, &iConnectCounter);

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
			NetNdrSetConnectRule(pConnectRule[i].strRuleName, pConnectRule[i].strRedirectIp, pConnectRule[i].strProtocol, pConnectRule[i].strProcessName);
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

