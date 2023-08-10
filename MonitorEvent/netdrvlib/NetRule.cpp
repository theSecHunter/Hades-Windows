#include "ntbasic.h"
#include "NetRule.h"

NetRule::NetRule()
{
}

NetRule::~NetRule()
{
}

void NetRule::SetDenyRule(const DENY_RULE& vecDeny)
{
	m_vecDenyRule.push_back(vecDeny);
}

void NetRule::SetTcpConnectRule(const TCPCONNECT_RULE& vecConnect)
{
	m_vecConnectRule.push_back(vecConnect);
}

void NetRule::NetRuleClear()
{
	m_vecDenyRule.clear();
	m_vecConnectRule.clear();
}