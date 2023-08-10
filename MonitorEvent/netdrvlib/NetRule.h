#pragma once
#include <vector>
#include <string>

typedef struct _NetWorkRuleNode
{
    std::string strRuleName;
    std::string strProtocol;
    std::string strAction;
    std::string strLevel;
}NetWorkRuleNode, * PNetWorkRuleNode;

typedef struct _DENY_RULE : NetWorkRuleNode
{
    std::string strIpAddress;
    std::string strPorts;
    std::vector<std::string> vecPorts;
    void clear()
    {
        strRuleName = "";
        strIpAddress = "";
        strProtocol = "";
        vecPorts.clear();
        strPorts = "";
        strAction = "";
        strLevel = "";
    }
}DENY_RULE, * PDENY_RULE;

typedef struct _TCPCONNECT_RULE : NetWorkRuleNode
{
    std::string strProcessName;
    std::vector<std::string> vecProcessName;
    std::string strRedirectIp;
    void clear()
    {
        strLevel = "";
        strAction = "";
        strRuleName = "";
        strProtocol = "";
        strRedirectIp = "";
        strProcessName = "";
        vecProcessName.clear();
    }
}TCPCONNECT_RULE, * PTCPCONNECT_RULE;

typedef struct _NetRuleNode
{
    std::vector<DENY_RULE> vecDeny;
    std::vector<TCPCONNECT_RULE> vecConnect;
}NetRuleNode, * PNetRuleNode;

class NetRule
{
public:
	NetRule();
	~NetRule();

    void SetDenyRule(const DENY_RULE& vecDeny);
	void SetTcpConnectRule(const TCPCONNECT_RULE& vecConnect);
	void NetRuleClear();

private:
    std::vector<DENY_RULE> m_vecDenyRule;
    std::vector<TCPCONNECT_RULE> m_vecConnectRule;
};
