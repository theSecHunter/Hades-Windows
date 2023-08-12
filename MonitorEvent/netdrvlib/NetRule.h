#pragma once
#include <vector>
#include <string>
#include <mutex>

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
    int iRedirectPort;
    std::string strRedirectIp;
    void clear()
    {
        iRedirectPort = 0;
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

    // Tcp/Udp Conenct Filter
    const bool FilterConnect(const std::string strIpaddr, const int iPort);

    // Tcp RediRect to ProxyServer
    const bool RedirectTcpConnect(const std::string strProcessName, const std::string strIpaddr, const int iPort, std::string& strRediRectIp, int& iRedrectPort);

	void NetRuleClear();

private:
    std::mutex  m_ruleDenyMtx;
    std::vector<DENY_RULE> m_vecDenyRule;

    std::mutex  m_ruleRediRectMtx;
    std::vector<TCPCONNECT_RULE> m_vecRedirectConnectRule;
};
