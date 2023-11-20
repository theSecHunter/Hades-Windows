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

typedef struct _REDIRECT_RULE : NetWorkRuleNode
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
}REDIRECT_RULE, * PREDIRECT_RULE;

typedef struct _DNS_RULE :NetWorkRuleNode 
{
    std::string sDnsName;
    void clear()
    {
        sDnsName = "";
    }
}DNS_RULE, *PDNS_RULE;

typedef struct _NetRuleNode
{
    std::vector<DENY_RULE> vecDeny;
    std::vector<REDIRECT_RULE> vecRedirect;
    std::vector<DNS_RULE> vecDns;
}NetRuleNode, * PNetRuleNode;

class NetRule
{
public:
	NetRule();
	~NetRule();

    
    void SetDenyRule(const DENY_RULE& rDenyNode);
	void SetRediRectRule(const REDIRECT_RULE& rConnectNode);
    void SetDnsRule(const DNS_RULE& rDnsNode);

    // Tcp/Udp Conenct Filter
    const bool FilterConnect(const std::string strIpaddr, const int iPort, std::string strProtocol);

    // Tcp RediRect to ProxyServer
    const bool FilterRedirect(const std::string strProcessName, const std::string strIpaddr, const int iPort, std::string& strRediRectIp, int& iRedrectPort, std::string strProtocol);

    // DNS
    const bool FilterDnsPacket(const std::string& sDomainName);

	void NetRuleClear();

private:
    std::mutex  m_ruleDenyMtx;
    std::vector<DENY_RULE> m_vecDenyRule;

    std::mutex  m_ruleRediRectMtx;
    std::vector<REDIRECT_RULE> m_vecRedirectRule;

    std::mutex  m_ruleDnsMtx;
    std::vector<DNS_RULE> m_vecDnsRule;
};
