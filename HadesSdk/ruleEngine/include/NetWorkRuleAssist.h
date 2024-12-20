#pragma once
#include <string>
#include <vector>

typedef struct _NetWorkRuleNode
{
    char strRuleName[256];
    char strProtocol[10];
    char strAction[10];
    char strLevel[10];
}NetWorkRuleNode, * PNetWorkRuleNode;

typedef struct _DENY_RULE : NetWorkRuleNode
{
    char strIpAddress[24];
    char strPorts[10];
    void clear()
    {
        memset(strRuleName, 0, sizeof(strRuleName));
        memset(strProtocol, 0, sizeof(strProtocol));
        memset(strAction, 0, sizeof(strAction));
        memset(strLevel, 0, sizeof(strLevel));

        memset(strIpAddress, 0, sizeof(strIpAddress));
        memset(strPorts, 0, sizeof(strPorts));
    }
}DENY_RULE, * PDENY_RULE;

typedef struct _REDIRECT_RULE : NetWorkRuleNode
{
    int  RedrectPort;
    char strProcessName[4096];
    char strRedirectIp[24];
    void clear()
    {
        memset(strRuleName, 0, sizeof(strRuleName));
        memset(strProtocol, 0, sizeof(strProtocol));
        memset(strAction, 0, sizeof(strAction));
        memset(strLevel, 0, sizeof(strLevel));

        RedrectPort = 0;
        memset(strProcessName, 0, sizeof(strProcessName));
        memset(strRedirectIp, 0, sizeof(strRedirectIp));
    }
}REDIRECT_RULE, * PREDIRECT_RULE;

typedef struct _DNS_RULE :NetWorkRuleNode
{
    std::string sDnsName;
    void clear()
    {
        sDnsName = "";
    }
}DNS_RULE, * PDNS_RULE;

#ifdef __cplusplus
extern "C" {
#endif

    __declspec(dllexport) const bool ConfigNetWorkYamlRuleParsing(DENY_RULE* const pDenyRule, int* pDenyCounter, REDIRECT_RULE* const pConnectRule, int* pConnetCounter, const int iMaxCounter);

    __declspec(dllexport) const bool ConfigNetWorkYamlDnsRuleParsing(DNS_RULE* const pDnsRule, int* pDnsCounter, const int iMaxCounter);

#ifdef __cplusplus
}
#endif