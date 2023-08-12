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
}DENY_RULE, *PDENY_RULE;

typedef struct _TCPCONNECT_RULE : NetWorkRuleNode
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
}TCPCONNECT_RULE, * PTCPCONNECT_RULE;

#ifdef __cplusplus
extern "C" {
#endif

    __declspec(dllexport) const bool ConfigNetWorkYamlRuleParsing(DENY_RULE* const pDenyRule, int* pDenyCounter, TCPCONNECT_RULE* const pConnectRule, int* pConnetCounter, const int iMaxCounter);

#ifdef __cplusplus
}
#endif