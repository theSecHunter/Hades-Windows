#pragma once
#include <string>
#include <vector>

typedef struct _NetWorkRuleNode
{
    std::string strRuleName;
    std::string strIpAddress;
    std::string strProtocol;
    std::vector<std::string> ports;
    std::string strAction;
    std::string strLevel;
    void clear()
    {
        strRuleName = "";
        strIpAddress = "";
        strProtocol = "";
        ports.clear();
        strAction = "";
        strLevel = "";
    }
}NetWorkRuleNode, * PNetWorkRuleNode;

#ifdef __cplusplus
extern "C" {
#endif

	// parsing config to
	__declspec(dllexport) const bool ConfigNetWorkYamlRuleParsing(std::vector<NetWorkRuleNode>& ruleNode);

#ifdef __cplusplus
}
#endif