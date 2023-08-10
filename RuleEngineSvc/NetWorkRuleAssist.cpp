#include "pch.h"
#include "utiltools.h"
#include "NetWorkRuleAssist.h"
#include <yaml-cpp/yaml.h>
#include <vector>
#include <string>
#include <fstream>
#include <iostream>

static const std::string g_NetWorkConfigName = "networkRuleConfig.yaml";

const bool ConfigNetWorkYamlRuleParsing(DENY_RULE* const pDenyRule, int* pDenyCounter, TCPCONNECT_RULE* const pConnectRule, int* pConnetCounter)
{
    try
    {
        if (!RuleEngineToos::InitDeviceDosPathToNtPath())
            return false;
        if (!RuleEngineToos::IsFile(g_NetWorkConfigName))
            return false;
        std::string strRet;
        if (!RuleEngineToos::GetCurrentExePath(strRet))
            return false;
        strRet.append("\\config\\");
        strRet.append(g_NetWorkConfigName.c_str());

        std::ifstream fin;
        fin.open(strRet.c_str());
        const YAML::Node config = YAML::LoadFile(strRet);
        do
        {
            const auto pRoot = config["egress"];
            if (pRoot.IsNull())
                break;
            
            std::string strAction = "";
            for (const auto iter : pRoot)
            {
                if (!iter["action"].IsNull() && iter["action"].IsScalar())
                    strAction = iter["action"].as<std::string>();
                else
                    continue;
                if (strAction == "DENY") {
                    if (*pDenyCounter >= 100)
                        continue;
                    strcpy(pDenyRule[*pDenyCounter].strAction, strAction.c_str());
                    if (!iter["name"].IsNull() && iter["name"].IsScalar())
                        strcpy(pDenyRule[*pDenyCounter].strRuleName, iter["name"].as<std::string>().c_str());
                    if (!iter["protocol"].IsNull() && iter["protocol"].IsScalar())
                        strcpy(pDenyRule[*pDenyCounter].strProtocol, iter["protocol"].as<std::string>().c_str());
                    if (!iter["level"].IsNull() && iter["level"].IsScalar())
                        strcpy(pDenyRule[*pDenyCounter].strLevel, iter["level"].as<std::string>().c_str());
                    if (!iter["address"].IsNull() && iter["address"].IsScalar())
                        strcpy(pDenyRule[*pDenyCounter].strIpAddress, iter["address"].as<std::string>().c_str());
                    if (!iter["ports"].IsNull() && iter["ports"].IsSequence())
                    {
                        std::string strCatPort = "";
                        for (const auto iterPort : iter["ports"])
                        {
                            if (iterPort.IsScalar()) {
                                const std::string tPort = iterPort.as<std::string>();
                                strCatPort.append(tPort).append("|");
                            }
                        }
                        if (strCatPort.length() < 4000)
                            strcpy(pDenyRule[*pDenyCounter].strPorts, strCatPort.c_str());
                    }
                    *pDenyCounter += 1;
                }
                else if (strAction == "REDIRECT") {
                    if (*pConnetCounter >= 100)
                        continue;
                    strcpy(pConnectRule[*pConnetCounter].strAction, strAction.c_str());
                    if (!iter["name"].IsNull() && iter["name"].IsScalar())
                        strcpy(pConnectRule[*pConnetCounter].strAction, iter["name"].as<std::string>().c_str());
                    if (!iter["protocol"].IsNull() && iter["protocol"].IsScalar())
                        strcpy(pConnectRule[*pConnetCounter].strProtocol, iter["protocol"].as<std::string>().c_str());
                    if (!iter["level"].IsNull() && iter["level"].IsScalar())
                        strcpy(pConnectRule[*pConnetCounter].strLevel, iter["level"].as<std::string>().c_str());
                    if (!iter["processname"].IsNull() && iter["processname"].IsScalar())
                        strcpy(pConnectRule[*pConnetCounter].strProcessName, iter["processname"].as<std::string>().c_str());
                    if (!iter["redirectip"].IsNull() && iter["redirectip"].IsScalar())
                        strcpy(pConnectRule[*pConnetCounter].strRedirectIp, iter["redirectip"].as<std::string>().c_str());
                    *pConnetCounter += 1;
                }
            }
        } while (false);
    }
    catch (const std::exception&)
    {
        return false;
    }
	return true;
}