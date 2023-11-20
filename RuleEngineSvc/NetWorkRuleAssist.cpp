#include "pch.h"
#include "utiltools.h"
#include "NetWorkRuleAssist.h"
#include <yaml-cpp/yaml.h>
#include <vector>
#include <string>
#include <fstream>
#include <iostream>

static const std::string g_NetWorkConfigName = "networkRuleConfig.yaml";

const bool ConfigNetWorkYamlRuleParsing(DENY_RULE* const pDenyRule, int* pDenyCounter, REDIRECT_RULE* const pConnectRule, int* pConnetCounter, const int iMaxCounter)
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
            const auto pRoot = config["tc"];
            if (pRoot.IsNull()) {
                OutputDebugStringA(("[HadesNetMon] Network Rule tc Failuer." + strRet).c_str());
                break;
            }
            
            std::string strAction = "";
            for (const auto iter : pRoot)
            {
                if (!iter["action"].IsNull() && iter["action"].IsScalar())
                    strAction = iter["action"].as<std::string>().c_str();
                else
                    continue;
                if ((strAction == "DENY") && (*pDenyCounter < iMaxCounter)) {
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
                else if ((strAction == "REDIRECT") && (*pConnetCounter < iMaxCounter)) {
                    strcpy(pConnectRule[*pConnetCounter].strAction, strAction.c_str());
                    if (!iter["name"].IsNull() && iter["name"].IsScalar())
                        strcpy(pConnectRule[*pConnetCounter].strRuleName, iter["name"].as<std::string>().c_str());
                    if (!iter["protocol"].IsNull() && iter["protocol"].IsScalar())
                        strcpy(pConnectRule[*pConnetCounter].strProtocol, iter["protocol"].as<std::string>().c_str());
                    if (!iter["level"].IsNull() && iter["level"].IsScalar())
                        strcpy(pConnectRule[*pConnetCounter].strLevel, iter["level"].as<std::string>().c_str());
                    if (!iter["processname"].IsNull() && iter["processname"].IsScalar())
                        strcpy(pConnectRule[*pConnetCounter].strProcessName, iter["processname"].as<std::string>().c_str());
                    if (!iter["redirectip"].IsNull() && iter["redirectip"].IsScalar())
                        strcpy(pConnectRule[*pConnetCounter].strRedirectIp, iter["redirectip"].as<std::string>().c_str());
                    if (!iter["redirectport"].IsNull() && iter["redirectport"].IsScalar())
                        pConnectRule[*pConnetCounter].RedrectPort = atoi(iter["redirectport"].as<std::string>().c_str());
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

const bool ConfigNetWorkYamlDnsRuleParsing(DNS_RULE* const pDnsRule, int* pDnsCounter, const int iMaxCounter)
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
            const auto pRoot = config["dns"];
            if (pRoot.IsNull()) {
                OutputDebugStringA(("[HadesNetMon] Network Rule dns Failuer." + strRet).c_str());
                break;
            }

            std::string strAction = "";
            for (const auto iter : pRoot)
            {
                if (!iter["action"].IsNull() && iter["action"].IsScalar())
                    strAction = iter["action"].as<std::string>().c_str();
                else
                    continue;
                if ((strAction == "DENY") && (*pDnsCounter < iMaxCounter)) {
                    strcpy(pDnsRule[*pDnsCounter].strAction, strAction.c_str());
                    if (!iter["name"].IsNull() && iter["name"].IsScalar())
                        strcpy(pDnsRule[*pDnsCounter].strRuleName, iter["name"].as<std::string>().c_str());
                    if (!iter["domain"].IsNull() && iter["domain"].IsScalar())
                        strcpy(pDnsRule[*pDnsCounter].strProtocol, iter["domain"].as<std::string>().c_str());
                    *pDnsCounter += 1;
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