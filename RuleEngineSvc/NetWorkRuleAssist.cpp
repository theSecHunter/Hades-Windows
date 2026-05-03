#include "pch.h"
#include "utiltools.h"
#include "NetWorkRuleAssist.h"
#include <yaml-cpp/yaml.h>
#include <vector>
#include <string>
#include <fstream>
#include <iostream>

static const std::string g_NetWorkConfigName = "networkRuleConfig.yaml";

namespace
{
    template <size_t N>
    void CopyField(char(&dest)[N], const std::string& value)
    {
        strncpy_s(dest, value.c_str(), _TRUNCATE);
    }
}

const bool ConfigNetWorkYamlRuleParsing(DENY_RULE* const pDenyRule, int* pDenyCounter, REDIRECT_RULE* const pConnectRule, int* pConnetCounter, const int iMaxCounter)
{
    try
    {
        if (!pDenyRule || !pDenyCounter || !pConnectRule || !pConnetCounter)
            return false;
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
                    CopyField(pDenyRule[*pDenyCounter].strAction, strAction);
                    if (!iter["name"].IsNull() && iter["name"].IsScalar())
                        CopyField(pDenyRule[*pDenyCounter].strRuleName, iter["name"].as<std::string>());
                    if (!iter["protocol"].IsNull() && iter["protocol"].IsScalar())
                        CopyField(pDenyRule[*pDenyCounter].strProtocol, iter["protocol"].as<std::string>());
                    if (!iter["level"].IsNull() && iter["level"].IsScalar())
                        CopyField(pDenyRule[*pDenyCounter].strLevel, iter["level"].as<std::string>());
                    if (!iter["address"].IsNull() && iter["address"].IsScalar())
                        CopyField(pDenyRule[*pDenyCounter].strIpAddress, iter["address"].as<std::string>());
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
                        CopyField(pDenyRule[*pDenyCounter].strPorts, strCatPort);
                    }
                    *pDenyCounter += 1;
                }
                else if ((strAction == "REDIRECT") && (*pConnetCounter < iMaxCounter)) {
                    CopyField(pConnectRule[*pConnetCounter].strAction, strAction);
                    if (!iter["name"].IsNull() && iter["name"].IsScalar())
                        CopyField(pConnectRule[*pConnetCounter].strRuleName, iter["name"].as<std::string>());
                    if (!iter["protocol"].IsNull() && iter["protocol"].IsScalar())
                        CopyField(pConnectRule[*pConnetCounter].strProtocol, iter["protocol"].as<std::string>());
                    if (!iter["level"].IsNull() && iter["level"].IsScalar())
                        CopyField(pConnectRule[*pConnetCounter].strLevel, iter["level"].as<std::string>());
                    if (!iter["processname"].IsNull() && iter["processname"].IsScalar())
                        CopyField(pConnectRule[*pConnetCounter].strProcessName, iter["processname"].as<std::string>());
                    if (!iter["redirectip"].IsNull() && iter["redirectip"].IsScalar())
                        CopyField(pConnectRule[*pConnetCounter].strRedirectIp, iter["redirectip"].as<std::string>());
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
        if (!pDnsRule || !pDnsCounter)
            return false;
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
                    CopyField(pDnsRule[*pDnsCounter].strAction, strAction);
                    if (!iter["name"].IsNull() && iter["name"].IsScalar())
                        CopyField(pDnsRule[*pDnsCounter].strRuleName, iter["name"].as<std::string>());
                    CopyField(pDnsRule[*pDnsCounter].strProtocol, "DNS");
                    if (!iter["domain"].IsNull() && iter["domain"].IsScalar())
                        pDnsRule[*pDnsCounter].sDnsName = iter["domain"].as<std::string>();
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
