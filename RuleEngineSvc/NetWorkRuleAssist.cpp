#include "pch.h"
#include "utiltools.h"
#include "NetWorkRuleAssist.h"
#include <yaml-cpp/yaml.h>
#include <vector>
#include <string>
#include <fstream>
#include <iostream>

static const std::string g_NetWorkConfigName = "networkRuleConfig.yaml";

const bool ConfigNetWorkYamlRuleParsing(std::vector<NetWorkRuleNode>& vecRuleNode)
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

        NetWorkRuleNode ruleNode;
        std::ifstream fin;
        fin.open(strRet.c_str());
        const YAML::Node config = YAML::LoadFile(strRet);
        do
        {
            ruleNode.clear();
            const auto pRoot = config["egress"];
            if (pRoot.IsNull())
                break;
            for (const auto& iter : pRoot)
            {
                if (!iter["name"].IsNull() && iter["name"].IsScalar())
                    ruleNode.strRuleName = iter["name"].as<std::string>();
                if (!iter["address"].IsNull() && iter["address"].IsScalar())
                    ruleNode.strIpAddress = iter["address"].as<std::string>();
                if (!iter["ports"].IsNull() && iter["ports"].IsSequence())
                {
                    for (const auto iterPort : iter["ports"])
                    {
                        if (iterPort.IsScalar())
                            ruleNode.ports.push_back(iterPort.as<std::string>());
                    }
                }

                if (!iter["protocol"].IsNull() && iter["protocol"].IsScalar())
                    ruleNode.strProtocol = iter["protocol"].as<std::string>();
                if (!iter["action"].IsNull() && iter["action"].IsScalar())
                    ruleNode.strAction = iter["action"].as<std::string>();
                if (!iter["level"].IsNull() && iter["level"].IsScalar())
                    ruleNode.strLevel = iter["level"].as<std::string>();
                vecRuleNode.push_back(ruleNode);
            }
        } while (false);
    }
    catch (const std::exception&)
    {
        return false;
    }
	return true;
}