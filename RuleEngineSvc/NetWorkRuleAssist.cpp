#include "pch.h"
#include "utiltools.h"
#include "NetWorkRuleAssist.h"
#include <yaml-cpp/yaml.h>
#include <vector>
#include <string>
#include <fstream>
#include <iostream>

static const std::string g_NetWorkConfigName = "networkRuleConfig.yaml";

const bool ConfigNetWorkYamlRuleParsing(NetWorkRuleNode& ruleNode)
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
        YAML::Node config = YAML::LoadFile(strRet);
        if (!config["address"].IsNull())
            ruleNode.strIpAddress = config["address"].as<std::string>();
        if (!config["ports"].IsNull())
            ruleNode.ports = config["ports"].as<std::vector<string>>();
    }
    catch (const std::exception&)
    {
        return false;
    }
	return true;
}