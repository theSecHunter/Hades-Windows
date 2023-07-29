#pragma once
#include <sysinfo.h>

#ifdef __cplusplus
extern "C" {
#endif

	// parsing config to
	__declspec(dllexport) const bool ConfigNetWorkYamlRuleParsing(NetWorkRuleNode& ruleNode);

#ifdef __cplusplus
}
#endif