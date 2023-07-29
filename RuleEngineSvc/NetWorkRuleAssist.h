#pragma once
#include <string>

#ifdef __cplusplus
extern "C" {
#endif

	// parsing config to
	__declspec(dllexport) const bool WINAPI ConfigNetWorkYamlRuleParsing(NetWorkRuleNode& ruleNode);

#ifdef __cplusplus
}
#endif