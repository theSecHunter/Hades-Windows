#pragma once
#include <string>

#ifdef __cplusplus
extern "C" {
#endif

	// Find Rule
	__declspec(dllexport) const bool FindRegisterRuleHit(const REGISTERINFO* const registerinfo);

	// parsing config nRet ProcessNameList
	__declspec(dllexport) const bool ConfigRegisterJsonRuleParsing(std::string& strProcessNameList);

#ifdef __cplusplus
}
#endif