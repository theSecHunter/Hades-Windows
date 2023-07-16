#pragma once
#include <string>

#ifdef __cplusplus
extern "C" {
#endif

	// parsing config to "processName" & "processRuleMod"
	__declspec(dllexport) const bool ConfigProcessJsonRuleParsing(unsigned int& imods, std::string& strProcessNameList);

#ifdef __cplusplus
}
#endif