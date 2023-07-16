#pragma once
#include <string>

#ifdef __cplusplus
extern "C" {
#endif

	// parsing config to "InjectProcessNameArray"
	__declspec(dllexport) const bool ConfigThreadJsonRuleParsing(std::string& strProcessNameList);

#ifdef __cplusplus
}
#endif