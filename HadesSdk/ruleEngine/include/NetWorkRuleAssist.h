#pragma once
#include <string>

#ifdef __cplusplus
extern "C" {
#endif

	// parsing config to
	__declspec(dllexport) const bool ConfigNetWorkYamlRuleParsing(unsigned int& imods, std::string& strProcessNameList);

#ifdef __cplusplus
}
#endif