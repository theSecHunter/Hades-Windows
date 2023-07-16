#pragma once
#include <string>

#ifdef __cplusplus
extern "C" {
#endif

	__declspec(dllexport) const bool ConfigDirectoryJsonRuleParsing(std::string& strNameWhitelis, std::string& strNameBlacklis, std::string& strDirPathWhitelis, std::string& strDirPathBlacklis);

#ifdef __cplusplus
}
#endif