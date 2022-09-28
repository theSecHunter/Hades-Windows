#pragma once
#include <string>
#include <vector>
#include <set>

bool IsFile(const std::string& fileName);
bool GetCurrentExePath(std::string& Path);
void SplitiStr(std::set<std::string>& vecProcesName, const std::string& sData);