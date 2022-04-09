#pragma once
#include <sysinfo.h>
#include <string>
extern std::string String_ToUtf8(const std::string& str);
extern std::string UTF8_ToString(const std::string& str);
extern bool Choose_mem(char*& ptr, DWORD& dwAllocateMemSize, const int code);