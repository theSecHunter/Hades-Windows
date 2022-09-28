#pragma once
#include <sysinfo.h>
#include <string>
#include <atlconv.h>

extern std::string String_ToUtf8(const std::string& str);
extern std::string UTF8_ToString(const std::string& str);
extern std::wstring Str2WStr(const std::string& str);
extern std::string WStr2Str(const std::wstring& wstr);
extern bool Choose_mem(char*& ptr, DWORD& dwAllocateMemSize, const int code);