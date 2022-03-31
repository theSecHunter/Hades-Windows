#pragma once

extern void Wchar_tToString(std::string& szDst, wchar_t* wchar);
extern bool Choose_mem(char*& ptr, DWORD64& dwAllocateMemSize, const int code);