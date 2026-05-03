#include "msgassist.h"

// 智能指针 or 内存池 or vectory
#include <limits>

namespace {

bool MultiByteToWideString(const std::string& input, UINT codePage, std::wstring& output)
{
    output.clear();
    if (input.empty())
        return true;

    if (input.size() > static_cast<size_t>((std::numeric_limits<int>::max)()))
        return false;

    const int inputLen = static_cast<int>(input.size());
    const int wideLen = ::MultiByteToWideChar(codePage, 0, input.data(), inputLen, nullptr, 0);
    if (wideLen <= 0)
        return false;

    output.resize(wideLen);
    return ::MultiByteToWideChar(codePage, 0, input.data(), inputLen, &output[0], wideLen) == wideLen;
}

bool WideToMultiByteString(const std::wstring& input, UINT codePage, std::string& output)
{
    output.clear();
    if (input.empty())
        return true;

    if (input.size() > static_cast<size_t>((std::numeric_limits<int>::max)()))
        return false;

    const int inputLen = static_cast<int>(input.size());
    const int multiLen = ::WideCharToMultiByte(codePage, 0, input.data(), inputLen, nullptr, 0, nullptr, nullptr);
    if (multiLen <= 0)
        return false;

    output.resize(multiLen);
    return ::WideCharToMultiByte(codePage, 0, input.data(), inputLen, &output[0], multiLen, nullptr, nullptr) == multiLen;
}

} // namespace

// 智能指针 or 内存池 or vectory
bool Choose_mem(char*& ptr, DWORD& dwAllocateMemSize, const int code)
{
    dwAllocateMemSize = 0;

    // kernel
    switch (code)
    {
    case NF_SSDT_ID:
    {
        dwAllocateMemSize = sizeof(SSDTINFO) * 0x200;
    }
    break;
    case NF_IDT_ID:
    {
        dwAllocateMemSize = sizeof(IDTINFO) * 0x100;
    }
    break;
    case NF_DPC_ID:
    {
        dwAllocateMemSize = sizeof(DPC_TIMERINFO) * 0x200;
    }
    break;
    case NF_FSD_ID:
    {
        dwAllocateMemSize = sizeof(ULONGLONG) * 0x1b * 2 + 1;
    }
    break;
    case NF_MOUSEKEYBOARD_ID:
    {
        dwAllocateMemSize = sizeof(ULONGLONG) * 0x1b * 3 + 1;
    }
    break;
    case NF_NETWORK_ID:
    {
        dwAllocateMemSize = sizeof(SYSNETWORKINFONODE);
    }
    break;
    case NF_PROCESS_ENUM:
    {
        dwAllocateMemSize = sizeof(HANDLE_INFO) * 1024 * 2;
    }
    break;
    case NF_PROCESS_MOD:
    {
        dwAllocateMemSize = sizeof(PROCESS_MOD) * 1024 * 2;
    }
    break;
    case NF_PROCESS_KILL:
    {
        dwAllocateMemSize = 1;
    }
    break;
    case NF_SYSMOD_ENUM:
    {
        dwAllocateMemSize = sizeof(PROCESS_MOD) * 1024 * 2;
    }
    break;
    case NF_EXIT:
    {
        dwAllocateMemSize = 1;
    }
    break;
    default:
        break;
    }

    // user
    switch (code)
    {
    case UF_PROCESS_ENUM:
    {
        dwAllocateMemSize = sizeof(UProcessNode) + 1;
    }
    break;
    case UF_PROCESS_PID_TREE:
    {
        dwAllocateMemSize = 0;
    }
    break;
    case UF_SYSAUTO_START:
    {
        dwAllocateMemSize = sizeof(UAutoStartNode) + 1;
    }
    break;
    case UF_SYSNET_INFO:
    {
        dwAllocateMemSize = sizeof(UNetNode) + 1;
    }
    break;
    case UF_SYSSESSION_INFO:
    {
        dwAllocateMemSize = 0;
    }
    break;
    case UF_SYSINFO_ID:
    {
        dwAllocateMemSize = 0;
    }
    break;
    case UF_SYSLOG_ID:
    {
        dwAllocateMemSize = 0;
    }
    break;
    case UF_SYSUSER_ID:
    {
        dwAllocateMemSize = sizeof(UUserNode) + 1;
    }
    break;
    case UF_SYSSERVICE_SOFTWARE_ID:
    {
        dwAllocateMemSize = sizeof(UAllServerSoftware) + 1;
    }
    break;
    case UF_SYSFILE_ID:
    {
        dwAllocateMemSize = sizeof(UDriectInfo) + 1;
    }
    break;
    case UF_FILE_INFO:
    {
        dwAllocateMemSize = sizeof(UFileInfo) + 1;
    }
    break;
    case UF_ROOTKIT_ID:
    {
        dwAllocateMemSize = 0;
    }
    break;
    default:
        break;
    }

    if (0 == dwAllocateMemSize)
        return false;

    ptr = new char[dwAllocateMemSize];
    if (ptr)
    {
        RtlSecureZeroMemory(ptr, dwAllocateMemSize);
        return true;
    }

    return false;
}
std::string String_ToUtf8(const std::string& str)
{
    std::wstring wideStr;
    std::string retStr;
    if (!MultiByteToWideString(str, CP_ACP, wideStr))
        return retStr;
    if (!WideToMultiByteString(wideStr, CP_UTF8, retStr))
        retStr.clear();
    return retStr;
}
std::string UTF8_ToString(const std::string& str)
{
    std::wstring wideStr;
    std::string retStr;
    if (!MultiByteToWideString(str, CP_UTF8, wideStr))
        return retStr;
    if (!WideToMultiByteString(wideStr, CP_ACP, retStr))
        retStr.clear();
    return retStr;
}
std::wstring Str2WStr(const std::string& str)
{
    std::wstring retStr;
    if (!MultiByteToWideString(str, CP_ACP, retStr))
        retStr.clear();
    return retStr;
} 
std::string WStr2Str(const std::wstring& wstr)
{
    std::string retStr;
    if (!WideToMultiByteString(wstr, CP_ACP, retStr))
        retStr.clear();
    return retStr;
}
void Wchar_tToString(std::string& szDst, const wchar_t* wchar)
{
    if (!wchar || lstrlenW(wchar) <= 0)
    {
        szDst = " ";
        return;
    }

    const std::wstring wideStr(wchar);
    if (!WideToMultiByteString(wideStr, CP_ACP, szDst) || szDst.empty())
        szDst = " ";
}
