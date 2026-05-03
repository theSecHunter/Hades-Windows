#include "msgassist.h"

// ÖÇÄÜÖ¸Õë or ÄÚ´æ³Ø
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
    if (str.empty())
        return "";

    const int wideLen = MultiByteToWideChar(CP_ACP, 0, str.c_str(), -1, nullptr, 0);
    if (wideLen <= 0)
        return "";

    std::wstring wideText(static_cast<size_t>(wideLen), L'\0');
    if (MultiByteToWideChar(CP_ACP, 0, str.c_str(), -1, &wideText[0], wideLen) <= 0)
        return "";

    const int utf8Len = WideCharToMultiByte(CP_UTF8, 0, wideText.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (utf8Len <= 0)
        return "";

    std::string utf8Text(static_cast<size_t>(utf8Len), '\0');
    if (WideCharToMultiByte(CP_UTF8, 0, wideText.c_str(), -1, &utf8Text[0], utf8Len, nullptr, nullptr) <= 0)
        return "";

    if (!utf8Text.empty() && utf8Text.back() == '\0')
        utf8Text.pop_back();
    return utf8Text;
}
std::string UTF8_ToString(const std::string& str)
{
    if (str.empty())
        return "";

    const int wideLen = MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, nullptr, 0);
    if (wideLen <= 0)
        return "";

    std::wstring wideText(static_cast<size_t>(wideLen), L'\0');
    if (MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, &wideText[0], wideLen) <= 0)
        return "";

    const int ansiLen = WideCharToMultiByte(CP_ACP, 0, wideText.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (ansiLen <= 0)
        return "";

    std::string ansiText(static_cast<size_t>(ansiLen), '\0');
    if (WideCharToMultiByte(CP_ACP, 0, wideText.c_str(), -1, &ansiText[0], ansiLen, nullptr, nullptr) <= 0)
        return "";

    if (!ansiText.empty() && ansiText.back() == '\0')
        ansiText.pop_back();
    return ansiText;
}
std::wstring Str2WStr(const std::string& str)
{
    if (str.empty())
        return L"";

    const int wideLen = MultiByteToWideChar(CP_ACP, 0, str.c_str(), -1, nullptr, 0);
    if (wideLen <= 0)
        return L"";

    std::wstring wideText(static_cast<size_t>(wideLen), L'\0');
    if (MultiByteToWideChar(CP_ACP, 0, str.c_str(), -1, &wideText[0], wideLen) <= 0)
        return L"";

    if (!wideText.empty() && wideText.back() == L'\0')
        wideText.pop_back();
    return wideText;
}
std::string WStr2Str(const std::wstring& wstr)
{
    if (wstr.empty())
        return "";

    const int ansiLen = WideCharToMultiByte(CP_ACP, 0, wstr.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (ansiLen <= 0)
        return "";

    std::string ansiText(static_cast<size_t>(ansiLen), '\0');
    if (WideCharToMultiByte(CP_ACP, 0, wstr.c_str(), -1, &ansiText[0], ansiLen, nullptr, nullptr) <= 0)
        return "";

    if (!ansiText.empty() && ansiText.back() == '\0')
        ansiText.pop_back();
    return ansiText;
}
void Wchar_tToString(std::string& szDst, const wchar_t* wchar)
{
    try
    {
        if (lstrlenW(wchar) <= 0)
        {
            szDst = " ";
            return;
        }
        const wchar_t* wText = wchar;
        DWORD dwNum = WideCharToMultiByte(CP_ACP, 0, wText, -1, NULL, 0, NULL, FALSE);
        if (dwNum <= 0)
        {
            szDst = " ";
            return;
        }
        char* psText = nullptr;
        psText = (char*)new char[dwNum + 1];
        if (psText)
        {
            WideCharToMultiByte(CP_ACP, 0, wText, -1, psText, dwNum, NULL, FALSE);
            psText[dwNum - 1] = 0;
            szDst = psText;
            delete[] psText;
        }
    }
    catch (const std::exception&)
    {
    }
}