#include "msgassist.h"

// ÖÇÄÜÖ¸Õë or ÄÚ´æ³Ø or vectory
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
    std::string retStr = "";
    char* pBuf = nullptr;  wchar_t* pwBuf = nullptr;
    try
    {
        const size_t nwLen = ::MultiByteToWideChar(CP_ACP, 0, str.c_str(), -1, NULL, 0);   
        do
        {
            pwBuf = new wchar_t[nwLen + 1];
            if (!pwBuf)
                break;
            RtlSecureZeroMemory(pwBuf, nwLen * 2 + 2);
            ::MultiByteToWideChar(CP_ACP, 0, str.c_str(), str.length(), pwBuf, nwLen);
            const size_t nLen = ::WideCharToMultiByte(CP_UTF8, 0, pwBuf, -1, NULL, NULL, NULL, NULL);
            pBuf = new char[nLen + 1];
            if (!pBuf)
                break;
            RtlSecureZeroMemory(pBuf, nLen + 1);
            ::WideCharToMultiByte(CP_UTF8, 0, pwBuf, nwLen, pBuf, nLen, NULL, NULL);
            retStr = pBuf;
        } while (false);
        if (pwBuf) {
            delete[] pwBuf;
            pwBuf = NULL;
        }
        if (pBuf) {
            delete[] pBuf;
            pBuf = NULL;
        }
        return retStr;
    }
    catch (const std::exception&)
    {
        if (pwBuf) {
            delete[] pwBuf;
            pwBuf = NULL;
        }
        if (pBuf) {
            delete[] pBuf;
            pBuf = NULL;
        }
        return retStr;
    }
}
std::string UTF8_ToString(const std::string& str)
{
    std::string retStr = "";
    char* pBuf = nullptr;  wchar_t* pwBuf = nullptr;
    try
    {
        const size_t nwLen = MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, NULL, 0);
        do
        {
            pwBuf = new wchar_t[nwLen + 1];
            if (!pwBuf)
                break;
            RtlSecureZeroMemory(pwBuf, nwLen * 2 + 2);
            MultiByteToWideChar(CP_UTF8, 0, str.c_str(), str.length(), pwBuf, nwLen);
            const size_t nLen = WideCharToMultiByte(CP_ACP, 0, pwBuf, -1, NULL, NULL, NULL, NULL);
            pBuf = new char[nLen + 1];
            if (!pBuf)
                break;
            RtlSecureZeroMemory(pBuf, nLen + 1);
            WideCharToMultiByte(CP_ACP, 0, pwBuf, nwLen, pBuf, nLen, NULL, NULL);
            retStr = pBuf;
        } while (false);
        if (pwBuf) {
            delete[] pwBuf;
            pwBuf = NULL;
        }
        if (pBuf) {
            delete[] pBuf;
            pBuf = NULL;
        }
        return retStr;
    }
    catch (const std::exception&)
    {
        if (pwBuf) {
            delete[] pwBuf;
            pwBuf = NULL;
        }
        if (pBuf) {
            delete[] pBuf;
            pBuf = NULL;
        }
        return retStr;
    }
}
std::wstring Str2WStr(const std::string& str)
{
    try
    {
        USES_CONVERSION;
        return A2W(str.c_str());
    }
    catch (const std::exception&)
    {
        return L"";
    }
} 
std::string WStr2Str(const std::wstring& wstr)
{
    try
    {
        USES_CONVERSION;
        return W2A(wstr.c_str());
    }
    catch (const std::exception&)
    {
        return "";
    }
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