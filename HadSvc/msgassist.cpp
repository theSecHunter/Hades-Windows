#include "msgassist.h"

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

    // etw


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
    try
    {
        int nwLen = ::MultiByteToWideChar(CP_ACP, 0, str.c_str(), -1, NULL, 0);
        wchar_t* pwBuf = new wchar_t[nwLen + 1];
        ZeroMemory(pwBuf, nwLen * 2 + 2);
        ::MultiByteToWideChar(CP_ACP, 0, str.c_str(), str.length(), pwBuf, nwLen);
        int nLen = ::WideCharToMultiByte(CP_UTF8, 0, pwBuf, -1, NULL, NULL, NULL, NULL);
        char* pBuf = new char[nLen + 1];
        ZeroMemory(pBuf, nLen + 1);
        ::WideCharToMultiByte(CP_UTF8, 0, pwBuf, nwLen, pBuf, nLen, NULL, NULL);
        std::string retStr(pBuf);
        delete[]pwBuf;
        delete[]pBuf;
        pwBuf = NULL;
        pBuf = NULL;
        return retStr;
    }
    catch (const std::exception&)
    {
    }
    return "";
}
std::string UTF8_ToString(const std::string& str)
{
    try
    {
        int nwLen = MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, NULL, 0);
        wchar_t* pwBuf = new wchar_t[nwLen + 1];
        memset(pwBuf, 0, nwLen * 2 + 2);
        MultiByteToWideChar(CP_UTF8, 0, str.c_str(), str.length(), pwBuf, nwLen);
        int nLen = WideCharToMultiByte(CP_ACP, 0, pwBuf, -1, NULL, NULL, NULL, NULL);
        char* pBuf = new char[nLen + 1];
        memset(pBuf, 0, nLen + 1);
        WideCharToMultiByte(CP_ACP, 0, pwBuf, nwLen, pBuf, nLen, NULL, NULL);
        std::string retStr = pBuf;
        delete[]pBuf;
        delete[]pwBuf;
        pBuf = NULL;
        pwBuf = NULL;
        return retStr;
    }
    catch (const std::exception&)
    {
    }
}