// [+] 后面一直到RuleEngineLib
#include "ntbasic.h"
#include "NetRule.h"
#include "CodeTool.h"
#include <map>

#define Length 4

// 子网掩码对照表
std::map<std::string, int>	g_mapNetMask;

void InitMask()
{
	g_mapNetMask.clear();
	g_mapNetMask["255.255.255.255"] = 32;
	g_mapNetMask["255.255.255.254"] = 31;
	g_mapNetMask["255.255.255.252"] = 30;
	g_mapNetMask["255.255.255.248"] = 29;
	g_mapNetMask["255.255.255.240"] = 28;
	g_mapNetMask["255.255.255.224"] = 27;
	g_mapNetMask["255.255.255.192"] = 26;
	g_mapNetMask["255.255.255.128"] = 25;

	g_mapNetMask["255.255.255.0"] = 24;
	g_mapNetMask["255.255.254.0"] = 23;
	g_mapNetMask["255.255.252.0"] = 22;
	g_mapNetMask["255.255.248.0"] = 21;
	g_mapNetMask["255.255.240.0"] = 20;
	g_mapNetMask["255.255.224.0"] = 19;
	g_mapNetMask["255.255.192.0"] = 18;
	g_mapNetMask["255.255.128.0"] = 17;

	g_mapNetMask["255.255.0.0"] = 16;
	g_mapNetMask["255.254.0.0"] = 15;
	g_mapNetMask["255.252.0.0"] = 14;
	g_mapNetMask["255.248.0.0"] = 13;
	g_mapNetMask["255.240.0.0"] = 12;
	g_mapNetMask["255.224.0.0"] = 11;
	g_mapNetMask["255.192.0.0"] = 10;
	g_mapNetMask["255.128.0.0"] = 9;

	g_mapNetMask["255.0.0.0"] = 8;
	g_mapNetMask["254.0.0.0"] = 7;
	g_mapNetMask["252.0.0.0"] = 6;
	g_mapNetMask["248.0.0.0"] = 5;
	g_mapNetMask["240.0.0.0"] = 4;
	g_mapNetMask["224.0.0.0"] = 3;
	g_mapNetMask["192.0.0.0"] = 2;
	g_mapNetMask["128.0.0.0"] = 1;
	g_mapNetMask["0.0.0.0"] = 0;
}

inline int charToInt(char ch, int sum) {
	try
	{
		const int result = sum * 10 + (ch - '0');
		return result;
	}
	catch (const std::exception&)
	{
	}
}

inline void ipAndSubIP(int* nums1, int* nums2, int* nums3) {
	try
	{
		for (int i = 0; i < Length; i++) {
			nums3[i] = nums1[i] & nums2[i];
		}
	}
	catch (const std::exception&)
	{
	}
}

void GetFlagToString(int* nums, char* ch) {
	try
	{
		int count = 0;
		for (int i = 0; i < Length; i++) {
			int num = nums[i];
			int getH = num / 100;
			int getM = num / 10 % 10;
			int getL = num % 10;
			if (getH) {
				ch[count++] = getH + '0';
				ch[count++] = getM + '0';
			}
			else if (getM) {
				ch[count++] = getM + '0';
			}
			ch[count++] = getL + '0';
			ch[count++] = '.';
		}
		ch[count - 1] = '\0';
	}
	catch (const std::exception&)
	{
	}
}

void GetIntOfIp(char* ip, int* intArray) {
	try
	{
		int count = 0;
		int temp = 0;
		while (*ip != '\0') {

			if (*ip == '.') {
				intArray[count] = temp;
				count++;
				temp = 0;
			}
			else if (count == 0) {
				temp = charToInt(*ip, temp);
			}
			else if (count == 1) {
				temp = charToInt(*ip, temp);
			}
			else if (count == 2) {
				temp = charToInt(*ip, temp);
			}
			else if (count == 3) {
				temp = charToInt(*ip, temp);
			}
			ip++;
		}
		intArray[count] = temp;
	}
	catch (const std::exception&)
	{
	}
}

const int GetResult(char* ip, char* subNet, char* ch) {
	int iCountHost = 0;
	int ip1Array[Length] = { 0, }, ip2Array[Length] = { 0, }, \
		ip3Array[Length] = { 0, }, flag1Array[Length] = { 0, };
	GetIntOfIp(ip, ip1Array);
	GetIntOfIp(subNet, ip2Array);
	GetIntOfIp(subNet, ip3Array);
	try
	{
		for (int i = 0; i < Length; i++) {
			while (ip3Array[i]) {
				if (ip3Array[i] & 1) {
					++iCountHost;
				}
				ip3Array[i] = ip3Array[i] >> 1;
			}
		}
		ipAndSubIP(ip1Array, ip2Array, flag1Array);
		GetFlagToString(flag1Array, ch);
		return iCountHost;
	}
	catch (const std::exception&)
	{
		return 0;
	}
}

const bool GetIpAddrMask(const std::string strIpAddr, std::string& strIpAddrSub)
{
	try
	{
		std::string strtokIpAddr = strIpAddr;
		std::vector<int> vecIpAddr;
		char* vector_ip = strtok((char*)strtokIpAddr.c_str(), ".");
		if (vector_ip) {
			while (vector_ip != NULL)
			{
				vecIpAddr.push_back(atoi(vector_ip));
				vector_ip = strtok(NULL, ".");
			}
		}
		if (vecIpAddr.empty())
			return false;
		if (vecIpAddr[0] < 0)
			return false;
		// Get Ip Network SuBNet
		char rIp[24] = { 0, }; char cIp[24] = { 0, }; int nHost = 0;
		strcpy(rIp, strIpAddr.c_str());
		// A
		if (vecIpAddr[0] <= 127) {
			nHost = GetResult(rIp, (char*)"255.0.0.0", cIp);
		}
		// B
		else if (vecIpAddr[0] <= 191) {
			nHost = GetResult(rIp, (char*)"255.255.0.0", cIp);
		}
		// C
		else if (vecIpAddr[0] <= 224) {
			nHost = GetResult(rIp, (char*)"255.255.255.0", cIp);
		}
		else
			return false;
		strIpAddrSub = cIp;
		strIpAddrSub.append("/").append(std::to_string(nHost));
	}
	catch (const std::exception&)
	{
		return false;
	}
	return true;
}

NetRule::NetRule()
{
}

NetRule::~NetRule()
{
}

void NetRule::SetDenyRule(const DENY_RULE& rDenyNode)
{
	std::unique_lock<std::mutex> lock(m_ruleDenyMtx);
	m_vecDenyRule.push_back(rDenyNode);
}

void NetRule::SetRediRectRule(const REDIRECT_RULE& rConnectNode)
{
	std::unique_lock<std::mutex> lock(m_ruleRediRectMtx);
	m_vecRedirectRule.push_back(rConnectNode);
}

void NetRule::SetDnsRule(const DNS_RULE& rDnsNode) 
{
	std::unique_lock<std::mutex> lock(m_ruleDnsMtx);
	m_vecDnsRule.push_back(rDnsNode);
}

const bool NetRule::FilterConnect(const std::string strIpaddr, const int iPort, std::string strProtocol)
{
	std::unique_lock<std::mutex> lock(m_ruleDenyMtx);
	if (m_vecDenyRule.empty()) {
		OutputDebugStringA("[HadesNetMon] FilterConnect DenyRule Empty");
		return false;
	}
	bool bFilter = false; bool bHit = false;
	const std::string strRPort = std::to_string(iPort);
	for (const auto iter : m_vecDenyRule) {
		if ((0 != strcmp(iter.strProtocol.c_str(), "ALL")) && (0 != strcmp(iter.strProtocol.c_str(), strProtocol.c_str()))) 
			continue;
		bHit = false;
		// 1: Filter Port
		for (const auto iterPort : iter.vecPorts) {
			std::string::size_type nPos = iterPort.find("-");
			if (nPos == std::string::npos) {
				if (strRPort == iterPort) {
					bHit = true;
					break;
				}
			}
			else
			{
				const int iStartPort = atoi(iterPort.substr(0, nPos).c_str());
				const int iEndPort = atoi(iterPort.substr(nPos + 1).c_str());
				if ((iPort >= iStartPort) && (iPort <= iEndPort)) {
					bHit = true;
					break;
				}
			}
		}
		// empty means all ports
		if (iter.vecPorts.empty())
			bHit = true;
		if (false == bHit)
			continue;
		// 2: Filter Ip
		std::string strIpMask = "";
		GetIpAddrMask(strIpaddr.c_str(), strIpMask);
		if (strIpMask == iter.strIpAddress) {
			bFilter = true;
			break;
		}
	}
	return bFilter;
}

const bool NetRule::FilterRedirect(const std::string strProcessName, const std::string strIpaddr, const int iPort, std::string& strRediRectIp, int& iRedrectPort, std::string strProtocol) 
{
	// 仅支持进程, ip:port粒度不支持
	std::unique_lock<std::mutex> lock(m_ruleRediRectMtx);
	if (m_vecRedirectRule.empty())
		return false;
	for (const auto iter : m_vecRedirectRule) {
		if (iter.strProtocol != strProtocol)
			continue;
		// empty means all process.
		if (iter.vecProcessName.empty()) {
			strRediRectIp = iter.strRedirectIp;
			iRedrectPort = iter.iRedirectPort;
			return true;
		}
		for (const auto iterNode : iter.vecProcessName) {
			if (strProcessName == iterNode) {
				strRediRectIp = iter.strRedirectIp;
				iRedrectPort = iter.iRedirectPort;
				return true;
			}
		}
	}
	return false;
}

const bool NetRule::FilterDnsPacket(const std::string& sDomainName) {
	try
	{
		for (const auto& iter : m_vecDnsRule) {
			if (CodeTool::MatchString(sDomainName.c_str(), iter.sDnsName.c_str()))
				return true;
		}
		return false;
	}
	catch (const std::exception&)
	{
		return false;
	}
}

void NetRule::NetRuleClear()
{
	{
		std::unique_lock<std::mutex> lock(m_ruleDenyMtx);
		m_vecDenyRule.clear();
	}

	{
		std::unique_lock<std::mutex> lock(m_ruleRediRectMtx);
		m_vecRedirectRule.clear();
	}
}