#include "pch.h"
#include <sysinfo.h>
#include "RegisterRuleAssist.h"
#include "utiltools.h"
#include <map>

const static std::string g_RegConfigName = "registerRuleConfig.json";
typedef struct _RegRuleNode
{
	int						registerRuleMod;
	int						permissions;
	std::wstring			processName;
	std::wstring			registerValuse;
}RegRuleNode, * PRegRuleNode;
static std::vector<RegRuleNode> g_vecRegRuleList;

static std::map<const unsigned long, std::wstring> g_objRegPathMap;

void GetProcessName(const std::wstring& ProcessPath, std::wstring& ProcessPathName)
{
	// Get ProcessName
	std::wstring wsProcPath = ProcessPath;
	if (ProcessPath.empty())
		return;
	const int iLast = wsProcPath.find_last_of(L"//");
	if (!iLast)
		return;
	ProcessPathName = wsProcPath.substr(iLast + 1);
}

bool ConfigRegisterJsonRuleParsing(std::string& strProcessNameList)
{
	if (!IsFile(g_RegConfigName))
		return false;
	std::string strRet;
	if (!GetCurrentExePath(strRet))
		return false;
	strRet.append("\\config\\");
	strRet.append(g_RegConfigName.c_str());

	const HANDLE FileHandle = CreateFileA(
		strRet.c_str(),
		GENERIC_READ,
		0,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL
	);
	if (!FileHandle)
		return false;

	DWORD dwGetSize = 0;
	const DWORD dwFileSize = GetFileSize(FileHandle, &dwGetSize);
	char* const data = new char[dwFileSize + 1];
	if (data)
		RtlSecureZeroMemory(data, dwFileSize + 1);
	else
	{
		CloseHandle(FileHandle);
		return false;
	}

	bool nRet = false;
	std::set<std::string> setAllProcessName;
	static std::string strStrings;
	do {
		DWORD dwRead = 0;
		if (!ReadFile(FileHandle, data, dwFileSize, &dwRead, NULL))
			break;
		rapidjson::Document document;
		document.Parse<0>(data);
		if (document.HasParseError())
			break;
		RegRuleNode ruleNode;
		const auto rArray = document.GetArray();
		for (int idx = 0 ;  idx < rArray.Size(); ++idx)
		{
			try
			{
				if (!rArray[idx].HasMember("registerRuleMod") || !rArray[idx].HasMember("processName") || !rArray[idx].HasMember("registerValuse") || !rArray[idx].HasMember("permissions"))
					continue;
				ruleNode.registerRuleMod = rArray[idx]["registerRuleMod"].GetInt();
				strStrings = rArray[idx]["processName"].GetString();
				SplitiStr(setAllProcessName, strStrings);
				ruleNode.processName = Str2WStr(strStrings);
				strStrings = rArray[idx]["registerValuse"].GetString();
				ruleNode.registerValuse = Str2WStr(strStrings);
				ruleNode.permissions = rArray[idx]["permissions"].GetInt();
				g_vecRegRuleList.push_back(ruleNode);
			}
			catch (const std::exception&)
			{
				continue;
			}
		}
		nRet = true;
	} while (false);

	if (FileHandle)
		CloseHandle(FileHandle);
	if (data)
		delete[] data;

	if (setAllProcessName.empty())
		return false;
	for (const auto& iter : setAllProcessName)
		strProcessNameList.append(iter.c_str());
	if (strProcessNameList.empty())
		return false;
	return nRet;
}

bool FindRegisterRuleHitEx(const int opearType, const int permissions, const int Rulepermissions)
{
	try
	{
		bool nRet = false;
		// Open
		const int _open = Rulepermissions;
		// Delete
		const int _delete = Rulepermissions;
		// Create
		const int _create = Rulepermissions;
		// Modify
		const int _modify = Rulepermissions;
		// SetValuse
		const int _setvaluse = Rulepermissions;
		// Query
		const int _query = Rulepermissions;
		// ReName
		const int _rename = Rulepermissions;

		// 默认Ex解析结构是>=Win7
		if (RegNtPreCreateKey)
		{// 非Ex版本，Create如果存在则打开

		}
		else if (RegNtPreOpenKey)
		{

		}
		else if (RegNtPostCreateKey)
		{
		}
		else if (RegNtPostOpenKey)
		{
		}
		else if (RegNtPreCreateKeyEx)
		{
		}
		else if (RegNtPreOpenKeyEx)
		{
		}
		else if (RegNtPostCreateKeyEx)
		{
		}
		else if (RegNtPostOpenKeyEx)
		{
		}
		else if (RegNtSetValueKey)
		{// 修改Key
		}
		else if (RegNtPreDeleteKey)
		{// 删除Key
		}
		else if (RegNtEnumerateKey)
		{// 枚举Key
		}
		else if (RegNtRenameKey)
		{// 重命名注册表
		}
		else if (RegNtQueryValueKey)
		{// 查询
		}
		else if (RegNtKeyHandleClose)
		{// 关闭
		}
		else if (RegNtPostKeyHandleClose)
		{// 关闭
		}

		return nRet;
	}
	catch (const std::exception&)
	{
		return false;
	}
	
}
bool FindRegisterRuleHit(const REGISTERINFO* const registerinfo)
{// true 放行 - false 拦截 
	if (!registerinfo || g_vecRegRuleList.empty())
		return true;
	
	// Get ComplteName
	const std::wstring wsCompleteName = registerinfo->CompleteName;
	if (wsCompleteName.empty())
		return true;

	const std::wstring wsProcessPath = registerinfo->ProcessPath;
	if (wsProcessPath.empty())
		return true;

	// Find Rule
	std::wstring wsProcessName;
	for (const auto& rule : g_vecRegRuleList)
	{
		const int idx_ = rule.registerValuse.find(wsCompleteName.c_str());
		if (idx_ < 0)
			continue;

		wsProcessName.clear();
		GetProcessName(wsProcessPath, wsProcessName);
		if (wsProcessName.empty())
			continue;

		const int idx = rule.processName.find(wsProcessName.c_str());
		if (idx < 0)
			continue;

		const bool bOperate = FindRegisterRuleHitEx(registerinfo->opeararg, registerinfo->DesiredAccess, rule.permissions);
		// 进程名 - 注册表 - 操作匹配完成,bOperate不为真,没命中操作,未知操作放行
		if (!bOperate)
			return true;
		const int mods = rule.registerRuleMod; 
		if (1 == mods && bOperate)
			return true;
		else if (2 == mods && bOperate)
			return false;
		else // 为真但Mods不是黑白名单放行
			return true;
	}

	return true;
}