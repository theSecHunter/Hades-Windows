#include "pch.h"
#include <sysinfo.h>
#include "RegisterRuleAssist.h"
#include "utiltools.h"
#include <map>
#include <mutex>

const static std::string g_RegConfigName = "registerRuleConfig.json";
typedef struct _RegRuleNode
{
	int						registerRuleMod;
	int						permissions;
	std::wstring			processName;
	std::wstring			registerValuse;
}RegRuleNode, * PRegRuleNode;
static std::vector<RegRuleNode> g_vecRegRuleList;

static std::mutex							g_objmaplock;
static std::map<const PVOID, std::wstring>	g_objRegPathMap;

void GetProcessName(const std::wstring& ProcessPath, std::wstring& ProcessPathName)
{
	// Get ProcessName
	if (ProcessPath.empty())
		return;
	const std::wstring wsProcPath = ProcessPath;
	const size_t iLast = wsProcPath.find_last_of(L"\\");
	if (iLast < 0)
		return;
	ProcessPathName = wsProcPath.substr(iLast + 1);
}

inline void InsertRuleMapObjToPathHplr(const PVOID object, const std::wstring& RegisterPath)
{
	g_objmaplock.lock();
	g_objRegPathMap[object] = RegisterPath;
	g_objmaplock.unlock();
}
inline void DeleteRuleMapObjtoPathHplr(const PVOID object)
{
	g_objmaplock.lock();
	const auto iters = g_objRegPathMap.find(object);
	if (iters != g_objRegPathMap.end())
		g_objRegPathMap.erase(iters);
	g_objmaplock.unlock();
}
inline void FindObjectRegisterPath(const PVOID object, std::wstring& RegisterPath)
{
	g_objmaplock.lock();
	const auto iters = g_objRegPathMap.find(object);
	if (iters != g_objRegPathMap.end())
		RegisterPath = iters->second;
	g_objmaplock.unlock();
}

bool ConfigRegisterJsonRuleParsing(std::string& strProcessNameList)
{
	if (!RuleEngineToos::IsFile(g_RegConfigName))
		return false;
	std::string strRet;
	if (!RuleEngineToos::GetCurrentExePath(strRet))
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
		g_vecRegRuleList.clear();
		RegRuleNode ruleNode;
		const auto rArray = document.GetArray();
		std::string strstrHex;
		for (rapidjson::SizeType idx = 0 ;  idx < rArray.Size(); ++idx)
		{
			try
			{
				if (!rArray[idx].HasMember("registerRuleMod") || !rArray[idx].HasMember("processName") || !rArray[idx].HasMember("registerValuse") || !rArray[idx].HasMember("permissions"))
					continue;
				ruleNode.registerRuleMod = rArray[idx]["registerRuleMod"].GetInt();
				strStrings = rArray[idx]["processName"].GetString();
				RuleEngineToos::SplitiStr(setAllProcessName, strStrings);
				ruleNode.processName = RuleEngineToos::Str2WStr(strStrings);
				strStrings = rArray[idx]["registerValuse"].GetString();
				ruleNode.registerValuse = RuleEngineToos::Str2WStr(strStrings);
				// string --> hex
				strstrHex = rArray[idx]["permissions"].GetString();
				ruleNode.permissions = strtoll(strstrHex.c_str(), NULL, 16);
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

bool FindRegisterRuleHitEx(const int opearType, const int permissions, const int Rulepermissions, const ULONG status, const PVOID object, const std::wstring& registerPath)
{
	try
	{
		bool nRet = false;

		// 解析规则权限
		// Open
		const int _open = Rulepermissions & 0x1000000;
		// Close
		const int _close = Rulepermissions & 0x0100000;
		// Delete
		const int _delete = Rulepermissions & 0x0010000;
		// Create
		const int _create = Rulepermissions & 0x0001000;
		// SetValuse
		const int _setvaluse = Rulepermissions & 0x0000100;
		// Query
		const int _query = Rulepermissions & 0x0000010;
		// ReName
		const int _rename = Rulepermissions & 0x0000001;

		// 根据opearType 对权限做出解释
		switch (opearType)
		{
			case RegNtPreCreateKey:
			{// CreateKey - 创建 打开 
				if (_create || _open)
					nRet = true;
			}
			break;
			case RegNtPreOpenKey:
			{
				if (_open)
					nRet = true;
			}
			break;
			case RegNtPostOpenKey:
			case RegNtPostCreateKey:
			case RegNtPostOpenKeyEx:
			case RegNtPostCreateKeyEx:
			{// 后操作默认true
				if (0 == status)
				{
					InsertRuleMapObjToPathHplr(object, registerPath);
					nRet = true;
					const std::wstring output = L"[HadesSvc] InsertRuleMapObjToPathHplr: " + to_wstring((ULONG64)object) + L" " + registerPath;
					OutputDebugString(output.c_str());
				}
			}
			break;
			case RegNtPreOpenKeyEx:
			case RegNtPreCreateKeyEx:
			{
				if (!_open)
					break;
				if ((permissions == KEY_QUERY_VALUE) && _query)
					nRet = true;
				else if ((permissions == KEY_ENUMERATE_SUB_KEYS) || (permissions == KEY_READ))
					nRet = true;
				else if (((permissions == KEY_CREATE_SUB_KEY) || (permissions == KEY_CREATE_LINK)) && _create)
					nRet = true;
				else if (((permissions == KEY_SET_VALUE) || (permissions == KEY_WRITE)) && _setvaluse)
					nRet = true;
				else if ((permissions == KEY_ALL_ACCESS) && _setvaluse && _create && _delete && _query && _rename && _close)
					nRet = true;
				wchar_t Output[250] = { 0, };
				wsprintf(Output, L"[HadesSvc] RegNtPreOpenKeyEx|RegNtPreCreateKeyEx Permissions: 0x%x query: %d create: %d setvlu: %d delete %d close %d rename %d", permissions, _query, _create, _setvaluse, _delete, _close, _rename);
				OutputDebugString(Output);
			}
			break;
			case RegNtPreSetValueKey:
			{// 修改Key
				if (_setvaluse)
					nRet = true;
				OutputDebugString((L"[HadesSvc] RegNtSetValueKey Object :" + to_wstring((ULONG64)object)).c_str());
			}
			break;
			case RegNtPreDeleteKey:
			{// 删除Key
				if (_delete)
					nRet = true;
			}
			break;
			case RegNtEnumerateKey:
			case RegNtQueryValueKey:
			{// 枚举- 查询
				if (_query)
					nRet = true;
			}
			break;
			case RegNtRenameKey:
			{// 重命名注册表
				if (_rename)
					nRet = true;
			}
			break;
			case RegNtKeyHandleClose:
			{// 关闭
				if (_close)
				{
					DeleteRuleMapObjtoPathHplr(object);
					nRet = true;
					OutputDebugString((L"[HadesSvc] DeleteRuleMapObjtoPathHplr Object: " + to_wstring((ULONG64)object)).c_str());
				}
			}
			break;
			case RegNtPostKeyHandleClose:
			{// 关闭完成后
				if (0 == status)
				{

				}
			}
			break;
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
	std::wstring wsCompleteName = registerinfo->CompleteName;
	if (wsCompleteName.empty() || (RegNtPreSetValueKey == registerinfo->opeararg))
	{// Find Table
		//if (RegNtPreSetValueKey == registerinfo->opeararg)
		//{// RegNtPreSetValueKey的时候CompleteName是键值 - 有需要先保存
		//	OutputDebugString((L"[HadesSvc] RegNtSetValueKey Object: " + wsCompleteName + to_wstring((ULONG64)registerinfo->Object)).c_str());
		//}
		if (registerinfo->Object)
			FindObjectRegisterPath(registerinfo->Object, wsCompleteName);
		if (wsCompleteName.empty())
			return true;
	}
	// Register Min Lens
	else if (wsCompleteName.size() <= 25)
		return true;

	// Get ProcessFullPath
	const std::wstring wsProcessPath = registerinfo->ProcessPath;
	if (wsProcessPath.empty())
		return true;

	// Find Rule
	std::wstring wsProcessName;
	for (const auto& rule : g_vecRegRuleList)
	{
		const size_t idx = rule.registerValuse.find(wsCompleteName.c_str());
		if (idx < 0)
			continue;

		wsProcessName.clear();
		GetProcessName(wsProcessPath, wsProcessName);
		if (wsProcessName.empty())
			continue;
		
		const size_t idx_ = rule.processName.find(wsProcessName.c_str());
		if (idx_ < 0)
			continue;

		// bOperate规则权限判定
		const bool bOperate = FindRegisterRuleHitEx(registerinfo->opeararg, registerinfo->DesiredAccess, rule.permissions, registerinfo->Status, registerinfo->Object, wsCompleteName);
		const int mods = rule.registerRuleMod; 
		bool nRet = true;
		// 白名单权限符合放行反之
		if (1 == mods)
			bOperate ? nRet = true : nRet = false;
		// 黑名单权限符合拦截反之
		else if (2 == mods)
			bOperate ? nRet = false : nRet = true;
		else
			nRet = true; // 未知情况一律放行
		return nRet;
	}
	return true;
}