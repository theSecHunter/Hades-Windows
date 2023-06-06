#pragma once

#include <string>

class FileDetailReader
{
public:
	static bool QueryValue(const std::string& ValueName, const std::string& szModuleName, std::string& RetStr);
	static bool GetFileDescription(const std::string& szModuleName, std::string& RetStr);	//获取文件说明
	static bool GetFileVersion(const std::string& szModuleName, std::string& RetStr);		//获取文件版本	
	static bool GetInternalName(const std::string& szModuleName, std::string& RetStr);		//获取内部名称
	static bool GetCompanyName(const std::string& szModuleName, std::string& RetStr);		//获取公司名称
	static bool GetLegalCopyright(const std::string& szModuleName, std::string& RetStr);	//获取版权
	static bool GetOriginalFilename(const std::string& szModuleName, std::string& RetStr);	//获取原始文件名
	static bool GetProductName(const std::string& szModuleName, std::string& RetStr);		//获取产品名称
	static bool GetProductVersion(const std::string& szModuleName, std::string& RetStr);	//获取产品版本
	static bool GetOEM(const std::string& szModuleName, std::string& RetStr);
};