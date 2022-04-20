#pragma once

class DriverManager
{
public:
	DriverManager();
	~DriverManager();

	int nf_GetServicesStatus(const wchar_t* driverName);
	bool nf_DriverInstall(const int mav, const int miv, const bool Is64);
	int nf_StartDrv(const wchar_t* cszDriverName, const wchar_t* cszDriverFullPath);
	int nf_StopDrv(const wchar_t* cszDriverName, const wchar_t* cszDriverFullPath);
	int nf_DeleteDrv(const wchar_t* cszDriverName, const wchar_t* cszDriverFullPath);
};

