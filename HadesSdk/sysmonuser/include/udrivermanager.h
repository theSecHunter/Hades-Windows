#pragma once

#ifdef __cplusplus
extern "C" {
#endif

	class __declspec(dllexport) DriverManager
	{
	public:
		DriverManager();
		~DriverManager();

		const int nf_GetServicesStatus(const wchar_t* driverName);
		const int nf_StartDrv(const wchar_t* cszDriverName, const wchar_t* cszDriverFullPath);
		const int nf_StopDrv(const wchar_t* cszDriverName, const wchar_t* cszDriverFullPath);
		const int nf_DeleteDrv(const wchar_t* cszDriverName, const wchar_t* cszDriverFullPath);

		const bool nf_DriverInstall_SysMonStart(const int mav, const int miv, const bool Is64);
		const bool nf_DriverInstall_NetMonStart(const int mav, const int miv, const bool Is64);
	};

#ifdef __cplusplus
}
#endif