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
		const bool nf_DriverInstall_Start(const int mav, const int miv, const bool Is64);
		const int nf_StartDrv(const wchar_t* cszDriverName, const wchar_t* cszDriverFullPath);
		const int nf_StopDrv(const wchar_t* cszDriverName, const wchar_t* cszDriverFullPath);
		const int nf_DeleteDrv(const wchar_t* cszDriverName, const wchar_t* cszDriverFullPath);
	};

#ifdef __cplusplus
}
#endif

