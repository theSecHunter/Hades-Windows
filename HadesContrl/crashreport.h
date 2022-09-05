
#ifndef CRASH_REPORTER_INSTALL_H__
#define CRASH_REPORTER_INSTALL_H__
#pragma once

typedef BOOL  (*pfInstallReport)(wchar_t *productName, wchar_t *reportUrl);
typedef void  (*pfHandlePureVirtualCall)();
typedef void  (*pfHandleInvalidParameter)(const wchar_t* expression, const wchar_t* function, const wchar_t* file, unsigned int line, uintptr_t reserved);

class Crash_Report_installer
{
public:
	Crash_Report_installer();
	~Crash_Report_installer() {};
	void InstallCrashReport();
	void InstallCRTHandle();

	static Crash_Report_installer* GetInstance() {
		static Crash_Report_installer installer;
		return &installer;
	}
private:
	void RegisterInvalidParamHandler();


private:
	pfHandlePureVirtualCall pfHandlePureVirtualCall_;
	pfHandleInvalidParameter pfHandleInvalidParameter_;
	pfInstallReport pfInstallReport_;
	HMODULE hBreakModule;

};



#endif  // CRASH_REPORTER_INSTALL_H__
