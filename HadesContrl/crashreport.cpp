
#include <Windows.h>

#include <algorithm>
#include <cassert>
#include <cstdio>
#include <string.h>
#include <tchar.h>
#include <stdio.h>
#include <stdlib.h>

#include "crashreport.h"

#pragma optimize("", off)
void InvalidParameter(const wchar_t* expression, const wchar_t* function,
	const wchar_t* file, unsigned int line,
	uintptr_t reserved) {
		int *i = reinterpret_cast<int*>(0x45);  
		*i = 5;  
		_exit(1);
}

void PureCall() {
	int *i = reinterpret_cast<int*>(0x45);  
	*i = 5;  
	_exit(1);
}
#pragma optimize("", on)


void Crash_Report_installer::RegisterInvalidParamHandler() {
	if(pfHandlePureVirtualCall_)
		_set_purecall_handler(pfHandlePureVirtualCall_);
	else
		_set_purecall_handler(PureCall);

	if(pfHandleInvalidParameter_)
		_set_invalid_parameter_handler(pfHandleInvalidParameter_);
	else
		_set_invalid_parameter_handler(InvalidParameter);

	_CrtSetReportMode(_CRT_ASSERT, 0);
	_CrtSetReportFile(_CRT_ASSERT, _CRTDBG_FILE_STDERR);
}

void Crash_Report_installer::InstallCRTHandle()
{
	if(hBreakModule == NULL)
		hBreakModule = LoadLibraryW(L"breakpad.dll");
	if (NULL != hBreakModule)
	{
		pfHandlePureVirtualCall_ = (pfHandlePureVirtualCall)GetProcAddress(hBreakModule, "HandlePureVirtualCall");
		pfHandleInvalidParameter_ = (pfHandleInvalidParameter)GetProcAddress(hBreakModule, "HandleInvalidParameter");
	}
	RegisterInvalidParamHandler();
}

void Crash_Report_installer::InstallCrashReport()
{
	hBreakModule = LoadLibraryW(L"breakpad.dll");
	if (NULL != hBreakModule)
	{
		pfInstallReport pfInstallReport_ = (pfInstallReport)GetProcAddress(hBreakModule, "InstallCrashReport");
		if(pfInstallReport_)
			pfInstallReport_(NULL, const_cast<wchar_t*>(L"..."));
	}

	InstallCRTHandle();	
}


Crash_Report_installer::Crash_Report_installer():hBreakModule(NULL),
													pfHandlePureVirtualCall_(NULL),
													pfHandleInvalidParameter_(NULL),
													pfInstallReport_(NULL)
{
}
