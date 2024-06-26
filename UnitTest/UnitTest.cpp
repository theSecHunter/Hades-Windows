#include <Windows.h>

#ifdef _X64
#include "UntsNetwork.h"
#endif

static bool bUnitExit = false;

DWORD WINAPI UnitTsNetWorkThread(LPVOID lpThreadParameter)
{
	try
	{
#ifdef _X64
		// [test] Networklib NetDriven
		UntsNetwork UntsNetworkOb;
		UntsNetworkOb.UnTs_NetworkInit();
#endif
		while (1) {
			if (bUnitExit)
				break;
			Sleep(1000);
		}
		return 0;
	}
	catch (...)
	{
		return 0;
	}
}

int main()
{
	QueueUserWorkItem(UnitTsNetWorkThread, nullptr, WT_EXECUTEDEFAULT);
	system("pause");
	bUnitExit = true;
	Sleep(2000);
	return 0;
}