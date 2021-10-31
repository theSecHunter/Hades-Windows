#include <Windows.h>
#include "ArkIdt.h"

#define CTL_DEVCTRL_ARK_INITIDT \
	CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1010, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define CTL_DEVCTRL_ARK_GETIDTDATA \
	CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1011, METHOD_BUFFERED, FILE_ANY_ACCESS)

ArkIdt::ArkIdt()
{
}

ArkIdt::~ArkIdt()
{

}

bool ArkIdt::nf_init()
{
	return true;
}

void ArkIdt::nf_GetIdtData()
{

}