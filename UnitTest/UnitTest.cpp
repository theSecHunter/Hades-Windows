#ifdef _X64
#include "UntsNetwork.h"
#endif

int main()
{

#ifdef _X64
	// [test] Networklib NetDriven
	UntsNetwork UntsNetworkOb;
	UntsNetworkOb.UnTs_NetworkInit();
#endif

}