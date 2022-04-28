#pragma once
#include "HlprIocpService.h"

class HlprSocketTcp : public IOCPHandler
{
public:
	HlprSocketTcp();
	~HlprSocketTcp();

	bool tcp_init();
	bool tcp_free();

private:

};

