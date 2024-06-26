#pragma once
#include <string>

class UntsSvc
{
public:
	UntsSvc();
	~UntsSvc();

	const bool UnTs_NetCheckStatus(const std::wstring sDriverName);
};

