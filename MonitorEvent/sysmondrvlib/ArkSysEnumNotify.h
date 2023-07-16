#pragma once

#ifdef __cplusplus
extern "C" {
#endif

	class __declspec(dllexport) ArkSysEnumNotify
	{
	public:
		ArkSysEnumNotify();
		~ArkSysEnumNotify();

		const bool nf_GetSysNofityInfo();
	};

#ifdef __cplusplus
}
#endif

