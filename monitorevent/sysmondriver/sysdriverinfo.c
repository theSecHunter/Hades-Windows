#include "public.h"
#include "sysdriverinfo.h"

int nf_EnumSysDriver(PDEVICE_OBJECT pDevObj, PPROCESS_MOD ModBffer)
{
	PDRIVER_OBJECT pDriverobj =  pDevObj->DriverObject;
	if (!pDriverobj)
		return -1;
	PLDR_DATA_TABLE_ENTRY pLdrTblEntry = (PLDR_DATA_TABLE_ENTRY)pDriverobj->DriverSection;
	PLIST_ENTRY pListHdr = &pLdrTblEntry->InLoadOrderLinks;
	PLIST_ENTRY pListEntry = NULL;
	ULONG index = 0;
	pListEntry = pListHdr;

	while (pListEntry->Flink != pListHdr)
	{
		pLdrTblEntry = CONTAINING_RECORD(pListEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
		memcpy(ModBffer[index].BaseDllName, pLdrTblEntry->BaseDllName.Buffer, pLdrTblEntry->BaseDllName.Length);
		memcpy(ModBffer[index].FullDllName, pLdrTblEntry->FullDllName.Buffer, pLdrTblEntry->FullDllName.Length);
		ModBffer[index].DllBase = pLdrTblEntry->DllBase;
		ModBffer[index].EntryPoint = pLdrTblEntry->EntryPoint;
		ModBffer[index].SizeOfImage = pLdrTblEntry->SizeOfImage;
		index++;
		pListEntry = pListEntry->Flink;

		// ·ÀÖ¹ËÀÑ­»·
		if (index > 2000)
			break;
	}

	return 1;
}

int nf_StopDriver()
{

}

int nf_UnDriver()
{

}

int nf_DumpDriverMemory()
{

}