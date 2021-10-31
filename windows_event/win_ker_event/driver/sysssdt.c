#include "public.h"
#include "sysssdt.h"

ULONGLONG HelpSsdtBaseAddr64(PUCHAR StartSearchAddress)
{
	PUCHAR EndSearchAddress = StartSearchAddress + 0x500;
	PUCHAR i = NULL;
	ULONG templong = 0;
	ULONGLONG addr = 0;
	for (i = StartSearchAddress; i < EndSearchAddress; i++)
	{
		if (MmIsAddressValid(i) && MmIsAddressValid(i + 1) && MmIsAddressValid(i + 2))
		{
			//4c8d15
			if ((*i == 0x4c) &&
				(*(i + 1) == 0x8d) &&
				(*(i + 2) == 0x15)) 
			{
				memcpy(&templong, i + 3, 4);
				addr = (ULONGLONG)templong + (ULONGLONG)i + 7;
				return addr;
			}
		}
	}
	return 0;
}

ULONGLONG SysGetSsdtBaseAddrto64()
{
	PUCHAR StartSearchAddress = (PUCHAR)__readmsr(0xC0000082);

	if (0x00 == *(StartSearchAddress + 0x9))
	{
		return HelpSsdtBaseAddr64(StartSearchAddress);
	}
	// KiSystemCall64Shadow
	else if(0x70 == *(StartSearchAddress + 0x9))
	{
		PUCHAR EndSearchAddress = StartSearchAddress + 0x500;
		PUCHAR i = NULL;
		INT temp = 0;
		for (i = StartSearchAddress; i < EndSearchAddress; i++)
		{
			//e9e35ce9ff	jmp     nt!KiSystemServiceUser
			//c3            ret
			if (MmIsAddressValid(i) && MmIsAddressValid(i + 5))
			{
				if ((*i == 0xe9) &&
					(*(i + 5) == 0xc3)
					)
				{
					memcpy(&temp, i + 1, 4);
					PUCHAR pKiSystemServiceUser = temp + (i + 5);
					return HelpSsdtBaseAddr64(pKiSystemServiceUser);
				}
			}
		}
	}
	return 0;
}

int Sstd_Init()
{
	KeServiceDescriptorTable = (PSYSTEM_SERVICE_TABLE)SysGetSsdtBaseAddrto64();
	if (KeServiceDescriptorTable)
		return 1;
	else
		return 0;
}

int Sstd_GetTableInfo(SSDTINFO* MemBuffer)
{
	if (!KeServiceDescriptorTable)
		return -1;

	ULONGLONG SsdtFunNumber = KeServiceDescriptorTable->NumberOfServices;
	if (0 >= SsdtFunNumber)
		return -1;

	PULONG ServiceTableBase = NULL;
	ServiceTableBase = (PULONG)KeServiceDescriptorTable->ServiceTableBase;
	if (0 >= ServiceTableBase)
		return -1;

	int  i = 0;
	LONG offset = 0;
	ULONGLONG funaddr = 0;
	PSSDTINFO ssdtinfo = ExAllocatePoolWithTag(NonPagedPool, sizeof(SSDTINFO), 'STMM');
	if (!ssdtinfo)
		return -1;
	RtlSecureZeroMemory(ssdtinfo, sizeof(SSDTINFO));
	for (i = 0; i < SsdtFunNumber; ++i)
	{
		ssdtinfo->ssdt_id = i;

		offset = ServiceTableBase[i];
		ssdtinfo->sstd_memoffset = offset;

		if (offset & 0x80000000)
			offset = (offset >> 4) | 0xF0000000;
		else
			offset = offset >> 4;
		funaddr = (ULONGLONG)ServiceTableBase + (ULONGLONG)offset;

		ssdtinfo->sstd_memaddr = funaddr;

		RtlCopyMemory(&MemBuffer[i], ssdtinfo, sizeof(SSDTINFO));
	}

	return 1;
}