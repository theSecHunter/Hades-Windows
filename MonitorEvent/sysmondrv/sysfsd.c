#include "public.h"
#include "sysfsd.h"

PDRIVER_OBJECT  g_fatdriverObject;
PDRIVER_OBJECT  g_ntfsdriverObject;
static NTSTATUS ob1 = STATUS_UNSUCCESSFUL, ob2 = STATUS_UNSUCCESSFUL;

int nf_fsdinit()
{
	UNICODE_STRING fatsysName;
	UNICODE_STRING ntfssysName;

	RtlInitUnicodeString(&fatsysName, L"\\FileSystem\\FastFat");
	RtlInitUnicodeString(&ntfssysName, L"\\FileSystem\\Ntfs");

	ob1 = ObReferenceObjectByName(
		&fatsysName,
		OBJ_CASE_INSENSITIVE,
		NULL,
		FILE_ALL_ACCESS,
		*IoDriverObjectType,
		KernelMode,
		NULL,
		(PVOID*)&g_fatdriverObject
	);

	ob2 = ObReferenceObjectByName(
		&ntfssysName,
		OBJ_CASE_INSENSITIVE,
		NULL,
		FILE_ALL_ACCESS,
		*IoDriverObjectType,
		KernelMode,
		NULL,
		(PVOID*)&g_ntfsdriverObject
	);

	if (!NT_SUCCESS(ob1) || !NT_SUCCESS(ob2))
		return -1;

	return 1;
}

int nf_GetfsdData(ULONGLONG* pBuffer)
{
	if (!NT_SUCCESS(ob1) || !NT_SUCCESS(ob2))
		return -1;

	int i = 0, index = 0;

	if (g_fatdriverObject)
	{
		for (i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; ++i)
		{
			pBuffer[index] = g_fatdriverObject->MajorFunction[i];
			index++;
		}
	}

	if (g_ntfsdriverObject)
	{
		for (i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; ++i)
		{
			pBuffer[index] = g_ntfsdriverObject->MajorFunction[i];
			index++;
		}
	}

	return 1;
}

int nf_fsdfree()
{
	if (!NT_SUCCESS(ob1) || !NT_SUCCESS(ob2))
		return -1;

	if (g_fatdriverObject)
	{
		ObDereferenceObject(g_fatdriverObject);
		g_fatdriverObject = NULL;
	}

	if (g_ntfsdriverObject)
	{
		ObDereferenceObject(g_ntfsdriverObject);
		g_ntfsdriverObject = NULL;
	}

	return 1;
}