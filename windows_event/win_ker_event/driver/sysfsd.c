#include "public.h"
#include "sysfsd.h"

extern POBJECT_TYPE* IoDriverObjectType;

NTSTATUS
ObReferenceObjectByName(
	__in PUNICODE_STRING ObjectName,
	__in ULONG Attributes,
	__in_opt PACCESS_STATE AccessState,
	__in_opt ACCESS_MASK DesiredAccess,
	__in POBJECT_TYPE ObjectType,
	__in KPROCESSOR_MODE AccessMode,
	__inout_opt PVOID ParseContext,
	__out PVOID* Object
);

static PDRIVER_OBJECT  g_fatdriverObject = NULL;
static PDRIVER_OBJECT  g_ntfsdriverObject = NULL;

int nf_fsdinit()
{
	static UNICODE_STRING fatsysName;
	static UNICODE_STRING ntfssysName;

	RtlInitUnicodeString(&fatsysName, L"\\FileSystem\\FastFat");
	RtlInitUnicodeString(&ntfssysName, L"\\FileSystem\\Ntfs");

	ObReferenceObjectByName(
		&fatsysName, 
		OBJ_CASE_INSENSITIVE,
		NULL,
		FILE_ALL_ACCESS,
		*IoDriverObjectType,
		KernelMode,
		NULL,
		g_fatdriverObject
		);

	ObReferenceObjectByName(
		&ntfssysName,
		OBJ_CASE_INSENSITIVE,
		NULL,
		FILE_ALL_ACCESS,
		*IoDriverObjectType,
		KernelMode,
		NULL,
		g_ntfsdriverObject
	);

	if (g_fatdriverObject == NULL || g_ntfsdriverObject == NULL)
		return -1;

	return 1;
}

int nf_GetfsdData(ULONGLONG* pBuffer)
{
	if (g_fatdriverObject == NULL || g_ntfsdriverObject == NULL)
		return -1;

	int i = 0;
	int index = 0;

	for (i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; ++i)
	{
		pBuffer[index] = g_fatdriverObject->MajorFunction[i];
		index++;
	}


	for (i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; ++i)
	{
		pBuffer[index] = g_ntfsdriverObject->MajorFunction[i];
		index++;
	}

	return 1;
}

int nf_fsdfree()
{
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

}