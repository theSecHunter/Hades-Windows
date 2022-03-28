#include "public.h"
#include "sysmousekeyboard.h"

/*
	@ KeyBoard:
		\\Driver\\Kbdclass
		\\Driver\\i8042ptr
		 - ACPI
	@ mouse
		\\Driver\\Mouclass
*/
PDRIVER_OBJECT  g_kbddriverObject;
PDRIVER_OBJECT  g_i8042driverObject;
PDRIVER_OBJECT  g_moudriverObject;
static NTSTATUS ob1 = STATUS_UNSUCCESSFUL, ob2 = STATUS_UNSUCCESSFUL, ob3 = STATUS_UNSUCCESSFUL;

int nf_mousKeyboardInit()
{
	UNICODE_STRING kbdysName;
	UNICODE_STRING i8042sysName;
	UNICODE_STRING mousysName;

	RtlInitUnicodeString(&kbdysName, L"\\Driver\\Kbdclass");
	RtlInitUnicodeString(&i8042sysName, L"\\Driver\\i8042ptr");
	RtlInitUnicodeString(&mousysName, L"\\Driver\\Mouclass");

	ob1 = ObReferenceObjectByName(
		&kbdysName,
		OBJ_CASE_INSENSITIVE,
		NULL,
		FILE_ALL_ACCESS,
		*IoDriverObjectType,
		KernelMode,
		NULL,
		(PVOID*)&g_kbddriverObject
	);

	ob2 = ObReferenceObjectByName(
		&i8042sysName,
		OBJ_CASE_INSENSITIVE,
		NULL,
		FILE_ALL_ACCESS,
		*IoDriverObjectType,
		KernelMode,
		NULL,
		(PVOID*)&g_i8042driverObject
	);

	ob3 = ObReferenceObjectByName(
		&mousysName,
		OBJ_CASE_INSENSITIVE,
		NULL,
		FILE_ALL_ACCESS,
		*IoDriverObjectType,
		KernelMode,
		NULL,
		(PVOID*)&g_moudriverObject
	);

	if (NT_SUCCESS(ob1) || !NT_SUCCESS(ob2) && NT_SUCCESS(ob3))
		return 1;

	return -1;
}

int nf_GetmousKeyboardInfoData(ULONGLONG * pBuffer)
{
	if (!NT_SUCCESS(ob1) && !NT_SUCCESS(ob2) && !NT_SUCCESS(ob3))
		return -1;

	int i = 0, index = 0;
	if (g_moudriverObject)
	{
		for (i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; ++i)
		{
			pBuffer[index] = g_moudriverObject->MajorFunction[i];
			index++;
		}
	}

	if (g_i8042driverObject)
	{
		for (i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; ++i)
		{
			pBuffer[index] = g_i8042driverObject->MajorFunction[i];
			index++;
		}
	}
	else
	{

		for (i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; ++i)
		{
			pBuffer[index] = (ULONGLONG)0;
			index++;
		}
	}

	if (g_kbddriverObject)
	{
		for (i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; ++i)
		{
			pBuffer[index] = g_kbddriverObject->MajorFunction[i];
			index++;
		}
	}

	return 1;

}

int nf_mouskeyboardfree()
{
	if (!NT_SUCCESS(ob1) && !NT_SUCCESS(ob2) && !NT_SUCCESS(ob3))
		return -1;

	if (g_moudriverObject)
	{
		ObDereferenceObject(g_moudriverObject);
		g_moudriverObject = NULL;
	}

	if (g_i8042driverObject)
	{
		ObDereferenceObject(g_i8042driverObject);
		g_i8042driverObject = NULL;
	}

	if (g_kbddriverObject)
	{
		ObDereferenceObject(g_kbddriverObject);
		g_kbddriverObject = NULL;
	}

	return 1;
}