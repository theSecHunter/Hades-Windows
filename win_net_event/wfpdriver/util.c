#include "public.h"
#include "util.h"
#include "ntdefines.h"

BOOLEAN QueryProcessNamePath(__in DWORD pid, __out PWCHAR path, __in DWORD pathlen)
{
	BOOLEAN bRet = FALSE;
	CLIENT_ID cid;
	OBJECT_ATTRIBUTES obj;
	HANDLE hProc = NULL;
	NTSTATUS status;

	InitializeObjectAttributes(&obj, NULL, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
	cid.UniqueProcess = (HANDLE)pid;
	cid.UniqueThread = NULL;
	status = ZwOpenProcess(&hProc, GENERIC_ALL, &obj, &cid);
	if (NT_SUCCESS(status))
	{
		DWORD dw;
		WCHAR ProcessPath[MAX_PROCESS_PATH_LEN + sizeof(UNICODE_STRING)] = { 0 };
		status = ZwQueryInformationProcess(hProc, ProcessImageFileName, ProcessPath, sizeof(ProcessPath), &dw);
		if (NT_SUCCESS(status))
		{
			PUNICODE_STRING dststring = (PUNICODE_STRING)ProcessPath;
			// 7/29 可能会遇到length为空，导致拷贝蓝屏 - 已修复
			if ((pathlen > (DWORD)dststring->Length + sizeof(WCHAR)) && dststring->Length)
			{
				RtlMoveMemory(path, dststring->Buffer, dststring->Length + sizeof(WCHAR));
				bRet = TRUE;
			}
		}
		ZwClose(hProc);
	}
	return bRet;
}
