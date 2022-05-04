#pragma once
typedef enum _MINI_COMMAND {
	SET_PROCESSNAME = 0,
	IPS_PROCESSSTART,
	IPS_REGISTERTAB,
	IPS_IMAGEDLL
}MIN_COMMAND;
typedef struct _MSG_DLGBUFFER {
	int options;
}MSG_DLGBUFFER, * PMSG_DLGBUFFER;
typedef struct _PROCESSINFO
{
    int parentprocessid;
    int pid;
    int endprocess;
    wchar_t processpath[260 * 2];
    wchar_t commandLine[260 * 2];
    wchar_t queryprocesspath[260 * 2];
}PROCESSINFO, * PPROCESSINFO;