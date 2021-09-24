#pragma once
#include <Windows.h>

typedef enum _MINI_COMMAND {
	SET_PROCESSNAME = 0,
}MIN_COMMAND;

typedef struct _COMAND_MESSAGE
{
	MIN_COMMAND Command;
	unsigned int processnamelen;
} COMMAND_MESSAGE, * PCOMMAND_MESSAGE;

bool nf_SetRuleProcess(PVOID64 rulebuffer, unsigned int buflen, unsigned int processnamelen);