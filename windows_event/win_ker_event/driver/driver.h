#ifndef _DRIVER_H
#define _DRIVER_H

typedef enum _MINI_COMMAND {
	SET_PROCESSNAME = 0,
}MIN_COMMAND;

typedef struct _COMAND_MESSAGE
{
	MIN_COMMAND Command;
	unsigned int processnamelen;
} COMMAND_MESSAGE, * PCOMMAND_MESSAGE;

extern unsigned short*	g_processname;
extern unsigned int		g_processnamelen;

NTSTATUS driver_free();

#endif // !MY_DRIVER_H

