#ifndef _KFTL_H
#define _KFTL_H

NTSTATUS FsFltPortInitialize();
NTSTATUS FsFltPortSendMessage(PVOID SendBuffer, ULONG SendBufferLength, PVOID ReplyBuffer, PULONG ReplyLength);
NTSTATUS FsFltPortSendMessageTo(PVOID SendBuffer, ULONG SendBufferLength, PVOID ReplyBuffer, PULONG ReplyLength);
VOID FsFltPortClose();
VOID FsFltPortDelete();

#endif // !_KFTL_H
