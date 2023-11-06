#ifndef _KFTL_H
#define _KFTL_H

NTSTATUS Fsflt_initPort();
NTSTATUS Fsflt_SendMsg(PVOID SenderBuffer, ULONG SenderBufferLength, PVOID ReplyBuffer, PULONG ReplyLength);
NTSTATUS Fsflt_SendToMsg(PVOID SenderBuffer, ULONG SenderBufferLength, PVOID ReplyBuffer, PULONG ReplyLength);
void Fsflt_ClosePort();
void Fsflt_freePort();

#endif // !_KFTL_H
