#ifndef _KFTL_H
#define _KFTL_H

NTSTATUS kflt_initPort();
NTSTATUS kflt_SendMsg(PVOID SenderBuffer, ULONG SenderBufferLength, PVOID ReplyBuffer, PULONG ReplyLength);
NTSTATUS kflt_SendToMsg(PVOID SenderBuffer, ULONG SenderBufferLength, PVOID ReplyBuffer, PULONG ReplyLength);
void kflt_ClosePort();
void kflt_freePort();

#endif // !_KFTL_H
