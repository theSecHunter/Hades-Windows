#ifndef _CALLOUTS_H
#define _CALLOUTS_H

NTSTATUS callout_init(PDEVICE_OBJECT deviceObject);
VOID callout_free();

#endif