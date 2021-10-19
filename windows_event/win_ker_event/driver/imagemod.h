#ifndef _IMAGEMOD_H
#define _IMAGEMOD_H

typedef struct _IMAGEMODINFO
{
	int		processid;
	__int64 imagebase;
	__int64	imagesize;
	int		systemmodeimage;
	wchar_t	imagename[260 * 2];
}IMAGEMODINFO, * PIMAGEMODINFO;

typedef struct _IMAGEMODBUFFER
{
	LIST_ENTRY			pEntry;
	ULONG				dataLength;
	char*				dataBuffer;
}IMAGEMODBUFFER, * PIMAGEMODBUFFER;

typedef struct _IMAGEMODDATA
{
	KSPIN_LOCK	imagemod_lock;
	LIST_ENTRY imagemod_pending;
}IMAGEMODDATA,* PIMAGEMODDATA;

NTSTATUS Imagemod_Init(void);
void Imagemod_Free(void);
void Imagemod_Clean(void);
void Imagemod_SetMonitor(BOOLEAN code);

IMAGEMODBUFFER* Imagemod_PacketAllocate(int lens);
void Imagemod_PacketFree(IMAGEMODBUFFER* packet);

IMAGEMODDATA* imagemodctx_get();

#endif

