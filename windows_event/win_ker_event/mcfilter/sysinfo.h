#ifndef _SYSINFO_H
#define _SYSINFO_H

typedef struct _PROCESSINFO
{
	int processid;
	int endprocess;
	wchar_t processpath[260 * 2];
	wchar_t commandLine[260 * 2];
	wchar_t queryprocesspath[260 * 2];
}PROCESSINFO, * PPROCESSINFO;

typedef struct _THREADINFO
{
	int processid;
	int threadid;
	int createid;
}THREADINFO, * PTHREADINFO;

typedef struct _IMAGEMODINFO
{
	int		processid;
	__int64 imagebase;
	__int64	imagesize;
	wchar_t	imagename[260 * 2];
}IMAGEMODINFO, * PIMAGEMODINFO;

#endif // !_SYSINFO_H
