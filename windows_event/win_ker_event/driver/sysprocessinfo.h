/*
	三种枚举方式 - 可以数据都统一采集
		1. 基于内核api(本质和2一样)
		2. 基于进程链表
		3. 基于句柄表
		4. 基于内存枚举
*/
#ifndef _SYSPROCESSINFO_H
#define _SYSPROCESSINFP_H


int nf_KillProcess(PEPROCESS Process);
int nf_DumpProcess();

int nf_GetSysProcess_SearchMemory();
int nf_GetSysProcess_Api();
int nf_GetSysProcess_List();
int nf_GetSysProcess_CidHandle();
int nf_GetSysProcess_Module();

#endif