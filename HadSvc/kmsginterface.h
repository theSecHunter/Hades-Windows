#pragma once
#include <sysinfo.h>
#include <queue>
#include <memory>
#include <vector>
#include <iostream>
#include <string>
#include <mutex>

class kMsgInterface
{
public:
	kMsgInterface();
	~kMsgInterface();

	void kMsg_SetSubQueuePtr(std::queue<std::shared_ptr<USubNode>>& qptr);
	void kMsg_SetSubQueueLockPtr(std::mutex& qptrcs);
	void kMsg_SetSubEventPtr(HANDLE& eventptr);
	void kMsg_taskPush(const int taskcode, std::vector<std::string>& vec_task_string);
	void kMsg_taskPopNotifyRoutineLoop();
	void kMsgNotifyRouteDataHandlerEx();

	void kMsg_Init();
	void kMsg_Free();
	void DriverInit(const int flag);
	void DriverFree();
	void StopReadFileThread();
	void StartReadFileThread();
	void OnMonitor();
	void OffMonitor();
	void OnBeSnipingMonitor();
	void OffBeSnipingMonitor();
	bool GetKerMonStatus();
	bool GetKerInitStatus();
	bool GetKerBeSnipingStatus();
	bool ReLoadProcessRuleConfig();
	bool ReLoadRegisterRuleConfig();
	bool ReLoadDirectoryRuleConfig();
	bool ReLoadThreadInjectRuleConfig();

private:
	void kMsg_SetTopicQueuePtr();
	void kMsg_SetTopicQueueLockPtr();
	void kMsg_SetTopicEventPtr();
	void kMsg_taskPopInit();
	

	std::vector<HANDLE> m_topicthread;
	bool kerMonStatus = false;
	bool kInitStatus = false;
	bool kBesnipingStatus = false;
};