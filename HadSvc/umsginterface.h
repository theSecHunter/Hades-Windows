#pragma once
#include <sysinfo.h>
#include <queue>
#include <memory>
#include <vector>
#include <iostream>
#include <string>
#include <mutex>

class uMsgInterface
{
public:
	 
	uMsgInterface(); 
	~uMsgInterface();
	void uMsg_taskPopEtwLoop();
	void uMsg_taskPopInit();
	void uMsg_taskPush(const int taskcode, std::vector<std::string>& vec_task_string);

	void uMsg_SetSubEventPtr(HANDLE& eventptr);
	void uMsg_SetSubQueueLockPtr(std::mutex& qptrcs);
	void uMsg_SetSubQueuePtr(std::queue<std::shared_ptr<USubNode>>& qptr);

	void uMsg_Init();
	void uMsg_Free();
	void uMsg_EtwInit();
	void uMsg_EtwClose();

private:
	void uMsg_SetTopicQueuePtr();
	void uMsg_SetTopicQueueLockPtr();
	void uMsg_SetTopicEventPtr();
	void uMsgEtwDataHandlerEx();

	std::vector<HANDLE> m_topicthread;
};
