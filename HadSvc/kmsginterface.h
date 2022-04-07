#pragma once

class kMsgInterface
{
public:
	inline
		kMsgInterface() { this->kMsg_Init(); }
	inline
		~kMsgInterface() { this->kMsg_Free(); }

	void kMsg_SetSubQueuePtr(std::queue<std::shared_ptr<USubNode>>& qptr);
	void kMsg_SetSubQueueLockPtr(std::mutex& qptrcs);
	void kMsg_SetSubEventPtr(HANDLE& eventptr);
	void kMsg_taskPush(const int taskcode, std::vector<std::string>& vec_task_string);
	void kMsg_taskPopNotifyRoutineLoop();
	void kMsgNotifyRouteDataHandlerEx();

private:
	void kMsg_Init();
	void kMsg_Free();

	void kMsg_SetTopicQueuePtr();
	void kMsg_SetTopicQueueLockPtr();
	void kMsg_SetTopicEventPtr();
	void kMsg_taskPopInit();
	

	std::vector<HANDLE> m_topicthread;
};

