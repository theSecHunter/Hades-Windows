#pragma once
class uMsgInterface
{
public:
	 
	inline uMsgInterface() { this->uMsg_Init(); }
	inline ~uMsgInterface() { this->uMsg_Free(); }

	void uMsg_taskPopEtwLoop();
	void uMsg_taskPopInit();
	void uMsg_taskPush(const int taskcode, std::vector<std::string>& vec_task_string);

	void uMsg_SetSubEventPtr(HANDLE& eventptr);
	void uMsg_SetSubQueueLockPtr(std::mutex& qptrcs);
	void uMsg_SetSubQueuePtr(std::queue<std::shared_ptr<UEtwSub>>& qptr);

private:
	void uMsg_Init();
	void uMsg_Free();
	void uMsg_SetTopicQueuePtr();
	void uMsg_SetTopicQueueLockPtr();
	void uMsg_SetTopicEventPtr();
	void uMsgEtwDataHandlerEx();

	std::vector<HANDLE> m_topicthread;
};

