#pragma once
class uMsgInterface
{
public:
	 
	inline uMsgInterface() { this->uMsg_Init(); }
	inline ~uMsgInterface() { this->uMsg_Free(); }

	void uMsg_taskPopEtwLoop();
	void uMsg_taskPopInit();
	void uMsg_taskPush(const int taskcode, std::vector<std::string>& vec_task_string);

private:
	void uMsg_Init();
	void uMsg_Free();
	void uMsg_SetQueuePtr();
	void uMsg_SetQueueLockPtr();
	void uMsg_SetEventPtr();
	void uMsgEtwDataHandlerEx();
	
	std::vector<HANDLE> m_thread;
};

