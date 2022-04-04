#pragma once
class uMsgInterface
{
public:
	inline 
		uMsgInterface() {}
	inline
		~uMsgInterface() {}

	void uMsg_ReadtaskPop(int& taskcode, std::string& data);
	void uMsg_taskPush(const int taskcode, std::vector<std::string>& vec_task_string);
};

