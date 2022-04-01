#pragma once

class kMsgInterface
{
public:
	inline
		kMsgInterface() {}
	inline
		~kMsgInterface() {}


	void kMsg_taskPush(const int taskcode, std::vector<std::string>& vec_task_string);
};

