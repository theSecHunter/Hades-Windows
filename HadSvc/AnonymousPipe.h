#pragma once
#include <functional>

class AnonymousPipe
{
public:
	AnonymousPipe() = default;
	 bool initPip();
	 void uninPip();
	 void set_on_read(const std::function<void(const std::shared_ptr<uint8_t>&, size_t)>& on_read);
	 void write(const std::shared_ptr<uint8_t>& data, size_t size);

private:
	bool connect_pipe();
	void read_loop();
	void write_loop();

	struct WriteData
	{
		std::shared_ptr<uint8_t> data;
		size_t size;
	};
	std::deque<WriteData> write_buffer;
	std::thread m_rthread;
	std::thread m_wthread;
	std::function<void(const std::shared_ptr<uint8_t>&, size_t)> on_read_notify;
	HANDLE m_hStdout, m_hStdin;

	bool m_stopevent = false;
};

