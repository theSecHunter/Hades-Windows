#pragma once
#include <functional>

class NamedPipe
{
public:
    NamedPipe() = default;
    bool init(const std::wstring& pipe);
    void uninit();
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
    std::thread m_readthread;
    std::thread m_writethread;
    std::function<void(const std::shared_ptr<uint8_t>&, size_t)> on_readnotify;
    std::atomic<bool> m_stopevent = false;
    std::wstring pipe_name;
    HANDLE m_pipe = INVALID_HANDLE_VALUE;
    std::condition_variable m_write_event;
    std::mutex m_mutex;

};