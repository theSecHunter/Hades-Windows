#pragma once
#include <functional>

class NamedPipe
{
public:
    NamedPipe() = default;
    bool init(const std::wstring& pipe_name);
    void uninit();
    void set_on_read(const std::function<void(const std::shared_ptr<uint8_t>&, size_t)>& on_read);
    void write(const std::shared_ptr<uint8_t>& data, size_t size);

private:
    bool connect_pipe();
    void read_loop();
    void write_loop();

private:
    std::atomic<bool> stoped_ = false;
    std::wstring pipe_name_;
    HANDLE pipe_ = INVALID_HANDLE_VALUE;
    std::thread read_thread_;
    std::thread write_thread_;
    std::function<void(const std::shared_ptr<uint8_t>&, size_t)> on_read_;
    std::condition_variable write_cv_;
    std::mutex mutex_;
    struct WriteBuffer
    {
        std::shared_ptr<uint8_t> data;
        size_t size;
    };
    std::deque<WriteBuffer> write_buffer_;
};