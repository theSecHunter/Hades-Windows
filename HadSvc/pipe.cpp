#include <Windows.h>
#include <cstdint>
#include <string>
#include <thread>
#include <atomic>
#include <deque>
#include <condition_variable>
#include <mutex>
#include <tchar.h>
#include <cassert>
#include <vector>
#include <chrono>
#include "Pipe.h"
#include "time_stamp.h"


bool NamedPipe::init(const std::wstring& pipe_name)
{
    pipe_name_ = pipe_name;
    if (!connect_pipe())
        return false;
    read_thread_ = std::thread{ std::bind(&NamedPipe::read_loop, this) };
    write_thread_ = std::thread{ std::bind(&NamedPipe::write_loop, this) };
    return true;
}

void NamedPipe::uninit()
{
    // FIXME: 暂时只能唤醒write_loop()，需要加入机制唤醒read_loop()
    stoped_ = true;
    write_cv_.notify_one();
    if (read_thread_.joinable())
    {
        read_thread_.join();
    }
    if (write_thread_.joinable())
    {
        write_thread_.join();
    }
    if (pipe_ != INVALID_HANDLE_VALUE)
    {
        CloseHandle(pipe_);
        pipe_ = INVALID_HANDLE_VALUE;
    }
}

void NamedPipe::set_on_read(const std::function<void(const std::shared_ptr<uint8_t>&, size_t)>& on_read)
{
    on_read_ = on_read;
}

void NamedPipe::write(const std::shared_ptr<uint8_t>& data, size_t size)
{
    {
        std::lock_guard<std::mutex> lock{ mutex_ };
        write_buffer_.push_back({ data, size });
    }
    write_cv_.notify_one();
}

bool NamedPipe::connect_pipe()
{
    constexpr int64_t kTimeout = 1000; //毫秒
    const int64_t start_time = common::Timestamp::now().microseconds_since_powerup();

    while (!stoped_)
    {
        //超时
        int64_t now = common::Timestamp::now().microseconds_since_powerup();
        if (now - start_time > kTimeout)
        {
            OutputDebugString(_T("connect pipe timetout"));
            return false;
        }

        //连接已创建的命名管道
        pipe_ = CreateFile(
            pipe_name_.c_str(),             // pipe name 
            GENERIC_READ | GENERIC_WRITE,   // read and write access 
            0,                              // no sharing 
            NULL,                           // default security attributes
            OPEN_EXISTING,                  // opens existing pipe 
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,   // default attributes 
            NULL);                          // no template file 

        //连接成功
        if (pipe_ != INVALID_HANDLE_VALUE)
        {
            OutputDebugString(_T("connect pipe success"));
            DWORD dwmode = PIPE_READMODE_MESSAGE;
            auto success = SetNamedPipeHandleState(
                pipe_,    // pipe handle
                &dwmode,  // new pipe mode
                NULL,     // don't set maximum bytes
                NULL);    // don't set maximum time
            if (!success)
            {
                OutputDebugString(_T("SetNamedPipeHandleState failed"));
                return false;
            }
            return true;
        }

        //失败
        if (GetLastError() != ERROR_PIPE_BUSY)
        {
            OutputDebugString(_T("open pipe failed error:%d"));
            return false;
        }

        //管道忙，等20ms重试
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    assert(false);
    return false;
}

void NamedPipe::read_loop()
{
    constexpr size_t kBufferSize = 10 * 1024 * 1024; //10MB，收发过来的Json数据
    std::vector<uint8_t> buffer;
    buffer.resize(kBufferSize);
    while (!stoped_)
    {
        OVERLAPPED ovlp = { 0 };
        ovlp.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);

        DWORD bytes_read;
        bool success = ReadFile(
            pipe_,          // pipe handle 
            buffer.data(),  // buffer to receive reply 
            kBufferSize,    // size of buffer 
            &bytes_read,    // number of bytes read 
            &ovlp);         // not overlapped 

        DWORD wait = WaitForSingleObject(ovlp.hEvent, INFINITE);
        if (wait != WAIT_OBJECT_0) {
            break;
        }

        bytes_read = (DWORD)ovlp.InternalHigh;

        if (bytes_read == 0) {
            break;
        }

        if (on_read_ && bytes_read != 0)
        {
            std::shared_ptr<uint8_t> data{ new uint8_t[bytes_read] };
            ::memcpy(data.get(), buffer.data(), bytes_read);
            on_read_(data, bytes_read);
        }
    }
}

void NamedPipe::write_loop()
{
    std::unique_lock<std::mutex> lock{ mutex_ };
    while (!stoped_)
    {
        write_cv_.wait(lock);
        if (stoped_)
        {
            return;
        }

        while (!write_buffer_.empty())
        {
            auto buff = write_buffer_.front();
            write_buffer_.pop_front();
            DWORD bytes_written;
            bool success = WriteFile(pipe_, buff.data.get(), (DWORD)buff.size, &bytes_written, nullptr);
            if (!success)
            {
                //错误处理
                OutputDebugString(_T("WriteFile fail %d"));
            }
        }
    }
}
