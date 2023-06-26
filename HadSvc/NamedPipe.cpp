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
#include "NamedPipe.h"
#include "time_stamp.h"


bool NamedPipe::init(const std::wstring& pipe)
{
    pipe_name = pipe_name;
    if (!connect_pipe())
        return false;
    m_readthread = std::thread{ std::bind(&NamedPipe::read_loop, this) };
    m_writethread = std::thread{ std::bind(&NamedPipe::write_loop, this) };
    return true;
}

void NamedPipe::uninit()
{
    m_stopevent = true;
    m_write_event.notify_one();
    if (m_readthread.joinable())
    {
        m_readthread.join();
    }
    if (m_writethread.joinable())
    {
        m_writethread.join();
    }
    if (m_pipe != INVALID_HANDLE_VALUE)
    {
        CloseHandle(m_pipe);
        m_pipe = INVALID_HANDLE_VALUE;
    }
}

void NamedPipe::set_on_read(const std::function<void(const std::shared_ptr<uint8_t>&, size_t)>& on_read)
{
    on_readnotify = on_read;
}

void NamedPipe::write(const std::shared_ptr<uint8_t>& data, size_t size)
{
    {
        std::lock_guard<std::mutex> lock{ m_mutex };
        write_buffer.push_back({ data, size });
    }
    m_write_event.notify_one();
}

bool NamedPipe::connect_pipe()
{
    constexpr int64_t kTimeout = 1000;
    const int64_t start_time = common::Timestamp::now().microseconds_since_powerup();

    while (!m_stopevent)
    {
        int64_t now = common::Timestamp::now().microseconds_since_powerup();
        if (now - start_time > kTimeout)
            return false;

        // CreatePip
        m_pipe = CreateFile(
            pipe_name.c_str(),              // pipe name 
            GENERIC_READ | GENERIC_WRITE,   // read and write access 
            0,                              // no sharing 
            NULL,                           // default security attributes
            OPEN_EXISTING,                  // opens existing pipe 
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,   // default attributes 
            NULL);                          // no template file 

        // Success
        if (m_pipe != INVALID_HANDLE_VALUE)
        {
            DWORD dwmode = PIPE_READMODE_MESSAGE;
            auto success = SetNamedPipeHandleState(
                m_pipe,     // pipe handle
                &dwmode,    // new pipe mode
                NULL,       // don't set maximum bytes
                NULL);       // don't set maximum time
            if (!success)
                return false;
            return true;
        }

        // Failuer
        if (GetLastError() != ERROR_PIPE_BUSY)
            return false;

        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    return false;
}

void NamedPipe::read_loop()
{
    constexpr size_t kBufferSize = 1024;
    std::vector<uint8_t> buffer;
    buffer.resize(kBufferSize);
    OVERLAPPED ovlp = { 0 };
    ovlp.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (!ovlp.hEvent)
        return;

    DWORD dwRead = 0;
    while (!m_stopevent)
    {
        bool success = ReadFile(
            m_pipe,             // pipe handle 
            buffer.data(),      // buffer to receive reply 
            kBufferSize,        // size of buffer 
            &dwRead,            // number of bytes read 
            &ovlp);             // not overlapped 

        DWORD wait = WaitForSingleObject(ovlp.hEvent, INFINITE);
        if (wait != WAIT_OBJECT_0) {
            break;
        }

        dwRead = (DWORD)ovlp.InternalHigh;
        if (dwRead <= 0) {
            continue;
        }
        if (on_readnotify)
        {
            std::shared_ptr<uint8_t> data{ new uint8_t[dwRead] };
            ::memcpy(data.get(), buffer.data(), dwRead);
            on_readnotify(data, dwRead);
        }
    }
}

void NamedPipe::write_loop()
{
    std::unique_lock<std::mutex> lock{ m_mutex };
    do {
        m_write_event.wait(lock);
        if (m_stopevent)
            break;
        while (!write_buffer.empty())
        {
            auto buff = write_buffer.front();
            write_buffer.pop_front();
            DWORD bytes_written;
            WriteFile(m_pipe, buff.data.get(), (DWORD)buff.size, &bytes_written, nullptr);
        }
    } while (!m_stopevent);
}
