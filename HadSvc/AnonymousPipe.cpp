#include <Windows.h>
#include <WinBase.h>
#include <memory>
#include <stdint.h>
#include <thread>
#include <vector>
#include <mutex>
#include <deque>
#include "AnonymousPipe.h"

static std::mutex g_write_mutex;
static std::condition_variable g_write_event;
static HANDLE g_read_event = NULL;

bool AnonymousPipe::initPip()
{
	if (!connect_pipe())
		return false;
	m_rthread = std::thread(std::bind(&AnonymousPipe::read_loop, this));
	m_wthread = std::thread(std::bind(&AnonymousPipe::write_loop, this));
	return true;
}

void AnonymousPipe::uninPip()
{
    m_stopevent = true;
    if (m_hStdout) {
        CloseHandle(m_hStdout);
        m_hStdout = NULL;
    }
    if (m_hStdin) {
        CloseHandle(m_hStdin);
        m_hStdin = NULL;
    }
    if (g_read_event)
        SetEvent(g_read_event);
    g_write_event.notify_one();
    if (m_rthread.joinable())
    {
        m_rthread.join();
    }
    if (m_wthread.joinable())
    {
        m_wthread.join();
    }
}

void AnonymousPipe::set_on_read(const std::function<void(const std::shared_ptr<uint8_t>&, size_t)>& on_read)
{
    on_read_notify = on_read;
}

void AnonymousPipe::write(const std::shared_ptr<uint8_t>& data, size_t size)
{
    {
        std::lock_guard<std::mutex> lock{ g_write_mutex };
        write_buffer.push_back({ data, size });
    }
    g_write_event.notify_one();
}

bool AnonymousPipe::connect_pipe()
{
    m_hStdout = GetStdHandle(STD_OUTPUT_HANDLE);
    m_hStdin = GetStdHandle(STD_INPUT_HANDLE);
    if ((m_hStdout == INVALID_HANDLE_VALUE) || (m_hStdin == INVALID_HANDLE_VALUE))
        return false;
    return true;
}

void AnonymousPipe::read_loop()
{
    BOOL bSuccess = false;
    constexpr size_t kBufferSize = 1024;
    std::vector<uint8_t> buffer;
    DWORD dwRead = 0;
    buffer.resize(kBufferSize);
    OVERLAPPED ovlp = { 0 };
    ovlp.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    g_read_event = ovlp.hEvent;
    if (!ovlp.hEvent) {
        return;
    }
    for (;;)
    {
        ReadFile(m_hStdin, buffer.data(), kBufferSize, &dwRead, &ovlp);
        DWORD wait = WaitForSingleObject(ovlp.hEvent, INFINITE);
        if (wait != WAIT_OBJECT_0) {
            break;
        }
        else if (m_stopevent)
            break;
        dwRead = (DWORD)ovlp.InternalHigh;
        if (dwRead <= 0) {
            continue;
        }
        if (on_read_notify)
        {
            std::shared_ptr<uint8_t> data{ new uint8_t[dwRead] };
            ::memcpy(data.get(), buffer.data(), dwRead);
            on_read_notify(data, dwRead);
        }
    }
    if (ovlp.hEvent)
        CloseHandle(ovlp.hEvent);
}

void AnonymousPipe::write_loop()
{
    std::unique_lock<std::mutex> lock{ g_write_mutex };
    do {
        g_write_event.wait(lock);
        if (m_stopevent)
            break;
        while (!write_buffer.empty())
        {
            auto buff = write_buffer.front();
            write_buffer.pop_front();
            DWORD dwWirteByte;
            WriteFile(m_hStdout, buff.data.get(), (DWORD)buff.size, &dwWirteByte, nullptr);
        }
    } while (!m_stopevent);
}