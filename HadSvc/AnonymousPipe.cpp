#include <Windows.h>
#include <WinBase.h>
#include <memory>
#include <stdint.h>
#include <thread>
#include <vector>
#include <mutex>
#include <deque>
#include <limits>
#include "AnonymousPipe.h"

static std::mutex g_write_mutex;
static std::condition_variable g_write_event;
static HANDLE g_read_event = NULL;

bool AnonymousPipe::initPip()
{
	m_stopevent = false;
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
        ResetEvent(ovlp.hEvent);
        dwRead = 0;
        const BOOL success = ReadFile(m_hStdin, buffer.data(), kBufferSize, &dwRead, &ovlp);
        if (!success)
        {
            const DWORD error = GetLastError();
            if (error != ERROR_IO_PENDING)
                break;

            const DWORD wait = WaitForSingleObject(ovlp.hEvent, INFINITE);
            if (wait != WAIT_OBJECT_0)
                break;

            if (!GetOverlappedResult(m_hStdin, &ovlp, &dwRead, FALSE))
                break;
        }

        if (m_stopevent)
            break;

        if (dwRead <= 0) {
            continue;
        }
        if (on_read_notify)
        {
            std::shared_ptr<uint8_t> data(new uint8_t[dwRead], std::default_delete<uint8_t[]>());
            ::memcpy(data.get(), buffer.data(), dwRead);
            on_read_notify(data, dwRead);
        }
    }
    if (g_read_event == ovlp.hEvent)
        g_read_event = NULL;
    if (ovlp.hEvent)
        CloseHandle(ovlp.hEvent);
}

void AnonymousPipe::write_loop()
{
    std::unique_lock<std::mutex> lock{ g_write_mutex };
    do {
        g_write_event.wait(lock, [this]() { return m_stopevent || !write_buffer.empty(); });
        if (m_stopevent)
            break;
        while (!write_buffer.empty())
        {
            auto buff = write_buffer.front();
            write_buffer.pop_front();
            lock.unlock();
            DWORD dwWirteByte;
            if (buff.size <= (std::numeric_limits<DWORD>::max)())
                WriteFile(m_hStdout, buff.data.get(), static_cast<DWORD>(buff.size), &dwWirteByte, nullptr);
            lock.lock();
        }
    } while (!m_stopevent);
}
