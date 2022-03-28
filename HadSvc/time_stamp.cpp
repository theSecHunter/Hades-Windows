#include "time_stamp.h"
#ifdef __unix__
#include <sys/time.h>  //gettimeofday();
#endif //__unix__
#if defined(_WIN32) || defined(WIN32) 
#include <ctime>
#include <windows.h>  //queryperformance_xxx()
#include <chrono>
#endif  //__win32
#include <cinttypes>

static int64_t microseconds_since_epoch()
{
    int64_t time_cur = std::chrono::duration_cast<std::chrono::microseconds>(
                std::chrono::steady_clock::now().time_since_epoch()).count();
    return time_cur;
}

namespace common
{

Timestamp Timestamp::now(int64_t offset)
{
    return Timestamp(::microseconds_since_epoch() + offset);
}
Timestamp Timestamp::now()
{
    return Timestamp(::microseconds_since_epoch());
}

Timestamp Timestamp::now_china()
{
    return Timestamp((static_cast<int64_t>(8) * 3600) * kMicroSecondsPerSecond + ::microseconds_since_epoch());
}

std::string Timestamp::to_string(bool show_microseconds)const 
{
    char buf[32] = {0};
    time_t seconds = static_cast<time_t>(microseconds_since_epoch_ / kMicroSecondsPerSecond);
    struct tm tm_time;
#if defined(WIN32) || defined(_WIN32)
    //gmtime is thread safe on windows
    tm_time = *(gmtime(&seconds));
#endif

#ifdef __unix__
    gmtime_r(&seconds, &tm_time);
#endif

    if (show_microseconds)
    {
        int microseconds = static_cast<int>(microseconds_since_epoch_ % kMicroSecondsPerSecond);
        snprintf(buf, sizeof(buf), "%4d%02d%02d %02d:%02d:%02d.%06d",
             tm_time.tm_year + 1900, tm_time.tm_mon + 1, tm_time.tm_mday,
             tm_time.tm_hour, tm_time.tm_min, tm_time.tm_sec,
             microseconds);
    }
    else
    {
        snprintf(buf, sizeof(buf), "%4d%02d%02d %02d:%02d:%02d",
             tm_time.tm_year + 1900, tm_time.tm_mon + 1, tm_time.tm_mday,
             tm_time.tm_hour, tm_time.tm_min, tm_time.tm_sec);
    }
    return buf;
}

}
