#ifndef COMMON_TIME_STAMP_H_
#define COMMON_TIME_STAMP_H_
#include <string>
#include <chrono>

namespace common
{
class Timestamp
{
public:
    static const int kMicroSecondsPerSecond = 1000 * 1000;
    static const int64_t kMicroSecondsPerDay = static_cast<int64_t>(kMicroSecondsPerSecond) * 24 * 60 * 60;

    Timestamp()
        :microseconds_since_epoch_(0)
    {}
    Timestamp(int64_t time_)
        :microseconds_since_epoch_(time_)
    {}
    void swap(Timestamp that)
    {
        std::swap(microseconds_since_epoch_,that.microseconds_since_epoch_);
    }
    std::string to_string(bool show_microseconds = true) const;

    inline int64_t microseconds_since_epoch() const
    {
        return microseconds_since_epoch_;
    }
    inline time_t seconds_since_epoch() const
    {
        return static_cast<time_t>(microseconds_since_epoch_ / kMicroSecondsPerSecond);
    }
    static inline int64_t microseconds_since_powerup()
    {
        return std::chrono::duration_cast<std::chrono::microseconds>(
                    std::chrono::steady_clock::now().time_since_epoch()).count();
    }
    //XXX:for verify time sync
    static Timestamp now(int64_t offset);
    static Timestamp now();
    static Timestamp now_china();
private:
    int64_t microseconds_since_epoch_;
};

inline bool operator < (const Timestamp& a,const Timestamp& b)
{
    return a.microseconds_since_epoch()< b.microseconds_since_epoch();
}
inline bool operator <= (const Timestamp& a,const Timestamp& b)
{
    return a.microseconds_since_epoch()<= b.microseconds_since_epoch();
}
inline bool operator > (const Timestamp& a,const Timestamp& b)
{
    return b < a ;
}
inline bool operator==(const Timestamp& lhs, const Timestamp& rhs)
{
    return lhs.microseconds_since_epoch() == rhs.microseconds_since_epoch();
}
inline bool operator!=(const Timestamp& lhs, const Timestamp& rhs)
{
    return !(lhs.microseconds_since_epoch() == rhs.microseconds_since_epoch());
}
inline int64_t  operator-(const Timestamp& lhs,const Timestamp& rhs)
{
    return lhs.microseconds_since_epoch() - rhs.microseconds_since_epoch();
}
inline int64_t operator+(const Timestamp& lhs,const Timestamp& rhs)
{
    return lhs.microseconds_since_epoch() + rhs.microseconds_since_epoch();
}

}
#endif
