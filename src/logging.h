// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_LOGGING_H
#define BITCOIN_LOGGING_H

#include <crypto/siphash.h>
#include <fs.h>
#include <tinyformat.h>
#include <threadsafety.h>
#include <util/string.h>
#include <util/time.h>

#include <atomic>
#include <cstdint>
#include <functional>
#include <list>
#include <mutex>
#include <string>
#include <vector>

static const bool DEFAULT_LOGTIMEMICROS = false;
static const bool DEFAULT_LOGIPS        = false;
static const bool DEFAULT_LOGTIMESTAMPS = true;
static const bool DEFAULT_LOGTHREADNAMES = false;
static const bool DEFAULT_LOGSOURCELOCATIONS = false;
static const bool DEFAULT_RATELIMITLOGGING = true;
extern const char * const DEFAULT_DEBUGLOGFILE;

extern bool fLogIPs;

// TODO: use C++20 std::sourcelocation when available
struct SourceLocation {
    std::string m_file;
    int m_line{0};

    bool operator==(const SourceLocation& other) const
    {
        return m_file.compare(other.m_file) == 0 &&
               m_line == other.m_line;
    }
};

struct SourceLocationHasher {
    size_t operator()(const SourceLocation& source_location) const noexcept
    {
        // Use CSipHasher(0, 0) as a simple way to get uniform distribution.
        return static_cast<size_t>(CSipHasher(0, 0)
                                       .Write(std::hash<std::string>{}(source_location.m_file))
                                       .Write(std::hash<int>{}(source_location.m_line))
                                       .Finalize());
    }
};

struct LogCategory {
    std::string category;
    bool active;
};

namespace BCLog {
    enum LogFlags : uint32_t {
        NONE        = 0,
        NET         = (1 <<  0),
        TOR         = (1 <<  1),
        MEMPOOL     = (1 <<  2),
        HTTP        = (1 <<  3),
        BENCH       = (1 <<  4),
        ZMQ         = (1 <<  5),
        WALLETDB    = (1 <<  6),
        RPC         = (1 <<  7),
        ESTIMATEFEE = (1 <<  8),
        ADDRMAN     = (1 <<  9),
        SELECTCOINS = (1 << 10),
        REINDEX     = (1 << 11),
        CMPCTBLOCK  = (1 << 12),
        RAND        = (1 << 13),
        PRUNE       = (1 << 14),
        PROXY       = (1 << 15),
        MEMPOOLREJ  = (1 << 16),
        LIBEVENT    = (1 << 17),
        COINDB      = (1 << 18),
        QT          = (1 << 19),
        LEVELDB     = (1 << 20),
        VALIDATION  = (1 << 21),
        I2P         = (1 << 22),
        IPC         = (1 << 23),
        LOCK        = (1 << 24),
        UTIL        = (1 << 25),
        BLOCKSTORE  = (1 << 26),
        ALL         = ~(uint32_t)0,
    };

    //! Fixed window rate limiter for logging.
    class LogRatelimiter
    {
    private:
        //! Timestamp of the last window reset.
        std::chrono::seconds m_last_reset;
        //! Interval after which the window is reset.
        std::chrono::seconds m_reset_interval;
        //! Remaining bytes in the current window interval.
        uint64_t m_available_bytes;
        //! Number of bytes that were not consumed within the current window.
        uint64_t m_dropped_bytes{0};
        //! The maximum number of bytes that can be logged withon one window.
        uint64_t m_max_bytes;

        //! Reset the window if the window interval has passed since the last reset.
        void MaybeReset();

    public:
        LogRatelimiter() {}

        LogRatelimiter(std::chrono::seconds interval, uint64_t max_bytes)
            : m_reset_interval{interval}, m_available_bytes{max_bytes}, m_max_bytes{max_bytes}
        {
            m_last_reset = GetTime<std::chrono::seconds>();
        }

        //! Consume bytes from the window if enough bytes are available.
        //!
        //! Returns whether or not enough bytes were available.
        bool Consume(uint64_t bytes);

        uint64_t GetAvailableBytes() const
        {
            return m_available_bytes;
        }

        uint64_t GetDroppedBytes() const
        {
            return m_dropped_bytes;
        }
    };

    class Logger
    {
    private:
        mutable StdMutex m_cs; // Can not use Mutex from sync.h because in debug mode it would cause a deadlock when a potential deadlock was detected

        FILE* m_fileout GUARDED_BY(m_cs) = nullptr;
        std::list<std::string> m_msgs_before_open GUARDED_BY(m_cs);
        bool m_buffering GUARDED_BY(m_cs) = true; //!< Buffer messages before logging can be started.

        /**
         * m_started_new_line is a state variable that will suppress printing of
         * the timestamp when multiple calls are made that don't end in a
         * newline.
         */
        std::atomic_bool m_started_new_line{true};

        /** Log categories bitfield. */
        std::atomic<uint32_t> m_categories{0};

        std::string LogTimestampStr(const std::string& str);

        /** Slots that connect to the print signal */
        std::list<std::function<void(const std::string&)>> m_print_callbacks GUARDED_BY(m_cs) {};

    public:
        bool m_print_to_console = false;
        bool m_print_to_file = false;

        bool m_log_timestamps = DEFAULT_LOGTIMESTAMPS;
        bool m_log_time_micros = DEFAULT_LOGTIMEMICROS;
        bool m_log_threadnames = DEFAULT_LOGTHREADNAMES;
        bool m_log_sourcelocations = DEFAULT_LOGSOURCELOCATIONS;
        bool m_ratelimit = DEFAULT_RATELIMITLOGGING;

        fs::path m_file_path;
        std::atomic<bool> m_reopen_file{false};

        /** Send a string to the log output */
        void LogPrintStr(const std::string& str, const std::string& logging_function, const SourceLocation& source_location, bool skip_ratelimiting);

        /** Returns whether logs will be written to any output */
        bool Enabled() const
        {
            StdLockGuard scoped_lock(m_cs);
            return m_buffering || m_print_to_console || m_print_to_file || !m_print_callbacks.empty();
        }

        /** Connect a slot to the print signal and return the connection */
        std::list<std::function<void(const std::string&)>>::iterator PushBackCallback(std::function<void(const std::string&)> fun)
        {
            StdLockGuard scoped_lock(m_cs);
            m_print_callbacks.push_back(std::move(fun));
            return --m_print_callbacks.end();
        }

        /** Delete a connection */
        void DeleteCallback(std::list<std::function<void(const std::string&)>>::iterator it)
        {
            StdLockGuard scoped_lock(m_cs);
            m_print_callbacks.erase(it);
        }

        /** Start logging (and flush all buffered messages) */
        bool StartLogging();
        /** Only for testing */
        void DisconnectTestLogger();

        void ShrinkDebugFile();

        uint32_t GetCategoryMask() const { return m_categories.load(); }

        void EnableCategory(LogFlags flag);
        bool EnableCategory(const std::string& str);
        void DisableCategory(LogFlags flag);
        bool DisableCategory(const std::string& str);

        bool WillLogCategory(LogFlags category) const;
        /** Returns a vector of the log categories in alphabetical order. */
        std::vector<LogCategory> LogCategoriesList() const;
        /** Returns a string with the log categories in alphabetical order. */
        std::string LogCategoriesString() const
        {
            return Join(LogCategoriesList(), ", ", [&](const LogCategory& i) { return i.category; });
        };

        bool DefaultShrinkDebugFile() const;
    };
} // namespace BCLog

BCLog::Logger& LogInstance();

/** Return true if log accepts specified category */
static inline bool LogAcceptCategory(BCLog::LogFlags category)
{
    return LogInstance().WillLogCategory(category);
}

/** Return true if str parses as a log category and set the flag */
bool GetLogCategory(BCLog::LogFlags& flag, const std::string& str);

// Be conservative when using LogPrintf/error or other things which
// unconditionally log to debug.log! It should not be the case that an inbound
// peer can fill up a user's disk with debug.log entries.

template <typename... Args>
static inline void LogPrintf_(const std::string& logging_function, const std::string& source_file, const int source_line, bool skip_ratelimiting, const char* fmt, const Args&... args)
{
    if (LogInstance().Enabled()) {
        std::string log_msg;
        try {
            log_msg = tfm::format(fmt, args...);
        } catch (tinyformat::format_error& fmterr) {
            /* Original format string will have newline so don't add one here */
            log_msg = "Error \"" + std::string(fmterr.what()) + "\" while formatting log message: " + fmt;
        }

        const SourceLocation source_location{source_file, source_line};
        LogInstance().LogPrintStr(log_msg, logging_function, source_location, skip_ratelimiting);
    }
}

// Unconditional logging. Uses basic rate limiting to mitigate disk filling attacks.
#define LogPrintf(...) LogPrintf_(__func__, __FILE__, __LINE__, /* skip_ratelimiting */ false, __VA_ARGS__)

// Unconditional logging WITHOUT rate limiting. Use only for log messages that
// MUST NOT be rate limited no matter how often they are logged. That requirement
// should be extremely rare, so please use with care. Prefer LogPrintf(...) if
// possible.
#define LogPrintfWithoutRateLimiting(...) LogPrintf_(__func__, __FILE__, __LINE__, /* skip_ratelimiting */ true, __VA_ARGS__)

// Use a macro instead of a function for conditional logging to prevent
// evaluating arguments when logging for the category is not enabled.
#define LogPrint(category, ...)              \
    do {                                     \
        if (LogAcceptCategory((category))) { \
            LogPrintf(__VA_ARGS__);          \
        }                                    \
    } while (0)

#endif // BITCOIN_LOGGING_H
