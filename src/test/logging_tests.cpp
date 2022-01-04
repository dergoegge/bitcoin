// Copyright (c) 2019-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <logging.h>
#include <logging/timer.h>
#include <test/util/logging.h>
#include <test/util/setup_common.h>

#include <chrono>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(logging_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(logging_timer)
{
    SetMockTime(1);
    auto micro_timer = BCLog::Timer<std::chrono::microseconds>("tests", "end_msg");
    SetMockTime(2);
    BOOST_CHECK_EQUAL(micro_timer.LogMsg("test micros"), "tests: test micros (1000000μs)");

    SetMockTime(1);
    auto ms_timer = BCLog::Timer<std::chrono::milliseconds>("tests", "end_msg");
    SetMockTime(2);
    BOOST_CHECK_EQUAL(ms_timer.LogMsg("test ms"), "tests: test ms (1000.00ms)");

    SetMockTime(1);
    auto sec_timer = BCLog::Timer<std::chrono::seconds>("tests", "end_msg");
    SetMockTime(2);
    BOOST_CHECK_EQUAL(sec_timer.LogMsg("test secs"), "tests: test secs (1.00s)");
}

BOOST_AUTO_TEST_CASE(logging_ratelimit_window)
{
    SetMockTime(std::chrono::minutes{1});
    BCLog::LogRatelimiter window{std::chrono::minutes{1}, 1000};

    // Check that window gets initialised correctly.
    BOOST_CHECK_EQUAL(window.GetAvailableBytes(), 1000ull);
    BOOST_CHECK_EQUAL(window.GetDroppedBytes(), 0ull);

    BOOST_CHECK(window.Consume(500));
    BOOST_CHECK_EQUAL(window.GetAvailableBytes(), 500ull);
    BOOST_CHECK_EQUAL(window.GetDroppedBytes(), 0ull);

    BOOST_CHECK(window.Consume(500));
    BOOST_CHECK_EQUAL(window.GetAvailableBytes(), 0ull);
    BOOST_CHECK_EQUAL(window.GetDroppedBytes(), 0ull);

    // Consuming another 500 bytes after already having consumed a 1000 bytes should fail.
    BOOST_CHECK(!window.Consume(500));
    BOOST_CHECK_EQUAL(window.GetAvailableBytes(), 0ull);
    BOOST_CHECK_EQUAL(window.GetDroppedBytes(), 500ull);

    // Advance time by one minute. This should trigger a window reset.
    SetMockTime(std::chrono::minutes{2});

    // Check that the window resets as expected when new bytes are consumed.
    BOOST_CHECK(window.Consume(100));
    BOOST_CHECK_EQUAL(window.GetAvailableBytes(), 900ull);
    BOOST_CHECK_EQUAL(window.GetDroppedBytes(), 0ull);
}

void LogFromLocation(int location, std::string message)
{
    switch (location) {
    case 0:
        LogPrintf("%s\n", message);
        break;
    case 1:
        LogPrintf("%s\n", message);
        break;
    default:
        BOOST_CHECK_MESSAGE(false, "Unkown log location");
    }
}

void LogFromLocationAndExpect(int location, std::string message, std::string expect)
{
    ASSERT_DEBUG_LOG(expect);
    LogFromLocation(location, message);
}

BOOST_AUTO_TEST_CASE(rate_limiting)
{
    bool prev_log_timestamps = LogInstance().m_log_sourcelocations;
    LogInstance().m_log_timestamps = false;
    bool prev_log_sourcelocations = LogInstance().m_log_sourcelocations;
    LogInstance().m_log_sourcelocations = false;
    bool prev_log_threadnames = LogInstance().m_log_threadnames;
    LogInstance().m_log_threadnames = false;

    // Log 1024-character lines (1023 plus newline) to make the math simple.
    std::string log_message(1023, 'a');

    SetMockTime(std::chrono::hours{1});

    // Logging 1 MiB should be allowed.
    for (int i = 0; i < 1024; ++i) {
        LogFromLocation(0, log_message);
    }

    BOOST_CHECK_NO_THROW(
        LogFromLocationAndExpect(0, log_message, "Excessive logging detected"));
    BOOST_CHECK_THROW(
        LogFromLocationAndExpect(1, log_message, "Excessive logging detected"), std::runtime_error);

    SetMockTime(std::chrono::hours{2});

    BOOST_CHECK_NO_THROW(
        LogFromLocationAndExpect(0, log_message, "Restarting logging"));
    BOOST_CHECK_THROW(
        LogFromLocationAndExpect(1, log_message, "Restarting logging"), std::runtime_error);

    LogInstance().m_log_timestamps = prev_log_timestamps;
    LogInstance().m_log_sourcelocations = prev_log_sourcelocations;
    LogInstance().m_log_threadnames = prev_log_threadnames;
    SetMockTime(std::chrono::seconds{0});
}

BOOST_AUTO_TEST_SUITE_END()
