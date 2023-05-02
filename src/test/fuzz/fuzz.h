// Copyright (c) 2009-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_TEST_FUZZ_FUZZ_H
#define BITCOIN_TEST_FUZZ_FUZZ_H

#include <span.h>

#include <cstdint>
#include <functional>
#include <string_view>

/**
 * Can be used to limit a theoretically unbounded loop. This caps the runtime
 * to avoid timeouts or OOMs.
 */
#define LIMITED_WHILE(condition, limit) \
    for (unsigned _count{limit}; (condition) && _count; --_count)

enum class FuzzResult
{
    /** Normal fuzzing result. */
    MAYBE_INTERESTING,

    /** This value can be returned by fuzz tests to indicate the input was uninteresting.
     *
     * libfuzzer can make use of this and will not insert the input in its corpus, even when it
     * appears to increase coverage. */
    UNINTERESTING
};

using FuzzBufferType = Span<const uint8_t>;
using TypeTestOneInput = std::function<FuzzResult(FuzzBufferType)>;

struct FuzzTargetOptions {
    std::function<void()> init{[] {}};
    bool hidden{false};
};

void FuzzFrameworkRegisterTarget(std::string_view name, TypeTestOneInput target, FuzzTargetOptions opts);

#if defined(__clang__)
#define FUZZ_TARGET(...) _Pragma("clang diagnostic push") _Pragma("clang diagnostic ignored \"-Wgnu-zero-variadic-macro-arguments\"") DETAIL_FUZZ(__VA_ARGS__) _Pragma("clang diagnostic pop")
#define FUZZ_PARTIAL_TARGET(...) _Pragma("clang diagnostic push") _Pragma("clang diagnostic ignored \"-Wgnu-zero-variadic-macro-arguments\"") DETAIL_FUZZ_PARTIAL(__VA_ARGS__) _Pragma("clang diagnostic pop")
#else
#define FUZZ_TARGET(...) DETAIL_FUZZ(__VA_ARGS__)
#define FUZZ_PARTIAL_TARGET(...) DETAIL_FUZZ_PARTIAL(__VA_ARGS__)
#endif

#define DETAIL_FUZZ(name, ...)                                                     \
    FuzzResult name##_fuzz_target(FuzzBufferType);                                 \
    void name##_fuzz_target_complete(FuzzBufferType);                              \
    struct name##_Before_Main {                                                    \
        name##_Before_Main()                                                       \
        {                                                                          \
            FuzzFrameworkRegisterTarget(#name, name##_fuzz_target, {__VA_ARGS__}); \
        }                                                                          \
    } const static g_##name##_before_main;                                         \
    FuzzResult name##_fuzz_target(FuzzBufferType buffer)                           \
    {                                                                              \
        name##_fuzz_target_complete(buffer);                                       \
        return FuzzResult::MAYBE_INTERESTING;                                      \
    }                                                                              \
    void name##_fuzz_target_complete(FuzzBufferType buffer)

#define DETAIL_FUZZ_PARTIAL(name, ...)                                             \
    FuzzResult name##_fuzz_target(FuzzBufferType);                                 \
    struct name##_Before_Main {                                                    \
        name##_Before_Main()                                                       \
        {                                                                          \
            FuzzFrameworkRegisterTarget(#name, name##_fuzz_target, {__VA_ARGS__}); \
        }                                                                          \
    } const static g_##name##_before_main;                                         \
    FuzzResult name##_fuzz_target(FuzzBufferType buffer)

#endif // BITCOIN_TEST_FUZZ_FUZZ_H
