// Copyright (c) 2009-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_TEST_FUZZ_FUZZ_H
#define BITCOIN_TEST_FUZZ_FUZZ_H

#include <span.h>

#include <cstdint>
#include <functional>
#include <optional>
#include <string_view>

extern "C" __attribute__((weak)) size_t LLVMFuzzerMutate(uint8_t* data, size_t size, size_t max_size);

/**
 * Can be used to limit a theoretically unbounded loop. This caps the runtime
 * to avoid timeouts or OOMs.
 */
#define LIMITED_WHILE(condition, limit) \
    for (unsigned _count{limit}; (condition) && _count; --_count)

using FuzzBufferType = Span<const uint8_t>;

using TypeTestOneInput = std::function<void(FuzzBufferType)>;
using TypeCustomMutator = std::function<size_t(uint8_t* data, size_t, size_t, unsigned int)>;
using TypeInitialize = std::function<void()>;
using TypeHidden = bool;

void FuzzFrameworkRegisterTarget(std::string_view name, TypeTestOneInput target, std::optional<TypeCustomMutator> mutator, TypeInitialize init, TypeHidden hidden);

inline void FuzzFrameworkEmptyInitFun() {}

#define FUZZ_TARGET(name) \
    FUZZ_TARGET_INIT(name, FuzzFrameworkEmptyInitFun)

#define FUZZ_TARGET_WITH_CUSTOM_MUTATOR(name, mutator) \
    FUZZ_TARGET_INIT_WITH_CUSTOM_MUTATOR(name, FuzzFrameworkEmptyInitFun, mutator)

#define FUZZ_TARGET_INIT_WITH_CUSTOM_MUTATOR(name, init_fun, mutator) \
    FUZZ_TARGET_INIT_HIDDEN(name, init_fun, mutator, false)

#define FUZZ_TARGET_INIT(name, init_fun) \
    FUZZ_TARGET_INIT_HIDDEN(name, init_fun, std::nullopt, false)

#define FUZZ_TARGET_INIT_HIDDEN(name, init_fun, mutator, hidden)                               \
    void name##_fuzz_target(FuzzBufferType);                                                   \
    struct name##_Before_Main {                                                                \
        name##_Before_Main()                                                                   \
        {                                                                                      \
            FuzzFrameworkRegisterTarget(#name, name##_fuzz_target, mutator, init_fun, hidden); \
        }                                                                                      \
    } const static g_##name##_before_main;                                                     \
    void name##_fuzz_target(FuzzBufferType buffer)


#endif // BITCOIN_TEST_FUZZ_FUZZ_H
