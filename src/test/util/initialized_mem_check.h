#ifndef BITCOIN_TEST_UTIL_INITIALIZED_MEM_CHECK_H
#define BITCOIN_TEST_UTIL_INITIALIZED_MEM_CHECK_H

#include <cstddef>
#include <string>
#include <type_traits>

void CheckMemInitialized(const void* data, size_t size);

template <typename T>
void CheckMemInitialized(const T& val)
{
    static_assert(std::is_trivially_copyable<T>::value);
    CheckMemInitialized(&val, sizeof(val));
}

template <>
void CheckMemInitialized(const std::string& str)
{
    CheckMemInitialized(str.data(), str.size());
}

#endif
