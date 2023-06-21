#include <test/util/initialized_mem_check.h>

#include <cstdint>
#include <cstdio>

extern "C" {
__attribute__((weak)) void __msan_check_mem_is_initialized(const volatile void* data, size_t size);
}

void CheckMemInitialized(const void* data, size_t size)
{
#ifdef CHECK_MEM_INITIALIZED
    if (__msan_check_mem_is_initialized) {
        __msan_check_mem_is_initialized(data, size);
    } else {
        FILE* dev_null = fopen("/dev/null", "wb");
        fwrite(data, sizeof(size), 1, dev_null);
        fclose(dev_null);
    }
#endif
}
