#ifndef BITCOIN_TEST_FUZZ_SNAPSHOT_FUZZ_H
#define BITCOIN_TEST_FUZZ_SNAPSHOT_FUZZ_H

#include <cstddef>
#include <cstdint>
#include <functional>

#include <span.h>
#include <test/fuzz/fuzz.h>

#ifdef SNAPSHOT_FUZZ
extern "C" __attribute__((weak)) void nyx_printf(const char*, ...);
#else
static void nyx_printf(const char*, ...) {}
#endif

namespace snapshot_fuzz {
class Fuzz
{
#ifdef SNAPSHOT_FUZZ
    size_t m_max_size;
#else
    Span<const uint8_t> m_buffer;
#endif

public:
    Fuzz(Span<const uint8_t> buffer);
    ~Fuzz() = default;

    void run(std::function<void(Span<const uint8_t>)> fn);
};
} // namespace snapshot_fuzz


/** Define a fuzz target that is meant for snapshot fuzzing.
 *
 * These fuzz targets will be registered and available as normal hidden fuzz
 * targets if the fuzz binary is not compiled with -DSNAPSHOT_FUZZ.
 *
 * Example:
 *
 * ```
 *   void FuzzFoo(snapshot_fuzz::Fuzz& fuzz)
 *   {
 *       // Do your exspensive state setup in here.
 *       ...
 *
 *       fuzz.run([](Span<const uint8_t> buffer) {
 *           // Fuzz target goes in here under the assumption that the
 *           // state from above is reset each iteration.
 *           ...
 *       });
 *   }
 *
 *   SNAPSHOT_FUZZ_TARGET(FuzzFoo);
 * ```
 */
#define SNAPSHOT_FUZZ_TARGET(target)                                 \
    static void target##_initialize() {}                             \
    FUZZ_TARGET(target, .init = target##_initialize, .hidden = true) \
    {                                                                \
        snapshot_fuzz::Fuzz fuzz{buffer};                            \
        target(fuzz);                                                \
    }

#endif
