#include <cstdint>
#include <cstdio>
#include <functional>

#include <span.h>
#include <test/fuzz/fuzz.h>
#include <util/check.h>

namespace snapshot_fuzz {
class Fuzz
{
    Span<const uint8_t> m_buffer;

public:
    Fuzz(Span<const uint8_t> buffer) : m_buffer{buffer} {}

    void run(std::function<void(Span<const uint8_t>)> fn)
    {
#ifdef SNAPSHOT_FUZZ
        // Take snapshot
        // Snapshot setup can be slow, since that only needs to happen once.
        //
        // We allocate a 1MiB buffer here for the fuzz engine to write into.
        constexpr size_t FUZZ_BUFFER_SIZE{1024 * 1024};
        // The fuzz engine will write fuzzed data into `buffer` and the size of
        // that data into `fuzzed_size`.
        uint8_t buffer[FUZZ_BUFFER_SIZE];
        size_t fuzzed_size{0};

        // Print out the addresses of `buffer` and `fuzzed_size`.
        printf("SNAPSHOT data buffer: %p\n", buffer);
        printf("SNAPSHOT data size: %p\n", &fuzzed_size);
        fflush(stdout);

        // VM snapshot is taken here (this instruction is specific to `snapchange`).
        __asm("int3 ; vmcall");

        Assert(fn)({buffer, fuzzed_size});
#else
        fn(m_buffer);
#endif
    }
};
} // namespace snapshot_fuzz


/** Define a fuzz target that is meant for snapshot fuzzing.
 *
 * These fuzz targets will be registered as normal hidden fuzz targets.
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
#define SNAPSHOT_FUZZ_TARGET(target)                              \
    static void init_target() {}                                  \
    FUZZ_TARGET_INIT_HIDDEN(target, init_target, /*hidden=*/true) \
    {                                                             \
        snapshot_fuzz::Fuzz fuzz{buffer};                         \
        target(fuzz);                                             \
    }

