// Copyright (c) 2024-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_COMMON_URANDOM_H
#define BITCOIN_COMMON_URANDOM_H

#include <cerrno>
#include <cstdint>
#include <cstring>
#include <span>
#include <stdexcept>
#include <string>
#include <vector>

#include <fcntl.h>
#include <unistd.h>

/**
 * Adversarial entropy source that reads directly from /dev/urandom on *every*
 * draw.
 *
 * This is deliberately different from FastRandomContext: FRC seeds once from the
 * OS RNG and then expands the stream internally with ChaCha20, so an external
 * fuzzer that controls the entropy device cannot steer the individual draws.
 * By issuing a fresh read() per request, every adversarial choice is taken
 * straight from /dev/urandom, which a deterministic hypervisor / coverage-guided
 * fuzzer (e.g. Antithesis) instruments and controls. The fuzzer therefore drives
 * the construction of every adversarial message, block and transaction.
 *
 * NOT for any security-sensitive use; this is a test-only adversarial tool.
 */
class UrandomSource
{
public:
    UrandomSource()
    {
        m_fd = ::open("/dev/urandom", O_RDONLY | O_CLOEXEC);
        if (m_fd < 0) {
            throw std::runtime_error(std::string{"UrandomSource: cannot open /dev/urandom: "} + std::strerror(errno));
        }
    }
    ~UrandomSource()
    {
        if (m_fd >= 0) ::close(m_fd);
    }
    UrandomSource(const UrandomSource&) = delete;
    UrandomSource& operator=(const UrandomSource&) = delete;

    //! Fill the buffer with bytes read directly from /dev/urandom.
    void fill(std::span<std::byte> out)
    {
        size_t off{0};
        while (off < out.size()) {
            const ssize_t n{::read(m_fd, out.data() + off, out.size() - off)};
            if (n <= 0) {
                if (n < 0 && errno == EINTR) continue;
                throw std::runtime_error("UrandomSource: read from /dev/urandom failed");
            }
            off += static_cast<size_t>(n);
        }
    }

    template <typename T>
    T rand()
    {
        static_assert(std::is_trivially_copyable_v<T>);
        T value{};
        fill(std::as_writable_bytes(std::span<T, 1>(&value, 1)));
        return value;
    }

    uint64_t rand64() { return rand<uint64_t>(); }
    uint32_t rand32() { return rand<uint32_t>(); }
    uint16_t rand16() { return rand<uint16_t>(); }
    uint8_t rand8() { return rand<uint8_t>(); }
    bool randbool() { return rand8() & 1; }

    //! Uniform-ish value in [0, range). Modulo bias is acceptable (and keeps the
    //! byte->choice mapping simple for the controlling fuzzer). Returns 0 if range==0.
    uint64_t randrange(uint64_t range) { return range == 0 ? 0 : rand64() % range; }

    //! n random bytes.
    std::vector<unsigned char> randbytes(size_t n)
    {
        std::vector<unsigned char> ret(n);
        if (n > 0) fill(std::as_writable_bytes(std::span<unsigned char>(ret.data(), n)));
        return ret;
    }

private:
    int m_fd{-1};
};

#endif // BITCOIN_COMMON_URANDOM_H
