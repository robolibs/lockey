#pragma once

// Secure memory wiping that cannot be optimized away
// Replaces libsodium's sodium_memzero()

#include <cstddef>
#include <cstdint>
#include <cstring>

namespace keylock::crypto::constant_time {

    // Securely wipe memory - guaranteed not to be optimized away
    inline void wipe(void *secret, size_t size) {
        volatile uint8_t *p = static_cast<volatile uint8_t *>(secret);
        for (size_t i = 0; i < size; ++i) {
            p[i] = 0;
        }
        // Memory barrier to prevent reordering
#if defined(_MSC_VER)
        _ReadWriteBarrier();
#else
        __asm__ __volatile__("" : : "r"(p) : "memory");
#endif
    }

    // Template version for fixed-size arrays
    template <typename T, size_t N> inline void wipe(T (&arr)[N]) { wipe(arr, sizeof(arr)); }

    // Wipe a container
    template <typename Container> inline void wipe_container(Container &c) {
        if (!c.empty()) {
            wipe(c.data(), c.size() * sizeof(typename Container::value_type));
        }
    }

} // namespace keylock::crypto::constant_time
