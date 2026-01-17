#pragma once

// Random number generation using system entropy sources
// Replaces libsodium's randombytes_buf()

#include <cstddef>
#include <cstdint>
#include <stdexcept>

#if defined(__linux__) || defined(__ANDROID__)
#include <sys/random.h>
#elif defined(__APPLE__)
#include <Security/SecRandom.h>
#elif defined(_WIN32)
#include <bcrypt.h>
#include <windows.h>
#pragma comment(lib, "bcrypt.lib")
#else
#include <fstream>
#endif

namespace keylock::crypto::rng {

    namespace detail {

#if defined(__linux__) || defined(__ANDROID__)

        inline void fill_random(void *buf, size_t size) {
            uint8_t *ptr = static_cast<uint8_t *>(buf);
            while (size > 0) {
                ssize_t ret = getrandom(ptr, size, 0);
                if (ret < 0) {
                    if (errno == EINTR) {
                        continue;
                    }
                    throw std::runtime_error("getrandom() failed");
                }
                ptr += ret;
                size -= static_cast<size_t>(ret);
            }
        }

#elif defined(__APPLE__)

        inline void fill_random(void *buf, size_t size) {
            if (SecRandomCopyBytes(kSecRandomDefault, size, buf) != errSecSuccess) {
                throw std::runtime_error("SecRandomCopyBytes() failed");
            }
        }

#elif defined(_WIN32)

        inline void fill_random(void *buf, size_t size) {
            NTSTATUS status = BCryptGenRandom(NULL, static_cast<PUCHAR>(buf), static_cast<ULONG>(size),
                                              BCRYPT_USE_SYSTEM_PREFERRED_RNG);
            if (!BCRYPT_SUCCESS(status)) {
                throw std::runtime_error("BCryptGenRandom() failed");
            }
        }

#else

        // Fallback: /dev/urandom
        inline void fill_random(void *buf, size_t size) {
            std::ifstream urandom("/dev/urandom", std::ios::binary);
            if (!urandom) {
                throw std::runtime_error("Failed to open /dev/urandom");
            }
            urandom.read(static_cast<char *>(buf), static_cast<std::streamsize>(size));
            if (!urandom) {
                throw std::runtime_error("Failed to read from /dev/urandom");
            }
        }

#endif

    } // namespace detail

    // Fill buffer with cryptographically secure random bytes
    // This is the replacement for libsodium's randombytes_buf()
    inline void randombytes_buf(void *buf, size_t size) {
        if (size == 0) {
            return;
        }
        detail::fill_random(buf, size);
    }

    // Generate random bytes into a container
    template <typename Container> inline void randombytes(Container &out, size_t size) {
        out.resize(size);
        randombytes_buf(out.data(), size);
    }

} // namespace keylock::crypto::rng
