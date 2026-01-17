#pragma once

// Constant-time comparison functions
// Replaces libsodium's crypto_verify16/32/64

#include <cstddef>
#include <cstdint>

namespace keylock::crypto::constant_time {

    namespace detail {

        // Constant-time XOR of two buffers, returns OR of all XOR results
        inline uint64_t xor_bytes(const uint8_t *a, const uint8_t *b, size_t size) {
            uint64_t diff = 0;
            for (size_t i = 0; i < size; ++i) {
                diff |= static_cast<uint64_t>(a[i] ^ b[i]);
            }
            return diff;
        }

        // Convert non-zero to -1, zero to 0 in constant time
        inline int neq0(uint64_t diff) {
            // If diff != 0, return -1; else return 0
            // This works by checking if the high bit propagates
            uint64_t half = (diff >> 32) | static_cast<uint32_t>(diff);
            return static_cast<int>((1 & ((half - 1) >> 32)) - 1);
        }

    } // namespace detail

    // Compare 16 bytes in constant time
    // Returns 0 if equal, -1 otherwise
    inline int verify16(const uint8_t a[16], const uint8_t b[16]) {
        uint64_t diff = 0;
        for (int i = 0; i < 16; i += 8) {
            uint64_t va = 0, vb = 0;
            for (int j = 0; j < 8; ++j) {
                va |= static_cast<uint64_t>(a[i + j]) << (j * 8);
                vb |= static_cast<uint64_t>(b[i + j]) << (j * 8);
            }
            diff |= va ^ vb;
        }
        return detail::neq0(diff);
    }

    // Compare 32 bytes in constant time
    // Returns 0 if equal, -1 otherwise
    inline int verify32(const uint8_t a[32], const uint8_t b[32]) {
        uint64_t diff = 0;
        for (int i = 0; i < 32; i += 8) {
            uint64_t va = 0, vb = 0;
            for (int j = 0; j < 8; ++j) {
                va |= static_cast<uint64_t>(a[i + j]) << (j * 8);
                vb |= static_cast<uint64_t>(b[i + j]) << (j * 8);
            }
            diff |= va ^ vb;
        }
        return detail::neq0(diff);
    }

    // Compare 64 bytes in constant time
    // Returns 0 if equal, -1 otherwise
    inline int verify64(const uint8_t a[64], const uint8_t b[64]) {
        uint64_t diff = 0;
        for (int i = 0; i < 64; i += 8) {
            uint64_t va = 0, vb = 0;
            for (int j = 0; j < 8; ++j) {
                va |= static_cast<uint64_t>(a[i + j]) << (j * 8);
                vb |= static_cast<uint64_t>(b[i + j]) << (j * 8);
            }
            diff |= va ^ vb;
        }
        return detail::neq0(diff);
    }

    // Generic constant-time comparison for arbitrary size
    // Returns 0 if equal, -1 otherwise
    inline int verify(const uint8_t *a, const uint8_t *b, size_t size) {
        return detail::neq0(detail::xor_bytes(a, b, size));
    }

    // Constant-time comparison returning bool
    inline bool secure_compare(const uint8_t *a, const uint8_t *b, size_t size) { return verify(a, b, size) == 0; }

} // namespace keylock::crypto::constant_time
