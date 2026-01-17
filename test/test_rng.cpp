#include "keylock/crypto/rng/randombytes.hpp"
#include <doctest/doctest.h>

#include <cstring>
#include <set>
#include <string>
#include <vector>

static std::string bytes_to_hex(const uint8_t *data, size_t len) {
    static const char hex_chars[] = "0123456789abcdef";
    std::string result;
    result.reserve(len * 2);
    for (size_t i = 0; i < len; ++i) {
        result += hex_chars[(data[i] >> 4) & 0xf];
        result += hex_chars[data[i] & 0xf];
    }
    return result;
}

TEST_SUITE("Random Number Generation") {

    TEST_CASE("randombytes_buf fills buffer") {
        uint8_t buf[32] = {0};
        keylock::crypto::rng::randombytes_buf(buf, sizeof(buf));

        // Should produce non-zero output (extremely unlikely to be all zeros)
        bool non_zero = false;
        for (size_t i = 0; i < sizeof(buf); ++i) {
            if (buf[i] != 0) {
                non_zero = true;
                break;
            }
        }
        CHECK(non_zero);
    }

    TEST_CASE("randombytes produces different outputs") {
        uint8_t buf1[32], buf2[32];
        keylock::crypto::rng::randombytes_buf(buf1, sizeof(buf1));
        keylock::crypto::rng::randombytes_buf(buf2, sizeof(buf2));

        // Should be different (extremely unlikely to be same)
        CHECK(std::memcmp(buf1, buf2, 32) != 0);
    }

    TEST_CASE("randombytes various sizes") {
        // Test various buffer sizes
        std::vector<size_t> sizes = {1, 7, 16, 32, 64, 128, 256, 1024};

        for (size_t size : sizes) {
            std::vector<uint8_t> buf(size, 0);
            keylock::crypto::rng::randombytes_buf(buf.data(), buf.size());

            // For sizes > 1, should have at least some non-zero bytes
            if (size > 1) {
                bool non_zero = false;
                for (size_t i = 0; i < size; ++i) {
                    if (buf[i] != 0) {
                        non_zero = true;
                        break;
                    }
                }
                CHECK(non_zero);
            }
        }
    }

    TEST_CASE("randombytes distribution check") {
        // Generate many random bytes and check for reasonable distribution
        std::vector<uint8_t> buf(10000);
        keylock::crypto::rng::randombytes_buf(buf.data(), buf.size());

        // Count occurrences of each byte value
        int counts[256] = {0};
        for (size_t i = 0; i < buf.size(); ++i) {
            counts[buf[i]]++;
        }

        // Each value should appear at least once with 10000 bytes
        // (probability of any value never appearing is negligible)
        int zero_count = 0;
        for (int i = 0; i < 256; ++i) {
            if (counts[i] == 0) {
                zero_count++;
            }
        }
        // Allow some values to be missing but not too many
        CHECK(zero_count < 50);
    }

    TEST_CASE("randombytes uniqueness test") {
        // Generate many 32-byte values and check they're all unique
        std::set<std::string> values;
        for (int i = 0; i < 100; ++i) {
            uint8_t buf[32];
            keylock::crypto::rng::randombytes_buf(buf, sizeof(buf));
            std::string hex = bytes_to_hex(buf, 32);
            values.insert(hex);
        }
        // All 100 values should be unique
        CHECK(values.size() == 100);
    }

    TEST_CASE("randombytes container function") {
        std::vector<uint8_t> buf;
        keylock::crypto::rng::randombytes(buf, 16);

        CHECK(buf.size() == 16);
        // Should produce non-zero output
        bool non_zero = false;
        for (size_t i = 0; i < buf.size(); ++i) {
            if (buf[i] != 0) {
                non_zero = true;
                break;
            }
        }
        CHECK(non_zero);
    }

    TEST_CASE("randombytes zero size") {
        // Should handle zero size gracefully
        uint8_t dummy = 0x42;
        keylock::crypto::rng::randombytes_buf(&dummy, 0);
        // Should not crash and dummy should be unchanged
        CHECK(dummy == 0x42);
    }
}
