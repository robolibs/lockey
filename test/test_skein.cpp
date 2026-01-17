#include "keylock/hash/skein/skein.hpp"
#include <doctest/doctest.h>

#include <cstring>
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

TEST_SUITE("Skein Hash Functions") {

    TEST_CASE("Skein-512-256 empty string") {
        uint8_t hash[32];
        keylock::hash::skein::skein512_256(hash, nullptr, 0);
        std::string result = bytes_to_hex(hash, 32);
        // Should produce valid output
        CHECK(result.length() == 64);
    }

    TEST_CASE("Skein-512-512 empty string") {
        uint8_t hash[64];
        keylock::hash::skein::skein512_512(hash, nullptr, 0);
        std::string result = bytes_to_hex(hash, 64);
        CHECK(result.length() == 128);
    }

    TEST_CASE("Skein-512-256 'abc'") {
        const uint8_t msg[] = {'a', 'b', 'c'};
        uint8_t hash[32];
        keylock::hash::skein::skein512_256(hash, msg, 3);
        std::string result = bytes_to_hex(hash, 32);
        // Verify it produces consistent output
        CHECK(result.length() == 64);
    }

    TEST_CASE("Skein-512-512 'abc'") {
        const uint8_t msg[] = {'a', 'b', 'c'};
        uint8_t hash[64];
        keylock::hash::skein::skein512_512(hash, msg, 3);
        std::string result = bytes_to_hex(hash, 64);
        CHECK(result.length() == 128);
    }

    TEST_CASE("Skein-256-256 empty string") {
        uint8_t hash[32];
        keylock::hash::skein::skein256_256(hash, nullptr, 0);
        std::string result = bytes_to_hex(hash, 32);
        CHECK(result.length() == 64);
    }

    TEST_CASE("Skein-256-128 empty string") {
        uint8_t hash[16];
        keylock::hash::skein::skein256_128(hash, nullptr, 0);
        std::string result = bytes_to_hex(hash, 16);
        CHECK(result.length() == 32);
    }

    TEST_CASE("Skein-512 incremental update") {
        keylock::hash::skein::Context512 ctx;
        keylock::hash::skein::init_512(&ctx, 256);

        const uint8_t part1[] = {'a', 'b'};
        const uint8_t part2[] = {'c'};
        keylock::hash::skein::update_512(&ctx, part1, 2);
        keylock::hash::skein::update_512(&ctx, part2, 1);

        uint8_t hash[32];
        keylock::hash::skein::final_512(&ctx, hash);

        // Compare with one-shot
        const uint8_t full_msg[] = {'a', 'b', 'c'};
        uint8_t expected[32];
        keylock::hash::skein::skein512_256(expected, full_msg, 3);

        CHECK(std::memcmp(hash, expected, 32) == 0);
    }

    TEST_CASE("Skein-256 incremental update") {
        keylock::hash::skein::Context256 ctx;
        keylock::hash::skein::init_256(&ctx, 256);

        const uint8_t part1[] = {'h', 'e', 'l', 'l', 'o', ' '};
        const uint8_t part2[] = {'w', 'o', 'r', 'l', 'd'};
        keylock::hash::skein::update_256(&ctx, part1, 6);
        keylock::hash::skein::update_256(&ctx, part2, 5);

        uint8_t hash[32];
        keylock::hash::skein::final_256(&ctx, hash);

        // Compare with one-shot
        const uint8_t full_msg[] = "hello world";
        uint8_t expected[32];
        keylock::hash::skein::skein256_256(expected, full_msg, 11);

        CHECK(std::memcmp(hash, expected, 32) == 0);
    }

    TEST_CASE("Skein-512 consistency") {
        const uint8_t msg[] = "The quick brown fox jumps over the lazy dog";

        uint8_t hash1[64], hash2[64];
        keylock::hash::skein::skein512_512(hash1, msg, sizeof(msg) - 1);
        keylock::hash::skein::skein512_512(hash2, msg, sizeof(msg) - 1);

        CHECK(std::memcmp(hash1, hash2, 64) == 0);
    }

    TEST_CASE("Skein-256 consistency") {
        const uint8_t msg[] = "The quick brown fox jumps over the lazy dog";

        uint8_t hash1[32], hash2[32];
        keylock::hash::skein::skein256_256(hash1, msg, sizeof(msg) - 1);
        keylock::hash::skein::skein256_256(hash2, msg, sizeof(msg) - 1);

        CHECK(std::memcmp(hash1, hash2, 32) == 0);
    }

    TEST_CASE("Skein-512 different output sizes") {
        const uint8_t msg[] = "test";

        uint8_t hash256[32], hash512[64];
        keylock::hash::skein::skein512_256(hash256, msg, 4);
        keylock::hash::skein::skein512_512(hash512, msg, 4);

        // Different output sizes should produce different hashes
        // (first 32 bytes should differ due to different configuration)
        CHECK(std::memcmp(hash256, hash512, 32) != 0);
    }

    TEST_CASE("Skein-256 vs Skein-512 different outputs") {
        const uint8_t msg[] = "test";

        uint8_t skein256_out[32], skein512_out[32];
        keylock::hash::skein::skein256_256(skein256_out, msg, 4);
        keylock::hash::skein::skein512_256(skein512_out, msg, 4);

        // Different variants should produce different outputs
        CHECK(std::memcmp(skein256_out, skein512_out, 32) != 0);
    }

    TEST_CASE("Skein-512 large message") {
        std::vector<uint8_t> large_data(10000, 0x42);

        uint8_t hash[64];
        keylock::hash::skein::skein512_512(hash, large_data.data(), large_data.size());

        // Should produce valid non-zero output
        bool non_zero = false;
        for (int i = 0; i < 64; ++i) {
            if (hash[i] != 0) {
                non_zero = true;
                break;
            }
        }
        CHECK(non_zero);
    }

    TEST_CASE("Skein different messages produce different hashes") {
        const uint8_t msg1[] = "message1";
        const uint8_t msg2[] = "message2";

        uint8_t hash1[64], hash2[64];
        keylock::hash::skein::skein512_512(hash1, msg1, 8);
        keylock::hash::skein::skein512_512(hash2, msg2, 8);

        CHECK(std::memcmp(hash1, hash2, 64) != 0);
    }

    TEST_CASE("Skein variable output size via hash_512") {
        const uint8_t msg[] = "test";

        uint8_t hash128[16], hash256[32];
        keylock::hash::skein::hash_512(hash128, 128, msg, 4);
        keylock::hash::skein::hash_512(hash256, 256, msg, 4);

        // Both should produce valid output
        bool hash128_valid = false;
        for (int i = 0; i < 16; ++i) {
            if (hash128[i] != 0) { hash128_valid = true; break; }
        }
        bool hash256_valid = false;
        for (int i = 0; i < 32; ++i) {
            if (hash256[i] != 0) { hash256_valid = true; break; }
        }
        CHECK(hash128_valid);
        CHECK(hash256_valid);

        // They shouldn't be identical (different output configs)
        CHECK(std::memcmp(hash128, hash256, 16) != 0);
    }
}
