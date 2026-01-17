#include "keylock/hash/legacy/sm3.hpp"
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

TEST_SUITE("SM3 Hash Function") {
    // Test vectors from GB/T 32905-2016 (Chinese national standard)

    TEST_CASE("SM3 empty string") {
        uint8_t hash[32];
        keylock::hash::sm3::hash(hash, nullptr, 0);
        std::string result = bytes_to_hex(hash, 32);
        // SM3("")
        CHECK(result == "1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b");
    }

    TEST_CASE("SM3 'abc'") {
        const uint8_t msg[] = {'a', 'b', 'c'};
        uint8_t hash[32];
        keylock::hash::sm3::hash(hash, msg, 3);
        std::string result = bytes_to_hex(hash, 32);
        // SM3("abc") from GB/T 32905-2016 example
        CHECK(result == "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0");
    }

    TEST_CASE("SM3 longer message") {
        // "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd" (64 bytes)
        const uint8_t msg[] = "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd";
        uint8_t hash[32];
        keylock::hash::sm3::hash(hash, msg, 64);
        std::string result = bytes_to_hex(hash, 32);
        // GB/T 32905-2016 example 2
        CHECK(result == "debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732");
    }

    TEST_CASE("SM3 incremental update") {
        keylock::hash::sm3::Context ctx;
        keylock::hash::sm3::init(&ctx);

        const uint8_t part1[] = {'a', 'b'};
        const uint8_t part2[] = {'c'};
        keylock::hash::sm3::update(&ctx, part1, 2);
        keylock::hash::sm3::update(&ctx, part2, 1);

        uint8_t hash[32];
        keylock::hash::sm3::final(&ctx, hash);

        // Compare with one-shot
        const uint8_t full_msg[] = {'a', 'b', 'c'};
        uint8_t expected[32];
        keylock::hash::sm3::hash(expected, full_msg, 3);

        CHECK(std::memcmp(hash, expected, 32) == 0);
    }

    TEST_CASE("SM3 consistency") {
        const uint8_t msg[] = "The quick brown fox jumps over the lazy dog";

        uint8_t hash1[32], hash2[32];
        keylock::hash::sm3::hash(hash1, msg, sizeof(msg) - 1);
        keylock::hash::sm3::hash(hash2, msg, sizeof(msg) - 1);

        CHECK(std::memcmp(hash1, hash2, 32) == 0);
    }

    TEST_CASE("SM3 large message") {
        // Test with message spanning multiple blocks
        std::vector<uint8_t> large_data(1000, 0x61); // 1000 bytes of 'a'

        uint8_t hash[32];
        keylock::hash::sm3::hash(hash, large_data.data(), large_data.size());

        // Should produce valid non-zero output
        bool non_zero = false;
        for (int i = 0; i < 32; ++i) {
            if (hash[i] != 0) {
                non_zero = true;
                break;
            }
        }
        CHECK(non_zero);
    }

    TEST_CASE("SM3 different messages produce different hashes") {
        const uint8_t msg1[] = "message1";
        const uint8_t msg2[] = "message2";

        uint8_t hash1[32], hash2[32];
        keylock::hash::sm3::hash(hash1, msg1, 8);
        keylock::hash::sm3::hash(hash2, msg2, 8);

        CHECK(std::memcmp(hash1, hash2, 32) != 0);
    }

    TEST_CASE("SM3 incremental multi-block") {
        // Build up message in parts, spanning block boundaries
        keylock::hash::sm3::Context ctx;
        keylock::hash::sm3::init(&ctx);

        // SM3 block size is 64 bytes
        std::vector<uint8_t> part1(50, 'a');
        std::vector<uint8_t> part2(50, 'b');
        std::vector<uint8_t> part3(50, 'c');

        keylock::hash::sm3::update(&ctx, part1.data(), part1.size());
        keylock::hash::sm3::update(&ctx, part2.data(), part2.size());
        keylock::hash::sm3::update(&ctx, part3.data(), part3.size());

        uint8_t hash1[32];
        keylock::hash::sm3::final(&ctx, hash1);

        // Compare with one-shot
        std::vector<uint8_t> full_msg;
        full_msg.insert(full_msg.end(), part1.begin(), part1.end());
        full_msg.insert(full_msg.end(), part2.begin(), part2.end());
        full_msg.insert(full_msg.end(), part3.begin(), part3.end());

        uint8_t hash2[32];
        keylock::hash::sm3::hash(hash2, full_msg.data(), full_msg.size());

        CHECK(std::memcmp(hash1, hash2, 32) == 0);
    }
}
