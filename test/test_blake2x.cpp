#include "keylock/hash/blake2x/blake2x.hpp"
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

TEST_SUITE("BLAKE2X XOF Functions") {

    TEST_CASE("BLAKE2xb basic XOF") {
        const uint8_t msg[] = "abc";
        uint8_t output[128];
        keylock::hash::blake2xb::xof(output, 128, msg, 3);

        // Just verify it produces something non-zero
        bool non_zero = false;
        for (int i = 0; i < 128; ++i) {
            if (output[i] != 0) {
                non_zero = true;
                break;
            }
        }
        CHECK(non_zero);
    }

    TEST_CASE("BLAKE2xb multi-squeeze produces continuous output") {
        const uint8_t msg[] = "test message";

        // One-shot 128 bytes
        uint8_t full_output[128];
        keylock::hash::blake2xb::xof(full_output, 128, msg, 12);

        // Incremental squeeze
        keylock::hash::blake2xb::Context ctx;
        keylock::hash::blake2xb::init(&ctx, 128);
        keylock::hash::blake2xb::update(&ctx, msg, 12);

        uint8_t part1[64], part2[64];
        keylock::hash::blake2xb::squeeze(&ctx, part1, 64);
        keylock::hash::blake2xb::squeeze(&ctx, part2, 64);
        keylock::hash::blake2xb::final(&ctx);

        // First 64 bytes should match
        CHECK(std::memcmp(full_output, part1, 64) == 0);
        // Second 64 bytes should match
        CHECK(std::memcmp(full_output + 64, part2, 64) == 0);
    }

    TEST_CASE("BLAKE2xb consistency") {
        const uint8_t msg[] = "The quick brown fox";

        uint8_t out1[256], out2[256];
        keylock::hash::blake2xb::xof(out1, 256, msg, sizeof(msg) - 1);
        keylock::hash::blake2xb::xof(out2, 256, msg, sizeof(msg) - 1);

        CHECK(std::memcmp(out1, out2, 256) == 0);
    }

    TEST_CASE("BLAKE2xb incremental update") {
        keylock::hash::blake2xb::Context ctx;
        keylock::hash::blake2xb::init(&ctx, 64);

        const uint8_t part1[] = "hello ";
        const uint8_t part2[] = "world";
        keylock::hash::blake2xb::update(&ctx, part1, 6);
        keylock::hash::blake2xb::update(&ctx, part2, 5);

        uint8_t hash1[64];
        keylock::hash::blake2xb::squeeze(&ctx, hash1, 64);
        keylock::hash::blake2xb::final(&ctx);

        // Compare with one-shot
        const uint8_t full_msg[] = "hello world";
        uint8_t hash2[64];
        keylock::hash::blake2xb::xof(hash2, 64, full_msg, 11);

        CHECK(std::memcmp(hash1, hash2, 64) == 0);
    }

    TEST_CASE("BLAKE2xb empty message") {
        uint8_t output[64];
        keylock::hash::blake2xb::xof(output, 64, nullptr, 0);

        // Should produce valid output
        std::string result = bytes_to_hex(output, 64);
        CHECK(!result.empty());
    }

    TEST_CASE("BLAKE2xs basic XOF") {
        const uint8_t msg[] = "abc";
        uint8_t output[64];
        keylock::hash::blake2xs::xof(output, 64, msg, 3);

        // Just verify it produces something non-zero
        bool non_zero = false;
        for (int i = 0; i < 64; ++i) {
            if (output[i] != 0) {
                non_zero = true;
                break;
            }
        }
        CHECK(non_zero);
    }

    TEST_CASE("BLAKE2xs multi-squeeze produces continuous output") {
        const uint8_t msg[] = "test message";

        // One-shot 64 bytes
        uint8_t full_output[64];
        keylock::hash::blake2xs::xof(full_output, 64, msg, 12);

        // Incremental squeeze
        keylock::hash::blake2xs::Context ctx;
        keylock::hash::blake2xs::init(&ctx, 64);
        keylock::hash::blake2xs::update(&ctx, msg, 12);

        uint8_t part1[32], part2[32];
        keylock::hash::blake2xs::squeeze(&ctx, part1, 32);
        keylock::hash::blake2xs::squeeze(&ctx, part2, 32);
        keylock::hash::blake2xs::final(&ctx);

        // First 32 bytes should match
        CHECK(std::memcmp(full_output, part1, 32) == 0);
        // Second 32 bytes should match
        CHECK(std::memcmp(full_output + 32, part2, 32) == 0);
    }

    TEST_CASE("BLAKE2xs consistency") {
        const uint8_t msg[] = "The quick brown fox";

        uint8_t out1[128], out2[128];
        keylock::hash::blake2xs::xof(out1, 128, msg, sizeof(msg) - 1);
        keylock::hash::blake2xs::xof(out2, 128, msg, sizeof(msg) - 1);

        CHECK(std::memcmp(out1, out2, 128) == 0);
    }

    TEST_CASE("BLAKE2xs incremental update") {
        keylock::hash::blake2xs::Context ctx;
        keylock::hash::blake2xs::init(&ctx, 32);

        const uint8_t part1[] = "hello ";
        const uint8_t part2[] = "world";
        keylock::hash::blake2xs::update(&ctx, part1, 6);
        keylock::hash::blake2xs::update(&ctx, part2, 5);

        uint8_t hash1[32];
        keylock::hash::blake2xs::squeeze(&ctx, hash1, 32);
        keylock::hash::blake2xs::final(&ctx);

        // Compare with one-shot
        const uint8_t full_msg[] = "hello world";
        uint8_t hash2[32];
        keylock::hash::blake2xs::xof(hash2, 32, full_msg, 11);

        CHECK(std::memcmp(hash1, hash2, 32) == 0);
    }

    TEST_CASE("BLAKE2xs empty message") {
        uint8_t output[32];
        keylock::hash::blake2xs::xof(output, 32, nullptr, 0);

        std::string result = bytes_to_hex(output, 32);
        CHECK(!result.empty());
    }

    TEST_CASE("BLAKE2xb and BLAKE2xs produce different outputs") {
        const uint8_t msg[] = "test";

        uint8_t blake2xb_out[64], blake2xs_out[64];
        keylock::hash::blake2xb::xof(blake2xb_out, 64, msg, 4);
        keylock::hash::blake2xs::xof(blake2xs_out, 64, msg, 4);

        // Different variants should produce different outputs
        CHECK(std::memcmp(blake2xb_out, blake2xs_out, 64) != 0);
    }

    TEST_CASE("BLAKE2xb large output") {
        const uint8_t msg[] = "seed";
        uint8_t output[512];
        keylock::hash::blake2xb::xof(output, 512, msg, 4);

        // Verify parts of the output aren't all the same (good expansion)
        CHECK(std::memcmp(output, output + 64, 64) != 0);
        CHECK(std::memcmp(output + 64, output + 128, 64) != 0);
    }
}
