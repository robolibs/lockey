#include "keylock/hash/shake/shake.hpp"
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

TEST_SUITE("SHAKE XOF Functions") {
    // Test vectors from NIST CAVP and SP 800-185

    TEST_CASE("SHAKE128 empty string 32 bytes") {
        uint8_t output[32];
        keylock::hash::shake::shake128(output, 32, nullptr, 0);
        std::string result = bytes_to_hex(output, 32);
        // NIST test vector for SHAKE128("", 256 bits)
        CHECK(result == "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26");
    }

    TEST_CASE("SHAKE256 empty string 64 bytes") {
        uint8_t output[64];
        keylock::hash::shake::shake256(output, 64, nullptr, 0);
        std::string result = bytes_to_hex(output, 64);
        // NIST test vector for SHAKE256("", 512 bits)
        CHECK(result == "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762fd75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be");
    }

    TEST_CASE("SHAKE128 'abc' 32 bytes") {
        const uint8_t msg[] = {'a', 'b', 'c'};
        uint8_t output[32];
        keylock::hash::shake::shake128(output, 32, msg, 3);
        std::string result = bytes_to_hex(output, 32);
        CHECK(result == "5881092dd818bf5cf8a3ddb793fbcba74097d5c526a6d35f97b83351940f2cc8");
    }

    TEST_CASE("SHAKE256 'abc' 64 bytes") {
        const uint8_t msg[] = {'a', 'b', 'c'};
        uint8_t output[64];
        keylock::hash::shake::shake256(output, 64, msg, 3);
        std::string result = bytes_to_hex(output, 64);
        CHECK(result == "483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739d5a15bef186a5386c75744c0527e1faa9f8726e462a12a4feb06bd8801e751e4");
    }

    TEST_CASE("SHAKE128 incremental update") {
        keylock::hash::shake::Context ctx;
        keylock::hash::shake::init_128(&ctx);

        const uint8_t part1[] = {'a', 'b'};
        const uint8_t part2[] = {'c'};
        keylock::hash::shake::update(&ctx, part1, 2);
        keylock::hash::shake::update(&ctx, part2, 1);

        uint8_t output[32];
        keylock::hash::shake::squeeze(&ctx, output, 32);
        keylock::hash::shake::final(&ctx);

        std::string result = bytes_to_hex(output, 32);
        // Should match SHAKE128("abc", 256 bits)
        CHECK(result == "5881092dd818bf5cf8a3ddb793fbcba74097d5c526a6d35f97b83351940f2cc8");
    }

    TEST_CASE("SHAKE256 multi-squeeze") {
        keylock::hash::shake::Context ctx;
        keylock::hash::shake::init_256(&ctx);

        const uint8_t msg[] = {'a', 'b', 'c'};
        keylock::hash::shake::update(&ctx, msg, 3);

        // Squeeze in multiple calls
        uint8_t output1[32], output2[32];
        keylock::hash::shake::squeeze(&ctx, output1, 32);
        keylock::hash::shake::squeeze(&ctx, output2, 32);
        keylock::hash::shake::final(&ctx);

        // Concatenate and compare with one-shot 64-byte output
        uint8_t combined[64];
        std::memcpy(combined, output1, 32);
        std::memcpy(combined + 32, output2, 32);

        uint8_t expected[64];
        keylock::hash::shake::shake256(expected, 64, msg, 3);

        CHECK(std::memcmp(combined, expected, 64) == 0);
    }

    TEST_CASE("SHAKE128 variable output length") {
        const uint8_t msg[] = "test";

        // Different output sizes should produce different prefixes
        uint8_t out16[16], out32[32], out64[64];
        keylock::hash::shake::shake128(out16, 16, msg, 4);
        keylock::hash::shake::shake128(out32, 32, msg, 4);
        keylock::hash::shake::shake128(out64, 64, msg, 4);

        // First 16 bytes should be identical
        CHECK(std::memcmp(out16, out32, 16) == 0);
        CHECK(std::memcmp(out16, out64, 16) == 0);
        CHECK(std::memcmp(out32, out64, 32) == 0);
    }

    TEST_CASE("cSHAKE128 with customization") {
        // NIST SP 800-185 test vector
        // cSHAKE128(X=0x00010203, L=256, N="", S="Email Signature")
        const uint8_t data[] = {0x00, 0x01, 0x02, 0x03};
        const uint8_t *N = nullptr;
        const uint8_t S[] = "Email Signature";

        uint8_t output[32];
        keylock::hash::shake::cshake128(output, 32, N, 0, S, 15, data, 4);
        std::string result = bytes_to_hex(output, 32);

        CHECK(result == "c1c36925b6409a04f1b504fcbca9d82b4017277cb5ed2b2065fc1d3814d5aaf5");
    }

    TEST_CASE("cSHAKE256 with customization") {
        // NIST SP 800-185 test vector
        const uint8_t data[] = {0x00, 0x01, 0x02, 0x03};
        const uint8_t *N = nullptr;
        const uint8_t S[] = "Email Signature";

        uint8_t output[64];
        keylock::hash::shake::cshake256(output, 64, N, 0, S, 15, data, 4);
        std::string result = bytes_to_hex(output, 64);

        CHECK(result == "d008828e2b80ac9d2218ffee1d070c48b8e4c87bff32c9699d5b6896eee0edd164020e2be0560858d9c00c037e34a96937c561a74c412bb4c746469527281c8c");
    }

    TEST_CASE("cSHAKE128 empty customization falls back to SHAKE128") {
        const uint8_t msg[] = "test";

        uint8_t shake_out[32], cshake_out[32];
        keylock::hash::shake::shake128(shake_out, 32, msg, 4);
        keylock::hash::shake::cshake128(cshake_out, 32, nullptr, 0, nullptr, 0, msg, 4);

        // When N="" and S="", cSHAKE should be identical to SHAKE
        CHECK(std::memcmp(shake_out, cshake_out, 32) == 0);
    }

    TEST_CASE("cSHAKE256 empty customization falls back to SHAKE256") {
        const uint8_t msg[] = "test";

        uint8_t shake_out[64], cshake_out[64];
        keylock::hash::shake::shake256(shake_out, 64, msg, 4);
        keylock::hash::shake::cshake256(cshake_out, 64, nullptr, 0, nullptr, 0, msg, 4);

        CHECK(std::memcmp(shake_out, cshake_out, 64) == 0);
    }

    TEST_CASE("SHAKE consistency") {
        const uint8_t data[] = "The quick brown fox jumps over the lazy dog";

        uint8_t out1[128], out2[128];
        keylock::hash::shake::shake256(out1, 128, data, sizeof(data) - 1);
        keylock::hash::shake::shake256(out2, 128, data, sizeof(data) - 1);

        CHECK(std::memcmp(out1, out2, 128) == 0);
    }
}
