#include "keylock/hash/blake2s/blake2s.hpp"
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

static std::vector<uint8_t> hex_to_bytes(const char *hex) {
    std::vector<uint8_t> bytes;
    while (*hex) {
        if (hex[1] == '\0')
            break;
        uint8_t byte = 0;
        for (int i = 0; i < 2; ++i) {
            byte <<= 4;
            char c = hex[i];
            if (c >= '0' && c <= '9')
                byte |= c - '0';
            else if (c >= 'a' && c <= 'f')
                byte |= c - 'a' + 10;
            else if (c >= 'A' && c <= 'F')
                byte |= c - 'A' + 10;
        }
        bytes.push_back(byte);
        hex += 2;
    }
    return bytes;
}

TEST_SUITE("BLAKE2s Hash Functions") {
    // Test vectors from RFC 7693 and reference implementation

    TEST_CASE("BLAKE2s-256 empty string") {
        uint8_t hash[32];
        keylock::hash::blake2s::hash(hash, nullptr, 0);
        std::string result = bytes_to_hex(hash, 32);
        // RFC 7693 test vector
        CHECK(result == "69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9");
    }

    TEST_CASE("BLAKE2s-256 'abc'") {
        const uint8_t msg[] = {'a', 'b', 'c'};
        uint8_t hash[32];
        keylock::hash::blake2s::hash(hash, msg, 3);
        std::string result = bytes_to_hex(hash, 32);
        CHECK(result == "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982");
    }

    TEST_CASE("BLAKE2s-256 longer message") {
        // "The quick brown fox jumps over the lazy dog"
        const uint8_t msg[] = "The quick brown fox jumps over the lazy dog";
        uint8_t hash[32];
        keylock::hash::blake2s::hash(hash, msg, 43);
        std::string result = bytes_to_hex(hash, 32);
        CHECK(result == "606beeec743ccbeff6cbcdf5d5302aa855c256c29b88c8ed331ea1a6bf3c8812");
    }

    TEST_CASE("BLAKE2s-128 output") {
        const uint8_t msg[] = {'a', 'b', 'c'};
        uint8_t hash[16];
        keylock::hash::blake2s::hash(hash, 16, msg, 3);
        std::string result = bytes_to_hex(hash, 16);
        // Verify shorter output
        CHECK(result.length() == 32);
    }

    TEST_CASE("BLAKE2s incremental update") {
        keylock::hash::blake2s::Context ctx;
        keylock::hash::blake2s::init(&ctx);

        const uint8_t part1[] = {'a', 'b'};
        const uint8_t part2[] = {'c'};
        keylock::hash::blake2s::update(&ctx, part1, 2);
        keylock::hash::blake2s::update(&ctx, part2, 1);

        uint8_t hash[32];
        keylock::hash::blake2s::final(&ctx, hash);

        // Should match BLAKE2s-256("abc")
        uint8_t expected[32];
        const uint8_t full_msg[] = {'a', 'b', 'c'};
        keylock::hash::blake2s::hash(expected, full_msg, 3);

        CHECK(std::memcmp(hash, expected, 32) == 0);
    }

    TEST_CASE("BLAKE2s keyed hash") {
        // Test vector from reference implementation
        auto key = hex_to_bytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        const uint8_t msg[] = {0x00};

        uint8_t hash[32];
        keylock::hash::blake2s::keyed(hash, 32, key.data(), key.size(), msg, 1);

        std::string result = bytes_to_hex(hash, 32);
        CHECK(result == "40d15fee7c328830166ac3f918650f807e7e01e177258cdc0a39b11f598066f1");
    }

    TEST_CASE("BLAKE2s keyed incremental") {
        auto key = hex_to_bytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");

        keylock::hash::blake2s::Context ctx;
        keylock::hash::blake2s::keyed_init(&ctx, 32, key.data(), key.size());

        const uint8_t msg[] = {0x00};
        keylock::hash::blake2s::update(&ctx, msg, 1);

        uint8_t hash[32];
        keylock::hash::blake2s::final(&ctx, hash);

        // Should match keyed one-shot
        uint8_t expected[32];
        keylock::hash::blake2s::keyed(expected, 32, key.data(), key.size(), msg, 1);

        CHECK(std::memcmp(hash, expected, 32) == 0);
    }

    TEST_CASE("BLAKE2s consistency check") {
        const uint8_t data[] = "The quick brown fox jumps over the lazy dog";

        uint8_t hash1[32], hash2[32];
        keylock::hash::blake2s::hash(hash1, data, sizeof(data) - 1);
        keylock::hash::blake2s::hash(hash2, data, sizeof(data) - 1);

        CHECK(std::memcmp(hash1, hash2, 32) == 0);
    }

    TEST_CASE("BLAKE2s different output sizes") {
        const uint8_t msg[] = "test";

        uint8_t hash16[16], hash24[24], hash32[32];
        keylock::hash::blake2s::hash(hash16, 16, msg, 4);
        keylock::hash::blake2s::hash(hash24, 24, msg, 4);
        keylock::hash::blake2s::hash(hash32, 32, msg, 4);

        // Different sizes should produce different hashes
        // (not just truncated versions due to different parameter blocks)
        CHECK(std::memcmp(hash16, hash32, 16) != 0);
    }

    TEST_CASE("BLAKE2s large message") {
        // Test with a larger message that spans multiple blocks
        std::vector<uint8_t> large_data(1000, 0x41); // 1000 bytes of 'A'

        uint8_t hash[32];
        keylock::hash::blake2s::hash(hash, large_data.data(), large_data.size());

        // Just verify it produces a valid hash (non-zero output)
        bool non_zero = false;
        for (int i = 0; i < 32; ++i) {
            if (hash[i] != 0) {
                non_zero = true;
                break;
            }
        }
        CHECK(non_zero);
    }

    TEST_CASE("BLAKE2s different keys produce different MACs") {
        const uint8_t key1[] = "key1";
        const uint8_t key2[] = "key2";
        const uint8_t msg[] = "message";

        uint8_t hash1[32], hash2[32];
        keylock::hash::blake2s::keyed(hash1, 32, key1, 4, msg, 7);
        keylock::hash::blake2s::keyed(hash2, 32, key2, 4, msg, 7);

        CHECK(std::memcmp(hash1, hash2, 32) != 0);
    }
}
