#include "keylock/hash/blake2b/blake2b.hpp"
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

TEST_SUITE("BLAKE2b Hash Function") {

    TEST_CASE("BLAKE2b-512 empty string") {
        uint8_t hash[64];
        keylock::hash::blake2b::hash(hash, 64, nullptr, 0);
        std::string result = bytes_to_hex(hash, 64);
        // RFC 7693 test vector
        CHECK(result == "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce");
    }

    TEST_CASE("BLAKE2b-512 'abc'") {
        const uint8_t msg[] = {'a', 'b', 'c'};
        uint8_t hash[64];
        keylock::hash::blake2b::hash(hash, 64, msg, 3);
        std::string result = bytes_to_hex(hash, 64);
        // RFC 7693 test vector
        CHECK(result == "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923");
    }

    TEST_CASE("BLAKE2b-256 output") {
        const uint8_t msg[] = {'a', 'b', 'c'};
        uint8_t hash[32];
        keylock::hash::blake2b::hash(hash, 32, msg, 3);
        std::string result = bytes_to_hex(hash, 32);
        CHECK(result.length() == 64);
    }

    TEST_CASE("BLAKE2b incremental update") {
        keylock::hash::blake2b::Context ctx;
        keylock::hash::blake2b::init(&ctx, 64);

        const uint8_t part1[] = {'a', 'b'};
        const uint8_t part2[] = {'c'};
        keylock::hash::blake2b::update(&ctx, part1, 2);
        keylock::hash::blake2b::update(&ctx, part2, 1);

        uint8_t hash[64];
        keylock::hash::blake2b::final(&ctx, hash);

        // Should match BLAKE2b-512("abc")
        uint8_t expected[64];
        const uint8_t full_msg[] = {'a', 'b', 'c'};
        keylock::hash::blake2b::hash(expected, 64, full_msg, 3);

        CHECK(std::memcmp(hash, expected, 64) == 0);
    }

    TEST_CASE("BLAKE2b keyed hash") {
        auto key = hex_to_bytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f");
        const uint8_t msg[] = {0x00};

        uint8_t hash[64];
        keylock::hash::blake2b::keyed(hash, 64, key.data(), key.size(), msg, 1);

        std::string result = bytes_to_hex(hash, 64);
        // RFC 7693 keyed test vector
        CHECK(result == "961f6dd1e4dd30f63901690c512e78e4b45e4742ed197c3c5e45c549fd25f2e4187b0bc9fe30492b16b0d0bc4ef9b0f34c7003fac09a5ef1532e69430234cebd");
    }

    TEST_CASE("BLAKE2b keyed incremental") {
        auto key = hex_to_bytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f");

        keylock::hash::blake2b::Context ctx;
        keylock::hash::blake2b::keyed_init(&ctx, 64, key.data(), key.size());

        const uint8_t msg[] = {0x00};
        keylock::hash::blake2b::update(&ctx, msg, 1);

        uint8_t hash[64];
        keylock::hash::blake2b::final(&ctx, hash);

        // Should match keyed one-shot
        uint8_t expected[64];
        keylock::hash::blake2b::keyed(expected, 64, key.data(), key.size(), msg, 1);

        CHECK(std::memcmp(hash, expected, 64) == 0);
    }

    TEST_CASE("BLAKE2b consistency") {
        const uint8_t msg[] = "The quick brown fox jumps over the lazy dog";

        uint8_t hash1[64], hash2[64];
        keylock::hash::blake2b::hash(hash1, 64, msg, sizeof(msg) - 1);
        keylock::hash::blake2b::hash(hash2, 64, msg, sizeof(msg) - 1);

        CHECK(std::memcmp(hash1, hash2, 64) == 0);
    }

    TEST_CASE("BLAKE2b different output sizes") {
        const uint8_t msg[] = "test";

        uint8_t hash32[32], hash48[48], hash64[64];
        keylock::hash::blake2b::hash(hash32, 32, msg, 4);
        keylock::hash::blake2b::hash(hash48, 48, msg, 4);
        keylock::hash::blake2b::hash(hash64, 64, msg, 4);

        // Different sizes should produce different hashes
        CHECK(std::memcmp(hash32, hash64, 32) != 0);
    }

    TEST_CASE("BLAKE2b large message") {
        std::vector<uint8_t> large_data(100000, 0x41);

        uint8_t hash[64];
        keylock::hash::blake2b::hash(hash, 64, large_data.data(), large_data.size());

        bool non_zero = false;
        for (int i = 0; i < 64; ++i) {
            if (hash[i] != 0) {
                non_zero = true;
                break;
            }
        }
        CHECK(non_zero);
    }

    TEST_CASE("BLAKE2b different keys produce different MACs") {
        const uint8_t key1[] = "key1key1key1key1";
        const uint8_t key2[] = "key2key2key2key2";
        const uint8_t msg[] = "message";

        uint8_t hash1[64], hash2[64];
        keylock::hash::blake2b::keyed(hash1, 64, key1, 16, msg, 7);
        keylock::hash::blake2b::keyed(hash2, 64, key2, 16, msg, 7);

        CHECK(std::memcmp(hash1, hash2, 64) != 0);
    }
}
