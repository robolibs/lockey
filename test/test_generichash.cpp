#include "keylock/hash/generichash/blake2b_keyed.hpp"
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

TEST_SUITE("Generic Hash (BLAKE2b)") {

    TEST_CASE("generichash one-shot unkeyed") {
        const uint8_t msg[] = "Hello, Generic Hash!";
        uint8_t hash[32];

        keylock::hash::generichash::generichash(hash, msg, sizeof(msg) - 1);

        std::string result = bytes_to_hex(hash, 32);
        CHECK(result.length() == 64);
    }

    TEST_CASE("generichash one-shot keyed") {
        const uint8_t msg[] = "Hello, Keyed Hash!";
        const uint8_t key[] = "secret key here!";
        uint8_t hash[32];

        keylock::hash::generichash::generichash(hash, msg, sizeof(msg) - 1, key, 16);

        std::string result = bytes_to_hex(hash, 32);
        CHECK(result.length() == 64);
    }

    TEST_CASE("generichash variable output size") {
        const uint8_t msg[] = "Test message";

        // Test different output sizes
        uint8_t hash16[16], hash32[32], hash64[64];

        keylock::hash::generichash::hash(hash16, 16, msg, sizeof(msg) - 1);
        keylock::hash::generichash::hash(hash32, 32, msg, sizeof(msg) - 1);
        keylock::hash::generichash::hash(hash64, 64, msg, sizeof(msg) - 1);

        std::string result16 = bytes_to_hex(hash16, 16);
        std::string result32 = bytes_to_hex(hash32, 32);
        std::string result64 = bytes_to_hex(hash64, 64);

        CHECK(result16.length() == 32);
        CHECK(result32.length() == 64);
        CHECK(result64.length() == 128);

        // Different sizes should produce different outputs
        CHECK(result16 != result32.substr(0, 32));
    }

    TEST_CASE("generichash keyed variable output") {
        const uint8_t msg[] = "Test message";
        const uint8_t key[] = "0123456789abcdef0123456789abcdef";

        uint8_t hash16[16], hash32[32], hash64[64];

        keylock::hash::generichash::hash(hash16, 16, msg, sizeof(msg) - 1, key, 32);
        keylock::hash::generichash::hash(hash32, 32, msg, sizeof(msg) - 1, key, 32);
        keylock::hash::generichash::hash(hash64, 64, msg, sizeof(msg) - 1, key, 32);

        std::string result16 = bytes_to_hex(hash16, 16);
        std::string result32 = bytes_to_hex(hash32, 32);
        std::string result64 = bytes_to_hex(hash64, 64);

        CHECK(result16.length() == 32);
        CHECK(result32.length() == 64);
        CHECK(result64.length() == 128);
    }

    TEST_CASE("generichash incremental API unkeyed") {
        const uint8_t msg[] = "Hello, World!";

        keylock::hash::generichash::Context ctx;
        keylock::hash::generichash::init(&ctx, 32);
        keylock::hash::generichash::update(&ctx, msg, sizeof(msg) - 1);
        uint8_t hash[32];
        keylock::hash::generichash::final(&ctx, hash);

        // Compare with one-shot
        uint8_t expected[32];
        keylock::hash::generichash::hash(expected, 32, msg, sizeof(msg) - 1);

        CHECK(std::memcmp(hash, expected, 32) == 0);
    }

    TEST_CASE("generichash incremental API keyed") {
        const uint8_t msg[] = "Hello, World!";
        const uint8_t key[] = "secret key";

        keylock::hash::generichash::Context ctx;
        keylock::hash::generichash::init(&ctx, 32, key, 10);
        keylock::hash::generichash::update(&ctx, msg, sizeof(msg) - 1);
        uint8_t hash[32];
        keylock::hash::generichash::final(&ctx, hash);

        // Compare with one-shot
        uint8_t expected[32];
        keylock::hash::generichash::hash(expected, 32, msg, sizeof(msg) - 1, key, 10);

        CHECK(std::memcmp(hash, expected, 32) == 0);
    }

    TEST_CASE("generichash incremental multi-part") {
        const uint8_t part1[] = "Hello, ";
        const uint8_t part2[] = "World!";
        const uint8_t full_msg[] = "Hello, World!";

        keylock::hash::generichash::Context ctx;
        keylock::hash::generichash::init(&ctx, 32);
        keylock::hash::generichash::update(&ctx, part1, sizeof(part1) - 1);
        keylock::hash::generichash::update(&ctx, part2, sizeof(part2) - 1);
        uint8_t hash[32];
        keylock::hash::generichash::final(&ctx, hash);

        // Compare with one-shot of full message
        uint8_t expected[32];
        keylock::hash::generichash::hash(expected, 32, full_msg, sizeof(full_msg) - 1);

        CHECK(std::memcmp(hash, expected, 32) == 0);
    }

    TEST_CASE("generichash empty message") {
        uint8_t hash[32];
        keylock::hash::generichash::generichash(hash, nullptr, 0);

        std::string result = bytes_to_hex(hash, 32);
        CHECK(result.length() == 64);
    }

    TEST_CASE("generichash consistency") {
        const uint8_t msg[] = "Test consistency";

        uint8_t hash1[32], hash2[32];
        keylock::hash::generichash::generichash(hash1, msg, sizeof(msg) - 1);
        keylock::hash::generichash::generichash(hash2, msg, sizeof(msg) - 1);

        CHECK(std::memcmp(hash1, hash2, 32) == 0);
    }

    TEST_CASE("generichash different messages produce different hashes") {
        const uint8_t msg1[] = "message1";
        const uint8_t msg2[] = "message2";

        uint8_t hash1[32], hash2[32];
        keylock::hash::generichash::generichash(hash1, msg1, sizeof(msg1) - 1);
        keylock::hash::generichash::generichash(hash2, msg2, sizeof(msg2) - 1);

        CHECK(std::memcmp(hash1, hash2, 32) != 0);
    }

    TEST_CASE("generichash different keys produce different hashes") {
        const uint8_t msg[] = "same message";
        const uint8_t key1[] = "key1key1key1key1";
        const uint8_t key2[] = "key2key2key2key2";

        uint8_t hash1[32], hash2[32];
        keylock::hash::generichash::hash(hash1, 32, msg, sizeof(msg) - 1, key1, 16);
        keylock::hash::generichash::hash(hash2, 32, msg, sizeof(msg) - 1, key2, 16);

        CHECK(std::memcmp(hash1, hash2, 32) != 0);
    }

    TEST_CASE("generichash keyed vs unkeyed produce different hashes") {
        const uint8_t msg[] = "test message";
        const uint8_t key[] = "secret key here!";

        uint8_t hash_unkeyed[32], hash_keyed[32];
        keylock::hash::generichash::generichash(hash_unkeyed, msg, sizeof(msg) - 1);
        keylock::hash::generichash::generichash(hash_keyed, msg, sizeof(msg) - 1, key, 16);

        CHECK(std::memcmp(hash_unkeyed, hash_keyed, 32) != 0);
    }

    TEST_CASE("generichash large message") {
        std::vector<uint8_t> msg(100000, 0x42);

        uint8_t hash[32];
        keylock::hash::generichash::hash(hash, 32, msg.data(), msg.size());

        std::string result = bytes_to_hex(hash, 32);
        CHECK(result.length() == 64);
    }

    TEST_CASE("generichash constants") {
        CHECK(keylock::hash::generichash::BYTES == 32);
        CHECK(keylock::hash::generichash::BYTES_MIN == 16);
        CHECK(keylock::hash::generichash::BYTES_MAX == 64);
        CHECK(keylock::hash::generichash::KEYBYTES == 32);
        CHECK(keylock::hash::generichash::KEYBYTES_MIN == 16);
        CHECK(keylock::hash::generichash::KEYBYTES_MAX == 64);
    }
}
