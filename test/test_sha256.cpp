#include "keylock/hash/sha256/sha256.hpp"
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

TEST_SUITE("SHA-256 Hash Function") {

    TEST_CASE("SHA-256 empty string") {
        uint8_t hash[32];
        keylock::hash::sha256::hash(hash, nullptr, 0);
        std::string result = bytes_to_hex(hash, 32);
        // NIST test vector
        CHECK(result == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    }

    TEST_CASE("SHA-256 'abc'") {
        const uint8_t msg[] = {'a', 'b', 'c'};
        uint8_t hash[32];
        keylock::hash::sha256::hash(hash, msg, 3);
        std::string result = bytes_to_hex(hash, 32);
        // NIST test vector
        CHECK(result == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    }

    TEST_CASE("SHA-256 longer message") {
        // "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
        const uint8_t msg[] = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
        uint8_t hash[32];
        keylock::hash::sha256::hash(hash, msg, 56);
        std::string result = bytes_to_hex(hash, 32);
        // NIST test vector
        CHECK(result == "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
    }

    TEST_CASE("SHA-256 incremental update") {
        keylock::hash::sha256::Context ctx;
        keylock::hash::sha256::init(&ctx);

        const uint8_t part1[] = {'a', 'b'};
        const uint8_t part2[] = {'c'};
        keylock::hash::sha256::update(&ctx, part1, 2);
        keylock::hash::sha256::update(&ctx, part2, 1);

        uint8_t hash[32];
        keylock::hash::sha256::final(&ctx, hash);

        // Should match SHA-256("abc")
        uint8_t expected[32];
        const uint8_t full_msg[] = {'a', 'b', 'c'};
        keylock::hash::sha256::hash(expected, full_msg, 3);

        CHECK(std::memcmp(hash, expected, 32) == 0);
    }

    TEST_CASE("SHA-256 incremental multi-block") {
        keylock::hash::sha256::Context ctx;
        keylock::hash::sha256::init(&ctx);

        // Process message in parts crossing block boundaries
        std::vector<uint8_t> part1(50, 'a');
        std::vector<uint8_t> part2(50, 'b');
        std::vector<uint8_t> part3(50, 'c');

        keylock::hash::sha256::update(&ctx, part1.data(), part1.size());
        keylock::hash::sha256::update(&ctx, part2.data(), part2.size());
        keylock::hash::sha256::update(&ctx, part3.data(), part3.size());

        uint8_t hash1[32];
        keylock::hash::sha256::final(&ctx, hash1);

        // Compare with one-shot
        std::vector<uint8_t> full_msg;
        full_msg.insert(full_msg.end(), part1.begin(), part1.end());
        full_msg.insert(full_msg.end(), part2.begin(), part2.end());
        full_msg.insert(full_msg.end(), part3.begin(), part3.end());

        uint8_t hash2[32];
        keylock::hash::sha256::hash(hash2, full_msg.data(), full_msg.size());

        CHECK(std::memcmp(hash1, hash2, 32) == 0);
    }

    TEST_CASE("SHA-256 consistency") {
        const uint8_t msg[] = "The quick brown fox jumps over the lazy dog";

        uint8_t hash1[32], hash2[32];
        keylock::hash::sha256::hash(hash1, msg, sizeof(msg) - 1);
        keylock::hash::sha256::hash(hash2, msg, sizeof(msg) - 1);

        CHECK(std::memcmp(hash1, hash2, 32) == 0);
    }

    TEST_CASE("SHA-256 different messages produce different hashes") {
        const uint8_t msg1[] = "message1";
        const uint8_t msg2[] = "message2";

        uint8_t hash1[32], hash2[32];
        keylock::hash::sha256::hash(hash1, msg1, 8);
        keylock::hash::sha256::hash(hash2, msg2, 8);

        CHECK(std::memcmp(hash1, hash2, 32) != 0);
    }

    TEST_CASE("SHA-256 large message") {
        std::vector<uint8_t> large_data(100000, 0x61); // 100KB of 'a'

        uint8_t hash[32];
        keylock::hash::sha256::hash(hash, large_data.data(), large_data.size());

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

    TEST_CASE("SHA-256 BYTES constant") {
        CHECK(keylock::hash::sha256::BYTES == 32);
    }
}
