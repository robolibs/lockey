#include "keylock/hash/sha512/sha512.hpp"
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

TEST_SUITE("SHA-512 Hash Function") {

    TEST_CASE("SHA-512 empty string") {
        uint8_t hash[64];
        keylock::hash::sha512::hash(hash, nullptr, 0);
        std::string result = bytes_to_hex(hash, 64);
        // NIST test vector
        CHECK(result == "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e");
    }

    TEST_CASE("SHA-512 'abc'") {
        const uint8_t msg[] = {'a', 'b', 'c'};
        uint8_t hash[64];
        keylock::hash::sha512::hash(hash, msg, 3);
        std::string result = bytes_to_hex(hash, 64);
        // NIST test vector
        CHECK(result == "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f");
    }

    TEST_CASE("SHA-512 longer message") {
        // "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"
        const uint8_t msg[] = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
        uint8_t hash[64];
        keylock::hash::sha512::hash(hash, msg, 112);
        std::string result = bytes_to_hex(hash, 64);
        // NIST test vector
        CHECK(result == "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909");
    }

    TEST_CASE("SHA-512 incremental update") {
        keylock::hash::sha512::Context ctx;
        keylock::hash::sha512::init(&ctx);

        const uint8_t part1[] = {'a', 'b'};
        const uint8_t part2[] = {'c'};
        keylock::hash::sha512::update(&ctx, part1, 2);
        keylock::hash::sha512::update(&ctx, part2, 1);

        uint8_t hash[64];
        keylock::hash::sha512::final(&ctx, hash);

        // Should match SHA-512("abc")
        uint8_t expected[64];
        const uint8_t full_msg[] = {'a', 'b', 'c'};
        keylock::hash::sha512::hash(expected, full_msg, 3);

        CHECK(std::memcmp(hash, expected, 64) == 0);
    }

    TEST_CASE("SHA-512 incremental multi-block") {
        keylock::hash::sha512::Context ctx;
        keylock::hash::sha512::init(&ctx);

        std::vector<uint8_t> part1(100, 'a');
        std::vector<uint8_t> part2(100, 'b');
        std::vector<uint8_t> part3(100, 'c');

        keylock::hash::sha512::update(&ctx, part1.data(), part1.size());
        keylock::hash::sha512::update(&ctx, part2.data(), part2.size());
        keylock::hash::sha512::update(&ctx, part3.data(), part3.size());

        uint8_t hash1[64];
        keylock::hash::sha512::final(&ctx, hash1);

        // Compare with one-shot
        std::vector<uint8_t> full_msg;
        full_msg.insert(full_msg.end(), part1.begin(), part1.end());
        full_msg.insert(full_msg.end(), part2.begin(), part2.end());
        full_msg.insert(full_msg.end(), part3.begin(), part3.end());

        uint8_t hash2[64];
        keylock::hash::sha512::hash(hash2, full_msg.data(), full_msg.size());

        CHECK(std::memcmp(hash1, hash2, 64) == 0);
    }

    TEST_CASE("SHA-512 consistency") {
        const uint8_t msg[] = "The quick brown fox jumps over the lazy dog";

        uint8_t hash1[64], hash2[64];
        keylock::hash::sha512::hash(hash1, msg, sizeof(msg) - 1);
        keylock::hash::sha512::hash(hash2, msg, sizeof(msg) - 1);

        CHECK(std::memcmp(hash1, hash2, 64) == 0);
    }

    TEST_CASE("SHA-512 different messages produce different hashes") {
        const uint8_t msg1[] = "message1";
        const uint8_t msg2[] = "message2";

        uint8_t hash1[64], hash2[64];
        keylock::hash::sha512::hash(hash1, msg1, 8);
        keylock::hash::sha512::hash(hash2, msg2, 8);

        CHECK(std::memcmp(hash1, hash2, 64) != 0);
    }

    TEST_CASE("SHA-512 large message") {
        std::vector<uint8_t> large_data(100000, 0x61);

        uint8_t hash[64];
        keylock::hash::sha512::hash(hash, large_data.data(), large_data.size());

        bool non_zero = false;
        for (int i = 0; i < 64; ++i) {
            if (hash[i] != 0) {
                non_zero = true;
                break;
            }
        }
        CHECK(non_zero);
    }

    TEST_CASE("SHA-512 BYTES constant") {
        CHECK(keylock::hash::sha512::BYTES == 64);
    }
}
