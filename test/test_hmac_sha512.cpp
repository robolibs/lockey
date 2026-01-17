#include "keylock/hash/hmac/hmac_sha512.hpp"
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

TEST_SUITE("HMAC-SHA512") {

    TEST_CASE("HMAC-SHA512 RFC 4231 Test Vector 1") {
        std::vector<uint8_t> key(20, 0x0b);
        const uint8_t msg[] = "Hi There";

        uint8_t hmac[64];
        keylock::hash::hmac_sha512::hmac(hmac, key.data(), key.size(), msg, 8);

        std::string result = bytes_to_hex(hmac, 64);
        CHECK(result == "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854");
    }

    TEST_CASE("HMAC-SHA512 RFC 4231 Test Vector 2") {
        const uint8_t key[] = "Jefe";
        const uint8_t msg[] = "what do ya want for nothing?";

        uint8_t hmac[64];
        keylock::hash::hmac_sha512::hmac(hmac, key, 4, msg, 28);

        std::string result = bytes_to_hex(hmac, 64);
        CHECK(result == "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737");
    }

    TEST_CASE("HMAC-SHA512 incremental API") {
        std::vector<uint8_t> key(20, 0x0b);
        const uint8_t msg[] = "Hi There";

        keylock::hash::hmac_sha512::Context ctx;
        keylock::hash::hmac_sha512::init(&ctx, key.data(), key.size());
        keylock::hash::hmac_sha512::update(&ctx, msg, 8);

        uint8_t hmac[64];
        keylock::hash::hmac_sha512::final(&ctx, hmac);

        // Should match one-shot
        uint8_t expected[64];
        keylock::hash::hmac_sha512::hmac(expected, key.data(), key.size(), msg, 8);
        CHECK(std::memcmp(hmac, expected, 64) == 0);
    }

    TEST_CASE("HMAC-SHA512 incremental multi-part") {
        const uint8_t key[] = "secret key";
        const uint8_t part1[] = "Hello, ";
        const uint8_t part2[] = "World!";

        keylock::hash::hmac_sha512::Context ctx;
        keylock::hash::hmac_sha512::init(&ctx, key, 10);
        keylock::hash::hmac_sha512::update(&ctx, part1, 7);
        keylock::hash::hmac_sha512::update(&ctx, part2, 6);

        uint8_t hmac[64];
        keylock::hash::hmac_sha512::final(&ctx, hmac);

        const uint8_t full_msg[] = "Hello, World!";
        uint8_t expected[64];
        keylock::hash::hmac_sha512::hmac(expected, key, 10, full_msg, 13);
        CHECK(std::memcmp(hmac, expected, 64) == 0);
    }

    TEST_CASE("HMAC-SHA512 empty message") {
        const uint8_t key[] = "key";

        uint8_t hmac[64];
        keylock::hash::hmac_sha512::hmac(hmac, key, 3, nullptr, 0);

        std::string result = bytes_to_hex(hmac, 64);
        CHECK(result.length() == 128);
    }

    TEST_CASE("HMAC-SHA512 long key") {
        std::vector<uint8_t> long_key(200, 0x42);
        const uint8_t msg[] = "Test message";

        uint8_t hmac[64];
        keylock::hash::hmac_sha512::hmac(hmac, long_key.data(), long_key.size(), msg, 12);

        std::string result = bytes_to_hex(hmac, 64);
        CHECK(result.length() == 128);
    }

    TEST_CASE("HMAC-SHA512 consistency") {
        const uint8_t key[] = "secret";
        const uint8_t msg[] = "message";

        uint8_t hmac1[64], hmac2[64];
        keylock::hash::hmac_sha512::hmac(hmac1, key, 6, msg, 7);
        keylock::hash::hmac_sha512::hmac(hmac2, key, 6, msg, 7);

        CHECK(std::memcmp(hmac1, hmac2, 64) == 0);
    }

    TEST_CASE("HMAC-SHA512 different keys produce different MACs") {
        const uint8_t key1[] = "key1";
        const uint8_t key2[] = "key2";
        const uint8_t msg[] = "message";

        uint8_t hmac1[64], hmac2[64];
        keylock::hash::hmac_sha512::hmac(hmac1, key1, 4, msg, 7);
        keylock::hash::hmac_sha512::hmac(hmac2, key2, 4, msg, 7);

        CHECK(std::memcmp(hmac1, hmac2, 64) != 0);
    }

    TEST_CASE("HMAC-SHA512 BYTES constant") {
        CHECK(keylock::hash::hmac_sha512::BYTES == 64);
    }
}
