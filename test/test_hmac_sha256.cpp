#include "keylock/hash/hmac/hmac_sha256.hpp"
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

TEST_SUITE("HMAC-SHA256") {

    TEST_CASE("HMAC-SHA256 RFC 4231 Test Vector 1") {
        // Key = 0x0b repeated 20 times
        std::vector<uint8_t> key(20, 0x0b);
        const uint8_t msg[] = "Hi There";

        uint8_t hmac[32];
        keylock::hash::hmac_sha256::hmac(hmac, key.data(), key.size(), msg, 8);

        std::string result = bytes_to_hex(hmac, 32);
        CHECK(result == "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
    }

    TEST_CASE("HMAC-SHA256 RFC 4231 Test Vector 2") {
        // Key = "Jefe"
        const uint8_t key[] = "Jefe";
        const uint8_t msg[] = "what do ya want for nothing?";

        uint8_t hmac[32];
        keylock::hash::hmac_sha256::hmac(hmac, key, 4, msg, 28);

        std::string result = bytes_to_hex(hmac, 32);
        CHECK(result == "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
    }

    TEST_CASE("HMAC-SHA256 RFC 4231 Test Vector 3") {
        // Key = 0xaa repeated 20 times
        std::vector<uint8_t> key(20, 0xaa);
        // Data = 0xdd repeated 50 times
        std::vector<uint8_t> msg(50, 0xdd);

        uint8_t hmac[32];
        keylock::hash::hmac_sha256::hmac(hmac, key.data(), key.size(), msg.data(), msg.size());

        std::string result = bytes_to_hex(hmac, 32);
        CHECK(result == "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe");
    }

    TEST_CASE("HMAC-SHA256 incremental API") {
        std::vector<uint8_t> key(20, 0x0b);
        const uint8_t msg[] = "Hi There";

        keylock::hash::hmac_sha256::Context ctx;
        keylock::hash::hmac_sha256::init(&ctx, key.data(), key.size());
        keylock::hash::hmac_sha256::update(&ctx, msg, 8);

        uint8_t hmac[32];
        keylock::hash::hmac_sha256::final(&ctx, hmac);

        // Should match one-shot
        uint8_t expected[32];
        keylock::hash::hmac_sha256::hmac(expected, key.data(), key.size(), msg, 8);
        CHECK(std::memcmp(hmac, expected, 32) == 0);
    }

    TEST_CASE("HMAC-SHA256 incremental multi-part") {
        const uint8_t key[] = "secret key";
        const uint8_t part1[] = "Hello, ";
        const uint8_t part2[] = "World!";

        keylock::hash::hmac_sha256::Context ctx;
        keylock::hash::hmac_sha256::init(&ctx, key, 10);
        keylock::hash::hmac_sha256::update(&ctx, part1, 7);
        keylock::hash::hmac_sha256::update(&ctx, part2, 6);

        uint8_t hmac[32];
        keylock::hash::hmac_sha256::final(&ctx, hmac);

        // Should match one-shot of full message
        const uint8_t full_msg[] = "Hello, World!";
        uint8_t expected[32];
        keylock::hash::hmac_sha256::hmac(expected, key, 10, full_msg, 13);
        CHECK(std::memcmp(hmac, expected, 32) == 0);
    }

    TEST_CASE("HMAC-SHA256 empty message") {
        const uint8_t key[] = "key";

        uint8_t hmac[32];
        keylock::hash::hmac_sha256::hmac(hmac, key, 3, nullptr, 0);

        std::string result = bytes_to_hex(hmac, 32);
        CHECK(result.length() == 64);
    }

    TEST_CASE("HMAC-SHA256 long key") {
        // Key longer than block size (64 bytes)
        std::vector<uint8_t> long_key(100, 0x42);
        const uint8_t msg[] = "Test message";

        uint8_t hmac[32];
        keylock::hash::hmac_sha256::hmac(hmac, long_key.data(), long_key.size(), msg, 12);

        // Should produce valid output
        std::string result = bytes_to_hex(hmac, 32);
        CHECK(result.length() == 64);
    }

    TEST_CASE("HMAC-SHA256 consistency") {
        const uint8_t key[] = "secret";
        const uint8_t msg[] = "message";

        uint8_t hmac1[32], hmac2[32];
        keylock::hash::hmac_sha256::hmac(hmac1, key, 6, msg, 7);
        keylock::hash::hmac_sha256::hmac(hmac2, key, 6, msg, 7);

        CHECK(std::memcmp(hmac1, hmac2, 32) == 0);
    }

    TEST_CASE("HMAC-SHA256 different keys produce different MACs") {
        const uint8_t key1[] = "key1";
        const uint8_t key2[] = "key2";
        const uint8_t msg[] = "message";

        uint8_t hmac1[32], hmac2[32];
        keylock::hash::hmac_sha256::hmac(hmac1, key1, 4, msg, 7);
        keylock::hash::hmac_sha256::hmac(hmac2, key2, 4, msg, 7);

        CHECK(std::memcmp(hmac1, hmac2, 32) != 0);
    }

    TEST_CASE("HMAC-SHA256 BYTES constant") {
        CHECK(keylock::hash::hmac_sha256::BYTES == 32);
    }
}
