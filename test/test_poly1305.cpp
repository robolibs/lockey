#include "keylock/crypto/poly1305/poly1305.hpp"
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

TEST_SUITE("Poly1305 MAC") {

    TEST_CASE("Poly1305 one-shot MAC") {
        // RFC 8439 test vector
        auto key = hex_to_bytes("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b");
        const uint8_t msg[] = "Cryptographic Forum Research Group";

        uint8_t mac[16];
        keylock::crypto::poly1305::poly1305(mac, msg, sizeof(msg) - 1, key.data());

        std::string result = bytes_to_hex(mac, 16);
        CHECK(result == "a8061dc1305136c6c22b8baf0c0127a9");
    }

    TEST_CASE("Poly1305 incremental API") {
        auto key = hex_to_bytes("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b");
        const uint8_t msg[] = "Cryptographic Forum Research Group";

        keylock::crypto::poly1305::Context ctx;
        keylock::crypto::poly1305::init(&ctx, key.data());
        keylock::crypto::poly1305::update(&ctx, msg, sizeof(msg) - 1);

        uint8_t mac[16];
        keylock::crypto::poly1305::final(&ctx, mac);

        // Should match one-shot result
        uint8_t expected[16];
        keylock::crypto::poly1305::poly1305(expected, msg, sizeof(msg) - 1, key.data());
        CHECK(std::memcmp(mac, expected, 16) == 0);
    }

    TEST_CASE("Poly1305 incremental multi-part") {
        auto key = hex_to_bytes("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b");
        const uint8_t part1[] = "Cryptographic ";
        const uint8_t part2[] = "Forum Research Group";

        keylock::crypto::poly1305::Context ctx;
        keylock::crypto::poly1305::init(&ctx, key.data());
        keylock::crypto::poly1305::update(&ctx, part1, 14);
        keylock::crypto::poly1305::update(&ctx, part2, 20);

        uint8_t mac[16];
        keylock::crypto::poly1305::final(&ctx, mac);

        // Should match full message
        const uint8_t full_msg[] = "Cryptographic Forum Research Group";
        uint8_t expected[16];
        keylock::crypto::poly1305::poly1305(expected, full_msg, sizeof(full_msg) - 1, key.data());
        CHECK(std::memcmp(mac, expected, 16) == 0);
    }

    TEST_CASE("Poly1305 empty message") {
        auto key = hex_to_bytes("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b");

        uint8_t mac[16];
        keylock::crypto::poly1305::poly1305(mac, nullptr, 0, key.data());

        // Should produce valid non-crash output
        std::string result = bytes_to_hex(mac, 16);
        CHECK(result.length() == 32);
    }

    TEST_CASE("Poly1305 consistency") {
        auto key = hex_to_bytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        const uint8_t msg[] = "Test message";

        uint8_t mac1[16], mac2[16];
        keylock::crypto::poly1305::poly1305(mac1, msg, sizeof(msg) - 1, key.data());
        keylock::crypto::poly1305::poly1305(mac2, msg, sizeof(msg) - 1, key.data());

        CHECK(std::memcmp(mac1, mac2, 16) == 0);
    }

    TEST_CASE("Poly1305 different keys produce different MACs") {
        auto key1 = hex_to_bytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        auto key2 = hex_to_bytes("1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100");
        const uint8_t msg[] = "Test message";

        uint8_t mac1[16], mac2[16];
        keylock::crypto::poly1305::poly1305(mac1, msg, sizeof(msg) - 1, key1.data());
        keylock::crypto::poly1305::poly1305(mac2, msg, sizeof(msg) - 1, key2.data());

        CHECK(std::memcmp(mac1, mac2, 16) != 0);
    }

    TEST_CASE("Poly1305 different messages produce different MACs") {
        auto key = hex_to_bytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        const uint8_t msg1[] = "Message 1";
        const uint8_t msg2[] = "Message 2";

        uint8_t mac1[16], mac2[16];
        keylock::crypto::poly1305::poly1305(mac1, msg1, sizeof(msg1) - 1, key.data());
        keylock::crypto::poly1305::poly1305(mac2, msg2, sizeof(msg2) - 1, key.data());

        CHECK(std::memcmp(mac1, mac2, 16) != 0);
    }

    TEST_CASE("Poly1305 large message") {
        auto key = hex_to_bytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        std::vector<uint8_t> large_msg(10000, 0x42);

        uint8_t mac[16];
        keylock::crypto::poly1305::poly1305(mac, large_msg.data(), large_msg.size(), key.data());

        // Verify valid output
        bool non_zero = false;
        for (int i = 0; i < 16; ++i) {
            if (mac[i] != 0) {
                non_zero = true;
                break;
            }
        }
        CHECK(non_zero);
    }
}
