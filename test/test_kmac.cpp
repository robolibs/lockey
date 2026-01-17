#include "keylock/hash/kmac/kmac.hpp"
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

TEST_SUITE("KMAC Functions") {
    // Test vectors from NIST SP 800-185

    TEST_CASE("KMAC128 basic test") {
        // NIST SP 800-185 test vector
        // KMAC128(K, X, L, S)
        // K = 404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f
        // X = 00010203
        // L = 256
        // S = ""
        auto key = hex_to_bytes("404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f");
        const uint8_t data[] = {0x00, 0x01, 0x02, 0x03};

        uint8_t mac[32];
        keylock::hash::kmac::kmac128(mac, 32, key.data(), key.size(), nullptr, 0, data, 4);

        std::string result = bytes_to_hex(mac, 32);
        CHECK(result == "e5780b0d3ea6f7d3a429c5706aa43a00fadbd7d49628839e3187243f456ee14e");
    }

    TEST_CASE("KMAC128 with customization string") {
        // NIST SP 800-185 test vector
        // K = 404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f
        // X = 00010203
        // L = 256
        // S = "My Tagged Application"
        auto key = hex_to_bytes("404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f");
        const uint8_t data[] = {0x00, 0x01, 0x02, 0x03};
        const uint8_t S[] = "My Tagged Application";

        uint8_t mac[32];
        keylock::hash::kmac::kmac128(mac, 32, key.data(), key.size(), S, 21, data, 4);

        std::string result = bytes_to_hex(mac, 32);
        CHECK(result == "3b1fba963cd8b0b59e8c1a6d71888b7143651af8ba0a7070c0979e2811324aa5");
    }

    TEST_CASE("KMAC256 basic test") {
        // NIST SP 800-185 test vector
        // K = 404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f
        // X = 00010203
        // L = 512
        // S = "My Tagged Application"
        auto key = hex_to_bytes("404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f");
        const uint8_t data[] = {0x00, 0x01, 0x02, 0x03};
        const uint8_t S[] = "My Tagged Application";

        uint8_t mac[64];
        keylock::hash::kmac::kmac256(mac, 64, key.data(), key.size(), S, 21, data, 4);

        std::string result = bytes_to_hex(mac, 64);
        CHECK(result == "20c570c31346f703c9ac36c61c03cb64c3970d0cfc787e9b79599d273a68d2f7f69d4cc3de9d104a351689f27cf6f5951f0103f33f4f24871024d9c27773a8dd");
    }

    TEST_CASE("KMAC128 incremental update") {
        auto key = hex_to_bytes("404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f");

        keylock::hash::kmac::Context ctx;
        keylock::hash::kmac::init_128(&ctx, key.data(), key.size(), nullptr, 0, 32);

        const uint8_t part1[] = {0x00, 0x01};
        const uint8_t part2[] = {0x02, 0x03};
        keylock::hash::kmac::update(&ctx, part1, 2);
        keylock::hash::kmac::update(&ctx, part2, 2);

        uint8_t mac[32];
        keylock::hash::kmac::final(&ctx, mac);

        // Should match one-shot KMAC128 with 0x00010203
        const uint8_t full_data[] = {0x00, 0x01, 0x02, 0x03};
        uint8_t expected[32];
        keylock::hash::kmac::kmac128(expected, 32, key.data(), key.size(), nullptr, 0, full_data, 4);

        CHECK(std::memcmp(mac, expected, 32) == 0);
    }

    TEST_CASE("KMAC256 incremental update") {
        auto key = hex_to_bytes("404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f");
        const uint8_t S[] = "My Tagged Application";

        keylock::hash::kmac::Context ctx;
        keylock::hash::kmac::init_256(&ctx, key.data(), key.size(), S, 21, 64);

        const uint8_t part1[] = {0x00, 0x01};
        const uint8_t part2[] = {0x02, 0x03};
        keylock::hash::kmac::update(&ctx, part1, 2);
        keylock::hash::kmac::update(&ctx, part2, 2);

        uint8_t mac[64];
        keylock::hash::kmac::final(&ctx, mac);

        std::string result = bytes_to_hex(mac, 64);
        CHECK(result == "20c570c31346f703c9ac36c61c03cb64c3970d0cfc787e9b79599d273a68d2f7f69d4cc3de9d104a351689f27cf6f5951f0103f33f4f24871024d9c27773a8dd");
    }

    TEST_CASE("KMAC128 XOF mode") {
        auto key = hex_to_bytes("404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f");
        const uint8_t data[] = {0x00, 0x01, 0x02, 0x03};

        keylock::hash::kmac::Context ctx;
        keylock::hash::kmac::init_128(&ctx, key.data(), key.size(), nullptr, 0, 0); // XOF mode

        keylock::hash::kmac::update(&ctx, data, 4);

        // Squeeze multiple times
        uint8_t out1[32], out2[32];
        keylock::hash::kmac::squeeze(&ctx, out1, 32);
        keylock::hash::kmac::squeeze(&ctx, out2, 32);
        keylock::hash::kmac::final_xof(&ctx);

        // Outputs should be different (continuation of stream)
        CHECK(std::memcmp(out1, out2, 32) != 0);
    }

    TEST_CASE("KMAC consistency check") {
        const uint8_t key[] = "secretkey";
        const uint8_t data[] = "The quick brown fox jumps over the lazy dog";

        uint8_t mac1[32], mac2[32];
        keylock::hash::kmac::kmac128(mac1, 32, key, 9, data, sizeof(data) - 1);
        keylock::hash::kmac::kmac128(mac2, 32, key, 9, data, sizeof(data) - 1);

        CHECK(std::memcmp(mac1, mac2, 32) == 0);
    }

    TEST_CASE("KMAC different keys produce different MACs") {
        const uint8_t key1[] = "key1";
        const uint8_t key2[] = "key2";
        const uint8_t data[] = "test data";

        uint8_t mac1[32], mac2[32];
        keylock::hash::kmac::kmac128(mac1, 32, key1, 4, data, sizeof(data) - 1);
        keylock::hash::kmac::kmac128(mac2, 32, key2, 4, data, sizeof(data) - 1);

        CHECK(std::memcmp(mac1, mac2, 32) != 0);
    }

    TEST_CASE("KMAC different customization strings produce different MACs") {
        const uint8_t key[] = "key";
        const uint8_t data[] = "data";
        const uint8_t S1[] = "app1";
        const uint8_t S2[] = "app2";

        uint8_t mac1[32], mac2[32];
        keylock::hash::kmac::kmac128(mac1, 32, key, 3, S1, 4, data, 4);
        keylock::hash::kmac::kmac128(mac2, 32, key, 3, S2, 4, data, 4);

        CHECK(std::memcmp(mac1, mac2, 32) != 0);
    }
}
