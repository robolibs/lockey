#include "keylock/hash/hkdf/hkdf_sha256.hpp"
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

TEST_SUITE("HKDF-SHA256") {

    TEST_CASE("HKDF-SHA256 RFC 5869 Test Case 1") {
        // IKM = 0x0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b (22 octets)
        std::vector<uint8_t> ikm(22, 0x0b);
        // Salt = 0x000102030405060708090a0b0c (13 octets)
        auto salt = hex_to_bytes("000102030405060708090a0b0c");
        // Info = 0xf0f1f2f3f4f5f6f7f8f9 (10 octets)
        auto info = hex_to_bytes("f0f1f2f3f4f5f6f7f8f9");
        // L = 42

        uint8_t okm[42];
        keylock::hash::hkdf_sha256::hkdf(okm, sizeof(okm), ikm.data(), ikm.size(), salt.data(), salt.size(), info.data(),
                                         info.size());

        std::string result = bytes_to_hex(okm, sizeof(okm));
        CHECK(result == "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865");
    }

    TEST_CASE("HKDF-SHA256 RFC 5869 Test Case 2") {
        // Longer inputs
        auto ikm = hex_to_bytes(
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30313233343536"
            "3738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f");
        auto salt = hex_to_bytes(
            "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495"
            "969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf");
        auto info = hex_to_bytes(
            "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5"
            "e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");

        uint8_t okm[82];
        keylock::hash::hkdf_sha256::hkdf(okm, sizeof(okm), ikm.data(), ikm.size(), salt.data(), salt.size(), info.data(),
                                         info.size());

        std::string result = bytes_to_hex(okm, sizeof(okm));
        CHECK(result ==
              "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f"
              "09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87");
    }

    TEST_CASE("HKDF-SHA256 RFC 5869 Test Case 3 (zero-length salt and info)") {
        std::vector<uint8_t> ikm(22, 0x0b);

        uint8_t okm[42];
        keylock::hash::hkdf_sha256::hkdf(okm, sizeof(okm), ikm.data(), ikm.size(), nullptr, 0, nullptr, 0);

        std::string result = bytes_to_hex(okm, sizeof(okm));
        CHECK(result == "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8");
    }

    TEST_CASE("HKDF-SHA256 extract only") {
        std::vector<uint8_t> ikm(22, 0x0b);
        auto salt = hex_to_bytes("000102030405060708090a0b0c");

        uint8_t prk[32];
        keylock::hash::hkdf_sha256::extract(prk, salt.data(), salt.size(), ikm.data(), ikm.size());

        std::string result = bytes_to_hex(prk, sizeof(prk));
        CHECK(result == "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5");
    }

    TEST_CASE("HKDF-SHA256 expand only") {
        auto prk = hex_to_bytes("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5");
        auto info = hex_to_bytes("f0f1f2f3f4f5f6f7f8f9");

        uint8_t okm[42];
        keylock::hash::hkdf_sha256::expand(okm, sizeof(okm), prk.data(), prk.size(), info.data(), info.size());

        std::string result = bytes_to_hex(okm, sizeof(okm));
        CHECK(result == "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865");
    }

    TEST_CASE("HKDF-SHA256 small output") {
        std::vector<uint8_t> ikm(16, 0x42);

        uint8_t okm[16];
        keylock::hash::hkdf_sha256::hkdf(okm, sizeof(okm), ikm.data(), ikm.size(), nullptr, 0, nullptr, 0);

        std::string result = bytes_to_hex(okm, sizeof(okm));
        CHECK(result.length() == 32);
    }

    TEST_CASE("HKDF-SHA256 large output (multiple blocks)") {
        std::vector<uint8_t> ikm(32, 0xaa);

        uint8_t okm[128];
        keylock::hash::hkdf_sha256::hkdf(okm, sizeof(okm), ikm.data(), ikm.size(), nullptr, 0, nullptr, 0);

        std::string result = bytes_to_hex(okm, sizeof(okm));
        CHECK(result.length() == 256);
    }

    TEST_CASE("HKDF-SHA256 consistency") {
        std::vector<uint8_t> ikm(32, 0x55);
        std::vector<uint8_t> salt(16, 0x66);
        std::vector<uint8_t> info(10, 0x77);

        uint8_t okm1[64], okm2[64];
        keylock::hash::hkdf_sha256::hkdf(okm1, sizeof(okm1), ikm.data(), ikm.size(), salt.data(), salt.size(),
                                         info.data(), info.size());
        keylock::hash::hkdf_sha256::hkdf(okm2, sizeof(okm2), ikm.data(), ikm.size(), salt.data(), salt.size(),
                                         info.data(), info.size());

        CHECK(std::memcmp(okm1, okm2, sizeof(okm1)) == 0);
    }

    TEST_CASE("HKDF-SHA256 different IKM produces different output") {
        std::vector<uint8_t> ikm1(32, 0x11);
        std::vector<uint8_t> ikm2(32, 0x22);

        uint8_t okm1[32], okm2[32];
        keylock::hash::hkdf_sha256::hkdf(okm1, sizeof(okm1), ikm1.data(), ikm1.size(), nullptr, 0, nullptr, 0);
        keylock::hash::hkdf_sha256::hkdf(okm2, sizeof(okm2), ikm2.data(), ikm2.size(), nullptr, 0, nullptr, 0);

        CHECK(std::memcmp(okm1, okm2, sizeof(okm1)) != 0);
    }
}
