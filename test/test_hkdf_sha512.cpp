#include "keylock/hash/hkdf/hkdf_sha512.hpp"
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

TEST_SUITE("HKDF-SHA512") {

    TEST_CASE("HKDF-SHA512 basic derivation") {
        std::vector<uint8_t> ikm(22, 0x0b);
        auto salt = hex_to_bytes("000102030405060708090a0b0c");
        auto info = hex_to_bytes("f0f1f2f3f4f5f6f7f8f9");

        uint8_t okm[42];
        keylock::hash::hkdf_sha512::hkdf(okm, sizeof(okm), ikm.data(), ikm.size(), salt.data(), salt.size(), info.data(),
                                         info.size());

        std::string result = bytes_to_hex(okm, sizeof(okm));
        CHECK(result.length() == 84);
    }

    TEST_CASE("HKDF-SHA512 zero-length salt and info") {
        std::vector<uint8_t> ikm(22, 0x0b);

        uint8_t okm[42];
        keylock::hash::hkdf_sha512::hkdf(okm, sizeof(okm), ikm.data(), ikm.size(), nullptr, 0, nullptr, 0);

        std::string result = bytes_to_hex(okm, sizeof(okm));
        CHECK(result.length() == 84);
    }

    TEST_CASE("HKDF-SHA512 extract only") {
        std::vector<uint8_t> ikm(22, 0x0b);
        auto salt = hex_to_bytes("000102030405060708090a0b0c");

        uint8_t prk[64];
        keylock::hash::hkdf_sha512::extract(prk, salt.data(), salt.size(), ikm.data(), ikm.size());

        std::string result = bytes_to_hex(prk, sizeof(prk));
        CHECK(result.length() == 128);
    }

    TEST_CASE("HKDF-SHA512 expand only") {
        std::vector<uint8_t> prk(64, 0xaa);
        auto info = hex_to_bytes("f0f1f2f3f4f5f6f7f8f9");

        uint8_t okm[42];
        keylock::hash::hkdf_sha512::expand(okm, sizeof(okm), prk.data(), prk.size(), info.data(), info.size());

        std::string result = bytes_to_hex(okm, sizeof(okm));
        CHECK(result.length() == 84);
    }

    TEST_CASE("HKDF-SHA512 small output") {
        std::vector<uint8_t> ikm(16, 0x42);

        uint8_t okm[16];
        keylock::hash::hkdf_sha512::hkdf(okm, sizeof(okm), ikm.data(), ikm.size(), nullptr, 0, nullptr, 0);

        std::string result = bytes_to_hex(okm, sizeof(okm));
        CHECK(result.length() == 32);
    }

    TEST_CASE("HKDF-SHA512 large output (multiple blocks)") {
        std::vector<uint8_t> ikm(32, 0xaa);

        uint8_t okm[256];
        keylock::hash::hkdf_sha512::hkdf(okm, sizeof(okm), ikm.data(), ikm.size(), nullptr, 0, nullptr, 0);

        std::string result = bytes_to_hex(okm, sizeof(okm));
        CHECK(result.length() == 512);
    }

    TEST_CASE("HKDF-SHA512 consistency") {
        std::vector<uint8_t> ikm(32, 0x55);
        std::vector<uint8_t> salt(16, 0x66);
        std::vector<uint8_t> info(10, 0x77);

        uint8_t okm1[128], okm2[128];
        keylock::hash::hkdf_sha512::hkdf(okm1, sizeof(okm1), ikm.data(), ikm.size(), salt.data(), salt.size(),
                                         info.data(), info.size());
        keylock::hash::hkdf_sha512::hkdf(okm2, sizeof(okm2), ikm.data(), ikm.size(), salt.data(), salt.size(),
                                         info.data(), info.size());

        CHECK(std::memcmp(okm1, okm2, sizeof(okm1)) == 0);
    }

    TEST_CASE("HKDF-SHA512 different IKM produces different output") {
        std::vector<uint8_t> ikm1(32, 0x11);
        std::vector<uint8_t> ikm2(32, 0x22);

        uint8_t okm1[64], okm2[64];
        keylock::hash::hkdf_sha512::hkdf(okm1, sizeof(okm1), ikm1.data(), ikm1.size(), nullptr, 0, nullptr, 0);
        keylock::hash::hkdf_sha512::hkdf(okm2, sizeof(okm2), ikm2.data(), ikm2.size(), nullptr, 0, nullptr, 0);

        CHECK(std::memcmp(okm1, okm2, sizeof(okm1)) != 0);
    }

    TEST_CASE("HKDF-SHA512 different salt produces different output") {
        std::vector<uint8_t> ikm(32, 0xaa);
        std::vector<uint8_t> salt1(16, 0x11);
        std::vector<uint8_t> salt2(16, 0x22);

        uint8_t okm1[64], okm2[64];
        keylock::hash::hkdf_sha512::hkdf(okm1, sizeof(okm1), ikm.data(), ikm.size(), salt1.data(), salt1.size(), nullptr,
                                         0);
        keylock::hash::hkdf_sha512::hkdf(okm2, sizeof(okm2), ikm.data(), ikm.size(), salt2.data(), salt2.size(), nullptr,
                                         0);

        CHECK(std::memcmp(okm1, okm2, sizeof(okm1)) != 0);
    }

    TEST_CASE("HKDF-SHA512 different info produces different output") {
        std::vector<uint8_t> ikm(32, 0xaa);
        std::vector<uint8_t> info1(10, 0x11);
        std::vector<uint8_t> info2(10, 0x22);

        uint8_t okm1[64], okm2[64];
        keylock::hash::hkdf_sha512::hkdf(okm1, sizeof(okm1), ikm.data(), ikm.size(), nullptr, 0, info1.data(),
                                         info1.size());
        keylock::hash::hkdf_sha512::hkdf(okm2, sizeof(okm2), ikm.data(), ikm.size(), nullptr, 0, info2.data(),
                                         info2.size());

        CHECK(std::memcmp(okm1, okm2, sizeof(okm1)) != 0);
    }
}
