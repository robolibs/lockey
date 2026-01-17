#include "keylock/hash/algorithms.hpp"
#include <doctest/doctest.h>

TEST_SUITE("HKDF Functions") {
    // RFC 5869 Test Vector 1 (SHA-256)
    // IKM  = 0x0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b (22 octets)
    // salt = 0x000102030405060708090a0b0c (13 octets)
    // info = 0xf0f1f2f3f4f5f6f7f8f9 (10 octets)
    // L    = 42

    const std::vector<uint8_t> rfc5869_ikm = {0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
                                              0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
                                              0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b};

    const std::vector<uint8_t> rfc5869_salt = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
                                               0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c};

    const std::vector<uint8_t> rfc5869_info = {0xf0, 0xf1, 0xf2, 0xf3, 0xf4,
                                               0xf5, 0xf6, 0xf7, 0xf8, 0xf9};

    // Expected PRK from RFC 5869 Test Vector 1
    const std::vector<uint8_t> rfc5869_prk = {0x07, 0x77, 0x09, 0x36, 0x2c, 0x2e, 0x32, 0xdf,
                                              0x0d, 0xdc, 0x3f, 0x0d, 0xc4, 0x7b, 0xba, 0x63,
                                              0x90, 0xb6, 0xc7, 0x3b, 0xb5, 0x0f, 0x9c, 0x31,
                                              0x22, 0xec, 0x84, 0x4a, 0xd7, 0xc2, 0xb3, 0xe5};

    // Expected OKM from RFC 5869 Test Vector 1
    const std::vector<uint8_t> rfc5869_okm = {0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a, 0x90, 0x43, 0x4f,
                                              0x64, 0xd0, 0x36, 0x2f, 0x2a, 0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a,
                                              0x5a, 0x4c, 0x5d, 0xb0, 0x2d, 0x56, 0xec, 0xc4, 0xc5, 0xbf, 0x34,
                                              0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18, 0x58, 0x65};

    TEST_CASE("HKDF-Extract SHA256 - RFC 5869 Test Vector 1") {
        auto result = keylock::hash::hkdf_extract(keylock::hash::Algorithm::SHA256, rfc5869_ikm, rfc5869_salt);

        REQUIRE(result.success);
        CHECK(result.data.size() == 32);
        CHECK(result.data == rfc5869_prk);
    }

    TEST_CASE("HKDF-Expand SHA256 - RFC 5869 Test Vector 1") {
        auto result = keylock::hash::hkdf_expand(keylock::hash::Algorithm::SHA256, rfc5869_prk, rfc5869_info, 42);

        REQUIRE(result.success);
        CHECK(result.data.size() == 42);
        CHECK(result.data == rfc5869_okm);
    }

    TEST_CASE("HKDF Combined SHA256 - RFC 5869 Test Vector 1") {
        auto result = keylock::hash::hkdf(keylock::hash::Algorithm::SHA256, rfc5869_ikm, rfc5869_salt, rfc5869_info, 42);

        REQUIRE(result.success);
        CHECK(result.data.size() == 42);
        CHECK(result.data == rfc5869_okm);
    }

    TEST_CASE("HKDF-Extract with empty salt") {
        // When salt is empty, it should be treated as HashLen zeros (RFC 5869)
        auto result = keylock::hash::hkdf_extract(keylock::hash::Algorithm::SHA256, rfc5869_ikm, {});

        REQUIRE(result.success);
        CHECK(result.data.size() == 32);
    }

    TEST_CASE("HKDF-Expand with empty info") {
        auto result = keylock::hash::hkdf_expand(keylock::hash::Algorithm::SHA256, rfc5869_prk, {}, 32);

        REQUIRE(result.success);
        CHECK(result.data.size() == 32);
    }

    TEST_CASE("HKDF SHA512") {
        auto result = keylock::hash::hkdf(keylock::hash::Algorithm::SHA512, rfc5869_ikm, rfc5869_salt, rfc5869_info, 64);

        REQUIRE(result.success);
        CHECK(result.data.size() == 64);
    }

    TEST_CASE("HKDF BLAKE2b") {
        auto result = keylock::hash::hkdf(keylock::hash::Algorithm::BLAKE2b, rfc5869_ikm, rfc5869_salt, rfc5869_info, 32);

        REQUIRE(result.success);
        CHECK(result.data.size() == 32);
    }

    TEST_CASE("HKDF output length limits") {
        // SHA256 hash length is 32, so max output is 255 * 32 = 8160
        auto result_ok = keylock::hash::hkdf(keylock::hash::Algorithm::SHA256, rfc5869_ikm, rfc5869_salt, rfc5869_info,
                                             255 * 32);
        REQUIRE(result_ok.success);
        CHECK(result_ok.data.size() == 255 * 32);

        // Requesting more than 255 * HashLen should fail
        auto result_fail = keylock::hash::hkdf(keylock::hash::Algorithm::SHA256, rfc5869_ikm, rfc5869_salt, rfc5869_info,
                                               255 * 32 + 1);
        CHECK_FALSE(result_fail.success);
        CHECK(result_fail.error_message.find("too large") != std::string::npos);
    }

    TEST_CASE("HKDF consistency") {
        auto result1 =
            keylock::hash::hkdf(keylock::hash::Algorithm::SHA256, rfc5869_ikm, rfc5869_salt, rfc5869_info, 32);
        auto result2 =
            keylock::hash::hkdf(keylock::hash::Algorithm::SHA256, rfc5869_ikm, rfc5869_salt, rfc5869_info, 32);

        REQUIRE(result1.success);
        REQUIRE(result2.success);
        CHECK(result1.data == result2.data);
    }

    TEST_CASE("HKDF different info produces different output") {
        std::vector<uint8_t> info1 = {0x01, 0x02, 0x03};
        std::vector<uint8_t> info2 = {0x04, 0x05, 0x06};

        auto result1 = keylock::hash::hkdf(keylock::hash::Algorithm::SHA256, rfc5869_ikm, rfc5869_salt, info1, 32);
        auto result2 = keylock::hash::hkdf(keylock::hash::Algorithm::SHA256, rfc5869_ikm, rfc5869_salt, info2, 32);

        REQUIRE(result1.success);
        REQUIRE(result2.success);
        CHECK(result1.data != result2.data);
    }

    TEST_CASE("HKDF-Expand with short PRK fails") {
        std::vector<uint8_t> short_prk = {0x01, 0x02, 0x03}; // Too short for SHA256
        auto result = keylock::hash::hkdf_expand(keylock::hash::Algorithm::SHA256, short_prk, rfc5869_info, 32);

        CHECK_FALSE(result.success);
        CHECK(result.error_message.find("PRK too short") != std::string::npos);
    }
}
