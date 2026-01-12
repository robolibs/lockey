#include "keylock/keylock.hpp"
#include <doctest/doctest.h>

TEST_SUITE("HMAC Functions") {
    const std::vector<uint8_t> test_data = {0x48, 0x65, 0x6c, 0x6c, 0x6f}; // "Hello"
    const std::vector<uint8_t> hmac_key = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
                                           0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
                                           0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20};

    TEST_CASE("HMAC-SHA256") {
        keylock::keylock crypto(keylock::keylock::Algorithm::XChaCha20_Poly1305,
                              keylock::keylock::HashAlgorithm::SHA256);

        auto result = crypto.hmac(test_data, hmac_key);
        REQUIRE(result.success);
        CHECK(result.data.size() == 32);
    }

    TEST_CASE("HMAC-SHA512") {
        keylock::keylock crypto(keylock::keylock::Algorithm::XChaCha20_Poly1305,
                              keylock::keylock::HashAlgorithm::SHA512);

        auto result = crypto.hmac(test_data, hmac_key);
        REQUIRE(result.success);
        CHECK(result.data.size() == 64);
    }

    TEST_CASE("HMAC with empty data") {
        keylock::keylock crypto(keylock::keylock::Algorithm::XChaCha20_Poly1305,
                              keylock::keylock::HashAlgorithm::SHA256);

        std::vector<uint8_t> empty_data;
        auto result = crypto.hmac(empty_data, hmac_key);
        REQUIRE(result.success);
        CHECK(result.data.size() == 32);
    }

    TEST_CASE("HMAC with empty key (BLAKE2b should fail)") {
        keylock::keylock crypto(keylock::keylock::Algorithm::XChaCha20_Poly1305,
                              keylock::keylock::HashAlgorithm::BLAKE2b);

        std::vector<uint8_t> empty_key;
        auto result = crypto.hmac(test_data, empty_key);
        CHECK_FALSE(result.success);
    }

    TEST_CASE("HMAC consistency") {
        keylock::keylock crypto(keylock::keylock::Algorithm::XChaCha20_Poly1305,
                              keylock::keylock::HashAlgorithm::SHA256);

        auto result1 = crypto.hmac(test_data, hmac_key);
        auto result2 = crypto.hmac(test_data, hmac_key);

        REQUIRE(result1.success);
        REQUIRE(result2.success);
        CHECK(result1.data == result2.data);
    }
}
