#include "keylock/keylock.hpp"
#include <doctest/doctest.h>

TEST_SUITE("Digital Signatures") {
    const std::vector<uint8_t> test_message = {
        0x54, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 0x61, 0x20, 0x74,
        0x65, 0x73, 0x74, 0x20, 0x6d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65}; // "This is a test message"

    TEST_CASE("Ed25519 sign and verify") {
        keylock::keylock crypto(keylock::keylock::Algorithm::Ed25519);

        auto keypair = crypto.generate_keypair();
        CHECK(keypair.algorithm == keylock::keylock::Algorithm::Ed25519);

        auto sign_result = crypto.sign(test_message, keypair.private_key);
        REQUIRE(sign_result.success);
        CHECK(sign_result.data.size() == crypto_sign_ed25519_BYTES);

        auto verify_result = crypto.verify(test_message, sign_result.data, keypair.public_key);
        REQUIRE(verify_result.success);

        // Verify with wrong message should fail
        std::vector<uint8_t> wrong_message = {0x77, 0x72, 0x6f, 0x6e, 0x67};
        auto verify_wrong = crypto.verify(wrong_message, sign_result.data, keypair.public_key);
        CHECK_FALSE(verify_wrong.success);

        // Verify with wrong public key should fail
        auto keypair2 = crypto.generate_keypair();
        auto verify_wrong_key = crypto.verify(test_message, sign_result.data, keypair2.public_key);
        CHECK_FALSE(verify_wrong_key.success);
    }

    TEST_CASE("Sign with wrong algorithm should fail") {
        keylock::keylock crypto(keylock::keylock::Algorithm::XChaCha20_Poly1305);
        std::vector<uint8_t> dummy_key = {0x01, 0x02, 0x03};

        auto result = crypto.sign(test_message, dummy_key);
        CHECK_FALSE(result.success);
        CHECK(result.error_message.find("does not support signing") != std::string::npos);
    }

    TEST_CASE("Large message signing") {
        keylock::keylock crypto(keylock::keylock::Algorithm::Ed25519);

        auto keypair = crypto.generate_keypair();
        std::vector<uint8_t> large_message(10000, 0x42); // 10KB of 'B'

        auto sign_result = crypto.sign(large_message, keypair.private_key);
        REQUIRE(sign_result.success);

        auto verify_result = crypto.verify(large_message, sign_result.data, keypair.public_key);
        CHECK(verify_result.success);
    }

    TEST_CASE("Ed25519 signatures deterministic") {
        keylock::keylock crypto(keylock::keylock::Algorithm::Ed25519);
        auto keypair = crypto.generate_keypair();

        auto sig1 = crypto.sign(test_message, keypair.private_key);
        auto sig2 = crypto.sign(test_message, keypair.private_key);

        REQUIRE(sig1.success);
        REQUIRE(sig2.success);
        CHECK(sig1.data == sig2.data);
    }
}
