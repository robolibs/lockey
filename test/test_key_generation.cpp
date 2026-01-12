#include "keylock/keylock.hpp"
#include <doctest/doctest.h>
#include <sodium.h>
#include <stdexcept>

TEST_SUITE("Key Generation") {
    TEST_CASE("Symmetric key generation") {
        keylock::keylock crypto;

        // Test default size (32 bytes)
        auto result = crypto.generate_symmetric_key();
        REQUIRE(result.success);
        CHECK(result.data.size() == 32);
        CHECK(result.error_message.empty());

        // Test different sizes
        auto result16 = crypto.generate_symmetric_key(16);
        REQUIRE(result16.success);
        CHECK(result16.data.size() == 16);

        auto result64 = crypto.generate_symmetric_key(64);
        REQUIRE(result64.success);
        CHECK(result64.data.size() == 64);

        // Keys should be different each time
        auto result2 = crypto.generate_symmetric_key();
        REQUIRE(result2.success);
        CHECK(result.data != result2.data);
    }

    TEST_CASE("X25519 key generation") {
        keylock::keylock crypto(keylock::keylock::Algorithm::X25519_Box);

        auto keypair = crypto.generate_keypair();
        CHECK(keypair.algorithm == keylock::keylock::Algorithm::X25519_Box);
        CHECK(keypair.public_key.size() == crypto_box_PUBLICKEYBYTES);
        CHECK(keypair.private_key.size() == crypto_box_PUBLICKEYBYTES + crypto_box_SECRETKEYBYTES);

        // Keys should be different each time
        auto keypair2 = crypto.generate_keypair();
        CHECK(keypair.public_key != keypair2.public_key);
        CHECK(keypair.private_key != keypair2.private_key);
    }

    TEST_CASE("Ed25519 key generation") {
        keylock::keylock crypto(keylock::keylock::Algorithm::Ed25519);

        auto keypair = crypto.generate_keypair();
        CHECK(keypair.algorithm == keylock::keylock::Algorithm::Ed25519);
        CHECK(keypair.public_key.size() == crypto_sign_ed25519_PUBLICKEYBYTES);
        CHECK(keypair.private_key.size() == crypto_sign_ed25519_SECRETKEYBYTES);
    }

    TEST_CASE("Key generation with symmetric algorithm should fail") {
        keylock::keylock crypto(keylock::keylock::Algorithm::XChaCha20_Poly1305);

        CHECK_THROWS_AS(crypto.generate_keypair(), std::runtime_error);
    }
}
