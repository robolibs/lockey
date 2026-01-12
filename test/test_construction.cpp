#include "keylock/keylock.hpp"
#include <doctest/doctest.h>

TEST_SUITE("Construction and Configuration") {
    TEST_CASE("Default constructor") {
        REQUIRE_NOTHROW(keylock::keylock crypto);

        keylock::keylock crypto;
        CHECK(crypto.get_algorithm() == keylock::keylock::Algorithm::XChaCha20_Poly1305);
        CHECK(crypto.get_hash_algorithm() == keylock::keylock::HashAlgorithm::SHA256);
    }

    TEST_CASE("Constructor with parameters") {
        REQUIRE_NOTHROW(keylock::keylock crypto(keylock::keylock::Algorithm::SecretBox_XSalsa20,
                                              keylock::keylock::HashAlgorithm::SHA512));

        keylock::keylock crypto(keylock::keylock::Algorithm::SecretBox_XSalsa20,
                              keylock::keylock::HashAlgorithm::SHA512);
        CHECK(crypto.get_algorithm() == keylock::keylock::Algorithm::SecretBox_XSalsa20);
        CHECK(crypto.get_hash_algorithm() == keylock::keylock::HashAlgorithm::SHA512);
    }

    TEST_CASE("Algorithm setting") {
        keylock::keylock crypto;

        crypto.set_algorithm(keylock::keylock::Algorithm::SecretBox_XSalsa20);
        CHECK(crypto.get_algorithm() == keylock::keylock::Algorithm::SecretBox_XSalsa20);

        crypto.set_algorithm(keylock::keylock::Algorithm::X25519_Box);
        CHECK(crypto.get_algorithm() == keylock::keylock::Algorithm::X25519_Box);

        crypto.set_algorithm(keylock::keylock::Algorithm::Ed25519);
        CHECK(crypto.get_algorithm() == keylock::keylock::Algorithm::Ed25519);
    }

    TEST_CASE("Hash algorithm setting") {
        keylock::keylock crypto;

        crypto.set_hash_algorithm(keylock::keylock::HashAlgorithm::SHA512);
        CHECK(crypto.get_hash_algorithm() == keylock::keylock::HashAlgorithm::SHA512);

        crypto.set_hash_algorithm(keylock::keylock::HashAlgorithm::BLAKE2b);
        CHECK(crypto.get_hash_algorithm() == keylock::keylock::HashAlgorithm::BLAKE2b);
    }

    TEST_CASE("Advanced algorithms are available") {
        CHECK_NOTHROW(
            keylock::keylock crypto(keylock::keylock::Algorithm::XChaCha20_Poly1305, keylock::keylock::HashAlgorithm::BLAKE2b));
        CHECK_NOTHROW(keylock::keylock crypto(keylock::keylock::Algorithm::Ed25519));
    }
}
