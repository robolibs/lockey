#include "keylock/keylock.hpp"
#include <doctest/doctest.h>

TEST_SUITE("Asymmetric Encryption") {
    const std::vector<uint8_t> test_data = {0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20,
                                            0x57, 0x6f, 0x72, 0x6c, 0x64}; // "Hello World"

    TEST_CASE("X25519 box encryption/decryption") {
        keylock::keylock crypto(keylock::keylock::Algorithm::X25519_Box);

        auto keypair = crypto.generate_keypair();
        CHECK(keypair.public_key.size() == crypto_box_PUBLICKEYBYTES);
        CHECK(keypair.private_key.size() ==
              crypto_box_PUBLICKEYBYTES + crypto_box_SECRETKEYBYTES);

        auto encrypt_result = crypto.encrypt_asymmetric(test_data, keypair.public_key);
        REQUIRE(encrypt_result.success);
        CHECK(encrypt_result.data.size() == test_data.size() + crypto_box_SEALBYTES);

        auto decrypt_result = crypto.decrypt_asymmetric(encrypt_result.data, keypair.private_key);
        REQUIRE(decrypt_result.success);
        CHECK(decrypt_result.data == test_data);
    }

    TEST_CASE("Empty data asymmetric encryption") {
        keylock::keylock crypto(keylock::keylock::Algorithm::X25519_Box);
        auto keypair = crypto.generate_keypair();
        std::vector<uint8_t> empty_data;

        auto encrypt_result = crypto.encrypt_asymmetric(empty_data, keypair.public_key);
        REQUIRE(encrypt_result.success);

        auto decrypt_result = crypto.decrypt_asymmetric(encrypt_result.data, keypair.private_key);
        REQUIRE(decrypt_result.success);
        CHECK(decrypt_result.data.empty());
    }

    TEST_CASE("Wrong key for decryption should fail") {
        keylock::keylock crypto(keylock::keylock::Algorithm::X25519_Box);

        auto keypair1 = crypto.generate_keypair();
        auto keypair2 = crypto.generate_keypair();

        auto encrypt_result = crypto.encrypt_asymmetric(test_data, keypair1.public_key);
        REQUIRE(encrypt_result.success);

        auto decrypt_wrong = crypto.decrypt_asymmetric(encrypt_result.data, keypair2.private_key);
        CHECK_FALSE(decrypt_wrong.success);

        auto decrypt_correct = crypto.decrypt_asymmetric(encrypt_result.data, keypair1.private_key);
        REQUIRE(decrypt_correct.success);
        CHECK(decrypt_correct.data == test_data);
    }

    TEST_CASE("Symmetric algorithms should not support asymmetric encryption") {
        keylock::keylock crypto(keylock::keylock::Algorithm::XChaCha20_Poly1305);
        std::vector<uint8_t> dummy_key = {0x01, 0x02, 0x03};

        auto encrypt_result = crypto.encrypt_asymmetric(test_data, dummy_key);
        CHECK_FALSE(encrypt_result.success);
        CHECK_FALSE(encrypt_result.error_message.empty());
    }

    TEST_CASE("Non-box algorithms reject asymmetric operations") {
        keylock::keylock crypto(keylock::keylock::Algorithm::Ed25519);

        auto encrypt_result = crypto.encrypt_asymmetric(test_data, {0x01});
        CHECK_FALSE(encrypt_result.success);
        CHECK_FALSE(encrypt_result.error_message.empty());

        auto decrypt_result = crypto.decrypt_asymmetric({0x02}, {0x03});
        CHECK_FALSE(decrypt_result.success);
        CHECK_FALSE(decrypt_result.error_message.empty());
    }
}
