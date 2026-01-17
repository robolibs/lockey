#include "keylock/keylock.hpp"
#include <doctest/doctest.h>

TEST_SUITE("Symmetric Encryption") {
    const std::vector<uint8_t> test_data = {0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20,
                                            0x57, 0x6f, 0x72, 0x6c, 0x64}; // "Hello World"
    const std::vector<uint8_t> key_material = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
                                               0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
                                               0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20};

    TEST_CASE("XChaCha20-Poly1305 encryption/decryption") {
        keylock::keylock crypto(keylock::keylock::Algorithm::XChaCha20_Poly1305);

        // Test encryption
        auto encrypt_result = crypto.encrypt(test_data, key_material);
        REQUIRE(encrypt_result.success);
        CHECK(encrypt_result.data.size() > test_data.size()); // Should be larger due to IV + tag
        CHECK(encrypt_result.error_message.empty());

        // Test decryption
        auto decrypt_result = crypto.decrypt(encrypt_result.data, key_material);
        REQUIRE(decrypt_result.success);
        CHECK(decrypt_result.data == test_data);
        CHECK(decrypt_result.error_message.empty());
    }

    TEST_CASE("SecretBox XSalsa20-Poly1305 encryption/decryption") {
        keylock::keylock crypto(keylock::keylock::Algorithm::SecretBox_XSalsa20);

        // Test encryption
        auto encrypt_result = crypto.encrypt(test_data, key_material);
        REQUIRE(encrypt_result.success);
        CHECK(encrypt_result.data.size() > test_data.size());

        // Test decryption
        auto decrypt_result = crypto.decrypt(encrypt_result.data, key_material);
        REQUIRE(decrypt_result.success);
        CHECK(decrypt_result.data == test_data);
    }

    TEST_CASE("Encryption with associated data (AEAD)") {
        keylock::keylock crypto(keylock::keylock::Algorithm::XChaCha20_Poly1305);
        std::vector<uint8_t> associated_data = {0x41, 0x44, 0x44, 0x44}; // "ADDD"

        // Test encryption with AAD
        auto encrypt_result = crypto.encrypt(test_data, key_material, associated_data);
        REQUIRE(encrypt_result.success);

        // Test decryption with correct AAD
        auto decrypt_result = crypto.decrypt(encrypt_result.data, key_material, associated_data);
        REQUIRE(decrypt_result.success);
        CHECK(decrypt_result.data == test_data);

        // Test decryption with wrong AAD (should fail)
        std::vector<uint8_t> wrong_aad = {0x42, 0x41, 0x44, 0x44}; // "BADD"
        auto decrypt_wrong_result = crypto.decrypt(encrypt_result.data, key_material, wrong_aad);
        CHECK_FALSE(decrypt_wrong_result.success);
        CHECK_FALSE(decrypt_wrong_result.error_message.empty());
    }

    TEST_CASE("Empty data encryption") {
        keylock::keylock crypto(keylock::keylock::Algorithm::XChaCha20_Poly1305);
        std::vector<uint8_t> empty_data;

        auto encrypt_result = crypto.encrypt(empty_data, key_material);
        REQUIRE(encrypt_result.success);

        auto decrypt_result = crypto.decrypt(encrypt_result.data, key_material);
        REQUIRE(decrypt_result.success);
        CHECK(decrypt_result.data.empty());
    }

    TEST_CASE("Large data encryption") {
        keylock::keylock crypto(keylock::keylock::Algorithm::XChaCha20_Poly1305);
        std::vector<uint8_t> large_data(10000, 0x42); // 10KB of 'B'

        auto encrypt_result = crypto.encrypt(large_data, key_material);
        REQUIRE(encrypt_result.success);

        auto decrypt_result = crypto.decrypt(encrypt_result.data, key_material);
        REQUIRE(decrypt_result.success);
        CHECK(decrypt_result.data == large_data);
    }

    TEST_CASE("Wrong algorithm for symmetric encryption") {
        keylock::keylock crypto(keylock::keylock::Algorithm::Ed25519);

        auto result = crypto.encrypt(test_data, key_material);
        CHECK_FALSE(result.success);
        CHECK(result.error_message.find("not suitable for symmetric encryption") != std::string::npos);
    }

    TEST_CASE("ChaCha20-Poly1305 IETF encryption/decryption") {
        keylock::keylock crypto(keylock::keylock::Algorithm::ChaCha20_Poly1305);

        // Test encryption
        auto encrypt_result = crypto.encrypt(test_data, key_material);
        REQUIRE(encrypt_result.success);
        // 12-byte nonce + ciphertext + 16-byte tag
        CHECK(encrypt_result.data.size() == test_data.size() + 12 + 16);
        CHECK(encrypt_result.error_message.empty());

        // Test decryption
        auto decrypt_result = crypto.decrypt(encrypt_result.data, key_material);
        REQUIRE(decrypt_result.success);
        CHECK(decrypt_result.data == test_data);
        CHECK(decrypt_result.error_message.empty());
    }

    TEST_CASE("ChaCha20-Poly1305 IETF with associated data") {
        keylock::keylock crypto(keylock::keylock::Algorithm::ChaCha20_Poly1305);
        std::vector<uint8_t> associated_data = {0x41, 0x44, 0x44, 0x44}; // "ADDD"

        // Test encryption with AAD
        auto encrypt_result = crypto.encrypt(test_data, key_material, associated_data);
        REQUIRE(encrypt_result.success);

        // Test decryption with correct AAD
        auto decrypt_result = crypto.decrypt(encrypt_result.data, key_material, associated_data);
        REQUIRE(decrypt_result.success);
        CHECK(decrypt_result.data == test_data);

        // Test decryption with wrong AAD (should fail)
        std::vector<uint8_t> wrong_aad = {0x42, 0x41, 0x44, 0x44}; // "BADD"
        auto decrypt_wrong_result = crypto.decrypt(encrypt_result.data, key_material, wrong_aad);
        CHECK_FALSE(decrypt_wrong_result.success);
    }

    TEST_CASE("ChaCha20-Poly1305 IETF empty data") {
        keylock::keylock crypto(keylock::keylock::Algorithm::ChaCha20_Poly1305);
        std::vector<uint8_t> empty_data;

        auto encrypt_result = crypto.encrypt(empty_data, key_material);
        REQUIRE(encrypt_result.success);

        auto decrypt_result = crypto.decrypt(encrypt_result.data, key_material);
        REQUIRE(decrypt_result.success);
        CHECK(decrypt_result.data.empty());
    }

    TEST_CASE("ChaCha20-Poly1305 IETF large data") {
        keylock::keylock crypto(keylock::keylock::Algorithm::ChaCha20_Poly1305);
        std::vector<uint8_t> large_data(10000, 0x42); // 10KB of 'B'

        auto encrypt_result = crypto.encrypt(large_data, key_material);
        REQUIRE(encrypt_result.success);

        auto decrypt_result = crypto.decrypt(encrypt_result.data, key_material);
        REQUIRE(decrypt_result.success);
        CHECK(decrypt_result.data == large_data);
    }

    TEST_CASE("ChaCha20-Poly1305 IETF wrong key fails") {
        keylock::keylock crypto(keylock::keylock::Algorithm::ChaCha20_Poly1305);

        auto encrypt_result = crypto.encrypt(test_data, key_material);
        REQUIRE(encrypt_result.success);

        std::vector<uint8_t> wrong_key = key_material;
        wrong_key[0] ^= 0xFF; // Flip bits in first byte

        auto decrypt_result = crypto.decrypt(encrypt_result.data, wrong_key);
        CHECK_FALSE(decrypt_result.success);
    }

    TEST_CASE("ChaCha20-Poly1305 IETF tampered ciphertext fails") {
        keylock::keylock crypto(keylock::keylock::Algorithm::ChaCha20_Poly1305);

        auto encrypt_result = crypto.encrypt(test_data, key_material);
        REQUIRE(encrypt_result.success);

        std::vector<uint8_t> tampered = encrypt_result.data;
        tampered[tampered.size() - 1] ^= 0xFF; // Flip bits in last byte (tag)

        auto decrypt_result = crypto.decrypt(tampered, key_material);
        CHECK_FALSE(decrypt_result.success);
    }

    TEST_CASE("AES-256-GCM availability check") {
        // This test always passes - it just checks the availability function works
        bool available = keylock::keylock::is_aes_gcm_available();
        // Result depends on hardware - just verify it returns a boolean
        CHECK((available == true || available == false));
    }

    TEST_CASE("AES-256-GCM encryption/decryption") {
        if (!keylock::keylock::is_aes_gcm_available()) {
            WARN("AES-GCM not available on this hardware - skipping test");
            return;
        }

        keylock::keylock crypto(keylock::keylock::Algorithm::AES256_GCM);

        // Test encryption
        auto encrypt_result = crypto.encrypt(test_data, key_material);
        REQUIRE(encrypt_result.success);
        // 12-byte nonce + ciphertext + 16-byte tag
        CHECK(encrypt_result.data.size() == test_data.size() + 12 + 16);
        CHECK(encrypt_result.error_message.empty());

        // Test decryption
        auto decrypt_result = crypto.decrypt(encrypt_result.data, key_material);
        REQUIRE(decrypt_result.success);
        CHECK(decrypt_result.data == test_data);
        CHECK(decrypt_result.error_message.empty());
    }

    TEST_CASE("AES-256-GCM with associated data") {
        if (!keylock::keylock::is_aes_gcm_available()) {
            WARN("AES-GCM not available on this hardware - skipping test");
            return;
        }

        keylock::keylock crypto(keylock::keylock::Algorithm::AES256_GCM);
        std::vector<uint8_t> associated_data = {0x41, 0x44, 0x44, 0x44}; // "ADDD"

        // Test encryption with AAD
        auto encrypt_result = crypto.encrypt(test_data, key_material, associated_data);
        REQUIRE(encrypt_result.success);

        // Test decryption with correct AAD
        auto decrypt_result = crypto.decrypt(encrypt_result.data, key_material, associated_data);
        REQUIRE(decrypt_result.success);
        CHECK(decrypt_result.data == test_data);

        // Test decryption with wrong AAD (should fail)
        std::vector<uint8_t> wrong_aad = {0x42, 0x41, 0x44, 0x44}; // "BADD"
        auto decrypt_wrong_result = crypto.decrypt(encrypt_result.data, key_material, wrong_aad);
        CHECK_FALSE(decrypt_wrong_result.success);
    }

    TEST_CASE("AES-256-GCM empty data") {
        if (!keylock::keylock::is_aes_gcm_available()) {
            WARN("AES-GCM not available on this hardware - skipping test");
            return;
        }

        keylock::keylock crypto(keylock::keylock::Algorithm::AES256_GCM);
        std::vector<uint8_t> empty_data;

        auto encrypt_result = crypto.encrypt(empty_data, key_material);
        REQUIRE(encrypt_result.success);

        auto decrypt_result = crypto.decrypt(encrypt_result.data, key_material);
        REQUIRE(decrypt_result.success);
        CHECK(decrypt_result.data.empty());
    }

    TEST_CASE("AES-256-GCM large data") {
        if (!keylock::keylock::is_aes_gcm_available()) {
            WARN("AES-GCM not available on this hardware - skipping test");
            return;
        }

        keylock::keylock crypto(keylock::keylock::Algorithm::AES256_GCM);
        std::vector<uint8_t> large_data(10000, 0x42); // 10KB of 'B'

        auto encrypt_result = crypto.encrypt(large_data, key_material);
        REQUIRE(encrypt_result.success);

        auto decrypt_result = crypto.decrypt(encrypt_result.data, key_material);
        REQUIRE(decrypt_result.success);
        CHECK(decrypt_result.data == large_data);
    }

    TEST_CASE("AES-256-GCM wrong key fails") {
        if (!keylock::keylock::is_aes_gcm_available()) {
            WARN("AES-GCM not available on this hardware - skipping test");
            return;
        }

        keylock::keylock crypto(keylock::keylock::Algorithm::AES256_GCM);

        auto encrypt_result = crypto.encrypt(test_data, key_material);
        REQUIRE(encrypt_result.success);

        std::vector<uint8_t> wrong_key = key_material;
        wrong_key[0] ^= 0xFF; // Flip bits in first byte

        auto decrypt_result = crypto.decrypt(encrypt_result.data, wrong_key);
        CHECK_FALSE(decrypt_result.success);
    }

    TEST_CASE("AES-256-GCM tampered ciphertext fails") {
        if (!keylock::keylock::is_aes_gcm_available()) {
            WARN("AES-GCM not available on this hardware - skipping test");
            return;
        }

        keylock::keylock crypto(keylock::keylock::Algorithm::AES256_GCM);

        auto encrypt_result = crypto.encrypt(test_data, key_material);
        REQUIRE(encrypt_result.success);

        std::vector<uint8_t> tampered = encrypt_result.data;
        tampered[tampered.size() - 1] ^= 0xFF; // Flip bits in last byte (tag)

        auto decrypt_result = crypto.decrypt(tampered, key_material);
        CHECK_FALSE(decrypt_result.success);
    }

    TEST_CASE("Algorithm string representations") {
        CHECK(keylock::keylock::algorithm_to_string(keylock::keylock::Algorithm::XChaCha20_Poly1305) ==
              "XChaCha20-Poly1305");
        CHECK(keylock::keylock::algorithm_to_string(keylock::keylock::Algorithm::ChaCha20_Poly1305) ==
              "ChaCha20-Poly1305-IETF");
        CHECK(keylock::keylock::algorithm_to_string(keylock::keylock::Algorithm::AES256_GCM) == "AES-256-GCM");
    }
}
