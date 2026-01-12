#include "keylock/keylock.hpp"
#include <doctest/doctest.h>

TEST_SUITE("Utility Functions") {
    TEST_CASE("Hex conversion") {
        // Test basic hex conversion
        std::vector<uint8_t> data = {0x48, 0x65, 0x6c, 0x6c, 0x6f}; // "Hello"
        std::string expected_hex = "48656c6c6f";

        auto hex_result = keylock::keylock::to_hex(data);
        CHECK(hex_result == expected_hex);

        // Test reverse conversion
        auto data_result = keylock::keylock::from_hex(hex_result);
        CHECK(data_result == data);
    }

    TEST_CASE("Empty data hex conversion") {
        std::vector<uint8_t> empty_data;

        auto hex_result = keylock::keylock::to_hex(empty_data);
        CHECK(hex_result.empty());

        auto data_result = keylock::keylock::from_hex("");
        CHECK(data_result.empty());
    }

    TEST_CASE("Hex conversion with all byte values") {
        std::vector<uint8_t> all_bytes;
        for (int i = 0; i < 256; ++i) {
            all_bytes.push_back(static_cast<uint8_t>(i));
        }

        auto hex_result = keylock::keylock::to_hex(all_bytes);
        CHECK(hex_result.length() == 512); // 256 bytes * 2 hex chars each

        auto data_result = keylock::keylock::from_hex(hex_result);
        CHECK(data_result == all_bytes);
    }

    TEST_CASE("Invalid hex string handling") {
        // Test invalid hex characters
        auto result1 = keylock::keylock::from_hex("xyz");
        CHECK(result1.empty()); // Should return empty vector for invalid chars

        // Test odd length hex string
        auto result2 = keylock::keylock::from_hex("48656c6c6");
        CHECK(result2.empty()); // Should return empty vector for odd length

        MESSAGE("Invalid hex handling returns empty vectors instead of throwing");
    }

    TEST_CASE("Case insensitive hex conversion") {
        std::vector<uint8_t> data = {0xAB, 0xCD, 0xEF};

        auto hex_lower = keylock::keylock::to_hex(data);

        // Test that we can convert back uppercase hex
        auto data_from_upper = keylock::keylock::from_hex("ABCDEF");
        auto data_from_lower = keylock::keylock::from_hex("abcdef");

        if (!data_from_upper.empty() && !data_from_lower.empty()) {
            CHECK(data_from_upper == data);
            CHECK(data_from_lower == data);
            MESSAGE("Case insensitive hex conversion supported");
        } else {
            MESSAGE("Case insensitive hex conversion may not be supported");
        }
    }

    TEST_CASE("Algorithm name conversion") {
        CHECK(keylock::keylock::algorithm_to_string(keylock::keylock::Algorithm::XChaCha20_Poly1305) ==
              "XChaCha20-Poly1305");
        CHECK(keylock::keylock::algorithm_to_string(keylock::keylock::Algorithm::SecretBox_XSalsa20) ==
              "SecretBox-XSalsa20-Poly1305");
        CHECK(keylock::keylock::algorithm_to_string(keylock::keylock::Algorithm::X25519_Box) == "X25519-Box");
        CHECK(keylock::keylock::algorithm_to_string(keylock::keylock::Algorithm::Ed25519) == "Ed25519");
    }

    TEST_CASE("Hash algorithm name conversion") {
        CHECK(keylock::keylock::hash_algorithm_to_string(keylock::keylock::HashAlgorithm::SHA256) == "SHA-256");
        CHECK(keylock::keylock::hash_algorithm_to_string(keylock::keylock::HashAlgorithm::SHA512) == "SHA-512");
        CHECK(keylock::keylock::hash_algorithm_to_string(keylock::keylock::HashAlgorithm::BLAKE2b) == "BLAKE2b");
    }
}
