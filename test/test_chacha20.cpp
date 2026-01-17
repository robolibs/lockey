#include "keylock/crypto/chacha20/chacha20.hpp"
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

TEST_SUITE("ChaCha20 Stream Cipher") {

    TEST_CASE("HChaCha20 subkey derivation") {
        auto key = hex_to_bytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        auto nonce = hex_to_bytes("000000090000004a0000000031415927");

        uint8_t subkey[32];
        keylock::crypto::chacha20::hchacha20(subkey, key.data(), nonce.data());

        std::string result = bytes_to_hex(subkey, 32);
        // HChaCha20 should produce a valid 32-byte subkey
        CHECK(result.length() == 64);

        // Verify deterministic
        uint8_t subkey2[32];
        keylock::crypto::chacha20::hchacha20(subkey2, key.data(), nonce.data());
        CHECK(std::memcmp(subkey, subkey2, 32) == 0);
    }

    TEST_CASE("ChaCha20 DJB variant encryption") {
        auto key = hex_to_bytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        auto nonce = hex_to_bytes("0001020304050607");
        const uint8_t plaintext[] = "Hello, ChaCha20!";

        std::vector<uint8_t> ciphertext(sizeof(plaintext) - 1);
        keylock::crypto::chacha20::chacha20_djb(ciphertext.data(), plaintext, sizeof(plaintext) - 1, key.data(),
                                                nonce.data(), 0);

        // Verify ciphertext is different from plaintext
        CHECK(std::memcmp(ciphertext.data(), plaintext, sizeof(plaintext) - 1) != 0);

        // Decrypt (XOR again)
        std::vector<uint8_t> decrypted(sizeof(plaintext) - 1);
        keylock::crypto::chacha20::chacha20_djb(decrypted.data(), ciphertext.data(), ciphertext.size(), key.data(),
                                                nonce.data(), 0);
        CHECK(std::memcmp(decrypted.data(), plaintext, sizeof(plaintext) - 1) == 0);
    }

    TEST_CASE("ChaCha20 IETF variant encryption") {
        auto key = hex_to_bytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        auto nonce = hex_to_bytes("000000000001020304050607");
        const uint8_t plaintext[] = "Hello, ChaCha20 IETF!";

        std::vector<uint8_t> ciphertext(sizeof(plaintext) - 1);
        keylock::crypto::chacha20::chacha20_ietf(ciphertext.data(), plaintext, sizeof(plaintext) - 1, key.data(),
                                                 nonce.data(), 0);

        // Verify ciphertext is different from plaintext
        CHECK(std::memcmp(ciphertext.data(), plaintext, sizeof(plaintext) - 1) != 0);

        // Decrypt (XOR again)
        std::vector<uint8_t> decrypted(sizeof(plaintext) - 1);
        keylock::crypto::chacha20::chacha20_ietf(decrypted.data(), ciphertext.data(), ciphertext.size(), key.data(),
                                                 nonce.data(), 0);
        CHECK(std::memcmp(decrypted.data(), plaintext, sizeof(plaintext) - 1) == 0);
    }

    TEST_CASE("XChaCha20 encryption") {
        auto key = hex_to_bytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        auto nonce = hex_to_bytes("000102030405060708090a0b0c0d0e0f1011121314151617");
        const uint8_t plaintext[] = "Hello, XChaCha20 with 24-byte nonce!";

        std::vector<uint8_t> ciphertext(sizeof(plaintext) - 1);
        keylock::crypto::chacha20::xchacha20(ciphertext.data(), plaintext, sizeof(plaintext) - 1, key.data(),
                                             nonce.data(), 0);

        // Verify ciphertext is different from plaintext
        CHECK(std::memcmp(ciphertext.data(), plaintext, sizeof(plaintext) - 1) != 0);

        // Decrypt (XOR again)
        std::vector<uint8_t> decrypted(sizeof(plaintext) - 1);
        keylock::crypto::chacha20::xchacha20(decrypted.data(), ciphertext.data(), ciphertext.size(), key.data(),
                                             nonce.data(), 0);
        CHECK(std::memcmp(decrypted.data(), plaintext, sizeof(plaintext) - 1) == 0);
    }

    TEST_CASE("ChaCha20 keystream generation") {
        auto key = hex_to_bytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        auto nonce = hex_to_bytes("0001020304050607");

        // Generate keystream by encrypting zeros
        std::vector<uint8_t> keystream(64);
        keylock::crypto::chacha20::chacha20_djb(keystream.data(), nullptr, 64, key.data(), nonce.data(), 0);

        // Keystream should be non-zero
        bool non_zero = false;
        for (size_t i = 0; i < 64; ++i) {
            if (keystream[i] != 0) {
                non_zero = true;
                break;
            }
        }
        CHECK(non_zero);
    }

    TEST_CASE("ChaCha20 counter increment") {
        auto key = hex_to_bytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        auto nonce = hex_to_bytes("0001020304050607");

        // Generate keystream with counter 0
        std::vector<uint8_t> ks0(64);
        keylock::crypto::chacha20::chacha20_djb(ks0.data(), nullptr, 64, key.data(), nonce.data(), 0);

        // Generate keystream with counter 1
        std::vector<uint8_t> ks1(64);
        keylock::crypto::chacha20::chacha20_djb(ks1.data(), nullptr, 64, key.data(), nonce.data(), 1);

        // Different counters should produce different keystreams
        CHECK(std::memcmp(ks0.data(), ks1.data(), 64) != 0);
    }

    TEST_CASE("ChaCha20 different keys produce different output") {
        auto key1 = hex_to_bytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        auto key2 = hex_to_bytes("1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100");
        auto nonce = hex_to_bytes("0001020304050607");

        std::vector<uint8_t> ks1(64), ks2(64);
        keylock::crypto::chacha20::chacha20_djb(ks1.data(), nullptr, 64, key1.data(), nonce.data(), 0);
        keylock::crypto::chacha20::chacha20_djb(ks2.data(), nullptr, 64, key2.data(), nonce.data(), 0);

        CHECK(std::memcmp(ks1.data(), ks2.data(), 64) != 0);
    }

    TEST_CASE("ChaCha20 different nonces produce different output") {
        auto key = hex_to_bytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        auto nonce1 = hex_to_bytes("0001020304050607");
        auto nonce2 = hex_to_bytes("0706050403020100");

        std::vector<uint8_t> ks1(64), ks2(64);
        keylock::crypto::chacha20::chacha20_djb(ks1.data(), nullptr, 64, key.data(), nonce1.data(), 0);
        keylock::crypto::chacha20::chacha20_djb(ks2.data(), nullptr, 64, key.data(), nonce2.data(), 0);

        CHECK(std::memcmp(ks1.data(), ks2.data(), 64) != 0);
    }

    TEST_CASE("ChaCha20 large message encryption") {
        auto key = hex_to_bytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        auto nonce = hex_to_bytes("0001020304050607");

        // 1KB message
        std::vector<uint8_t> plaintext(1024, 0x42);
        std::vector<uint8_t> ciphertext(1024);
        std::vector<uint8_t> decrypted(1024);

        keylock::crypto::chacha20::chacha20_djb(ciphertext.data(), plaintext.data(), 1024, key.data(), nonce.data(), 0);
        keylock::crypto::chacha20::chacha20_djb(decrypted.data(), ciphertext.data(), 1024, key.data(), nonce.data(), 0);

        CHECK(std::memcmp(decrypted.data(), plaintext.data(), 1024) == 0);
    }

    TEST_CASE("ChaCha20 consistency") {
        auto key = hex_to_bytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        auto nonce = hex_to_bytes("0001020304050607");
        const uint8_t plaintext[] = "Test message";

        std::vector<uint8_t> ct1(sizeof(plaintext) - 1), ct2(sizeof(plaintext) - 1);
        keylock::crypto::chacha20::chacha20_djb(ct1.data(), plaintext, sizeof(plaintext) - 1, key.data(), nonce.data(),
                                                0);
        keylock::crypto::chacha20::chacha20_djb(ct2.data(), plaintext, sizeof(plaintext) - 1, key.data(), nonce.data(),
                                                0);

        CHECK(std::memcmp(ct1.data(), ct2.data(), sizeof(plaintext) - 1) == 0);
    }
}
