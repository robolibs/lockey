#include "keylock/crypto/secretbox_xsalsa20poly1305/secretbox.hpp"
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

TEST_SUITE("SecretBox (XSalsa20-Poly1305)") {

    TEST_CASE("SecretBox easy encrypt/decrypt") {
        auto key = hex_to_bytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        auto nonce = hex_to_bytes("000102030405060708090a0b0c0d0e0f1011121314151617");
        const uint8_t plaintext[] = "Hello, SecretBox!";
        size_t pt_len = sizeof(plaintext) - 1;

        std::vector<uint8_t> ciphertext(pt_len + keylock::crypto::secretbox::MACBYTES);
        int result = keylock::crypto::secretbox::easy(ciphertext.data(), plaintext, pt_len, nonce.data(), key.data());
        CHECK(result == 0);

        std::vector<uint8_t> decrypted(pt_len);
        result = keylock::crypto::secretbox::open_easy(decrypted.data(), ciphertext.data(), ciphertext.size(),
                                                       nonce.data(), key.data());
        CHECK(result == 0);
        CHECK(std::memcmp(decrypted.data(), plaintext, pt_len) == 0);
    }

    TEST_CASE("SecretBox detached encrypt/decrypt") {
        auto key = hex_to_bytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        auto nonce = hex_to_bytes("000102030405060708090a0b0c0d0e0f1011121314151617");
        const uint8_t plaintext[] = "Hello, SecretBox detached!";
        size_t pt_len = sizeof(plaintext) - 1;

        std::vector<uint8_t> ciphertext(pt_len);
        uint8_t mac[16];
        int result =
            keylock::crypto::secretbox::detached(ciphertext.data(), mac, plaintext, pt_len, nonce.data(), key.data());
        CHECK(result == 0);

        std::vector<uint8_t> decrypted(pt_len);
        result = keylock::crypto::secretbox::open_detached(decrypted.data(), ciphertext.data(), pt_len, mac,
                                                           nonce.data(), key.data());
        CHECK(result == 0);
        CHECK(std::memcmp(decrypted.data(), plaintext, pt_len) == 0);
    }

    TEST_CASE("SecretBox empty message") {
        auto key = hex_to_bytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        auto nonce = hex_to_bytes("000102030405060708090a0b0c0d0e0f1011121314151617");

        std::vector<uint8_t> ciphertext(keylock::crypto::secretbox::MACBYTES);
        int result = keylock::crypto::secretbox::easy(ciphertext.data(), nullptr, 0, nonce.data(), key.data());
        CHECK(result == 0);

        std::vector<uint8_t> decrypted;
        result = keylock::crypto::secretbox::open_easy(decrypted.data(), ciphertext.data(), ciphertext.size(),
                                                       nonce.data(), key.data());
        CHECK(result == 0);
    }

    TEST_CASE("SecretBox wrong key fails") {
        auto key1 = hex_to_bytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        auto key2 = hex_to_bytes("1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100");
        auto nonce = hex_to_bytes("000102030405060708090a0b0c0d0e0f1011121314151617");
        const uint8_t plaintext[] = "Secret message";
        size_t pt_len = sizeof(plaintext) - 1;

        std::vector<uint8_t> ciphertext(pt_len + keylock::crypto::secretbox::MACBYTES);
        keylock::crypto::secretbox::easy(ciphertext.data(), plaintext, pt_len, nonce.data(), key1.data());

        std::vector<uint8_t> decrypted(pt_len);
        int result = keylock::crypto::secretbox::open_easy(decrypted.data(), ciphertext.data(), ciphertext.size(),
                                                           nonce.data(), key2.data());
        CHECK(result != 0);
    }

    TEST_CASE("SecretBox wrong nonce fails") {
        auto key = hex_to_bytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        auto nonce1 = hex_to_bytes("000102030405060708090a0b0c0d0e0f1011121314151617");
        auto nonce2 = hex_to_bytes("171615141312111000f0e0d0c0b0a09080706050403020100");
        const uint8_t plaintext[] = "Secret message";
        size_t pt_len = sizeof(plaintext) - 1;

        std::vector<uint8_t> ciphertext(pt_len + keylock::crypto::secretbox::MACBYTES);
        keylock::crypto::secretbox::easy(ciphertext.data(), plaintext, pt_len, nonce1.data(), key.data());

        std::vector<uint8_t> decrypted(pt_len);
        int result = keylock::crypto::secretbox::open_easy(decrypted.data(), ciphertext.data(), ciphertext.size(),
                                                           nonce2.data(), key.data());
        CHECK(result != 0);
    }

    TEST_CASE("SecretBox modified ciphertext fails") {
        auto key = hex_to_bytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        auto nonce = hex_to_bytes("000102030405060708090a0b0c0d0e0f1011121314151617");
        const uint8_t plaintext[] = "Secret message";
        size_t pt_len = sizeof(plaintext) - 1;

        std::vector<uint8_t> ciphertext(pt_len + keylock::crypto::secretbox::MACBYTES);
        keylock::crypto::secretbox::easy(ciphertext.data(), plaintext, pt_len, nonce.data(), key.data());

        // Modify ciphertext
        ciphertext[keylock::crypto::secretbox::MACBYTES] ^= 0x01;

        std::vector<uint8_t> decrypted(pt_len);
        int result = keylock::crypto::secretbox::open_easy(decrypted.data(), ciphertext.data(), ciphertext.size(),
                                                           nonce.data(), key.data());
        CHECK(result != 0);
    }

    TEST_CASE("SecretBox large message") {
        auto key = hex_to_bytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        auto nonce = hex_to_bytes("000102030405060708090a0b0c0d0e0f1011121314151617");
        std::vector<uint8_t> plaintext(10000, 0x42);

        std::vector<uint8_t> ciphertext(plaintext.size() + keylock::crypto::secretbox::MACBYTES);
        int result =
            keylock::crypto::secretbox::easy(ciphertext.data(), plaintext.data(), plaintext.size(), nonce.data(), key.data());
        CHECK(result == 0);

        std::vector<uint8_t> decrypted(plaintext.size());
        result = keylock::crypto::secretbox::open_easy(decrypted.data(), ciphertext.data(), ciphertext.size(),
                                                       nonce.data(), key.data());
        CHECK(result == 0);
        CHECK(std::memcmp(decrypted.data(), plaintext.data(), plaintext.size()) == 0);
    }

    TEST_CASE("SecretBox constants") {
        CHECK(keylock::crypto::secretbox::KEYBYTES == 32);
        CHECK(keylock::crypto::secretbox::NONCEBYTES == 24);
        CHECK(keylock::crypto::secretbox::MACBYTES == 16);
    }
}
