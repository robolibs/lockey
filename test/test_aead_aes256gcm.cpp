#include "keylock/crypto/aead_aes256gcm/aead.hpp"
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

TEST_SUITE("AEAD AES-256-GCM") {

    TEST_CASE("AES-256-GCM is available") {
        CHECK(keylock::crypto::aead_aes256gcm::is_available() == 1);
    }

    TEST_CASE("AES-256-GCM encrypt/decrypt") {
        auto key = hex_to_bytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        auto nonce = hex_to_bytes("000102030405060708090a0b");
        const uint8_t plaintext[] = "Hello, AES-256-GCM!";
        size_t pt_len = sizeof(plaintext) - 1;
        const uint8_t ad[] = "additional data";
        size_t ad_len = sizeof(ad) - 1;

        std::vector<uint8_t> ciphertext(pt_len + keylock::crypto::aead_aes256gcm::ABYTES);
        unsigned long long clen = 0;
        int result = keylock::crypto::aead_aes256gcm::encrypt(ciphertext.data(), &clen, plaintext, pt_len, ad, ad_len,
                                                              nullptr, nonce.data(), key.data());
        CHECK(result == 0);
        CHECK(clen == pt_len + keylock::crypto::aead_aes256gcm::ABYTES);

        std::vector<uint8_t> decrypted(pt_len);
        unsigned long long mlen = 0;
        result = keylock::crypto::aead_aes256gcm::decrypt(decrypted.data(), &mlen, nullptr, ciphertext.data(), clen, ad,
                                                          ad_len, nonce.data(), key.data());
        CHECK(result == 0);
        CHECK(mlen == pt_len);
        CHECK(std::memcmp(decrypted.data(), plaintext, pt_len) == 0);
    }

    TEST_CASE("AES-256-GCM detached encrypt/decrypt") {
        auto key = hex_to_bytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        auto nonce = hex_to_bytes("010203040506070809101112");
        const uint8_t plaintext[] = "Detached mode test";
        size_t pt_len = sizeof(plaintext) - 1;
        const uint8_t ad[] = "auth data";
        size_t ad_len = sizeof(ad) - 1;

        std::vector<uint8_t> ciphertext(pt_len);
        uint8_t mac[16];
        unsigned long long maclen = 0;
        int result = keylock::crypto::aead_aes256gcm::encrypt_detached(ciphertext.data(), mac, &maclen, plaintext,
                                                                       pt_len, ad, ad_len, nullptr, nonce.data(),
                                                                       key.data());
        CHECK(result == 0);
        CHECK(maclen == 16);

        std::vector<uint8_t> decrypted(pt_len);
        result = keylock::crypto::aead_aes256gcm::decrypt_detached(decrypted.data(), nullptr, ciphertext.data(), pt_len,
                                                                   mac, ad, ad_len, nonce.data(), key.data());
        CHECK(result == 0);
        CHECK(std::memcmp(decrypted.data(), plaintext, pt_len) == 0);
    }

    TEST_CASE("AES-256-GCM empty message") {
        auto key = hex_to_bytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        auto nonce = hex_to_bytes("020304050607080910111213");
        const uint8_t ad[] = "only auth data";
        size_t ad_len = sizeof(ad) - 1;

        std::vector<uint8_t> ciphertext(keylock::crypto::aead_aes256gcm::ABYTES);
        unsigned long long clen = 0;
        int result = keylock::crypto::aead_aes256gcm::encrypt(ciphertext.data(), &clen, nullptr, 0, ad, ad_len, nullptr,
                                                              nonce.data(), key.data());
        CHECK(result == 0);
        CHECK(clen == keylock::crypto::aead_aes256gcm::ABYTES);

        unsigned long long mlen = 0;
        result = keylock::crypto::aead_aes256gcm::decrypt(nullptr, &mlen, nullptr, ciphertext.data(), clen, ad, ad_len,
                                                          nonce.data(), key.data());
        CHECK(result == 0);
        CHECK(mlen == 0);
    }

    TEST_CASE("AES-256-GCM no associated data") {
        auto key = hex_to_bytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        auto nonce = hex_to_bytes("030405060708091011121314");
        const uint8_t plaintext[] = "No AD";
        size_t pt_len = sizeof(plaintext) - 1;

        std::vector<uint8_t> ciphertext(pt_len + keylock::crypto::aead_aes256gcm::ABYTES);
        unsigned long long clen = 0;
        int result = keylock::crypto::aead_aes256gcm::encrypt(ciphertext.data(), &clen, plaintext, pt_len, nullptr, 0,
                                                              nullptr, nonce.data(), key.data());
        CHECK(result == 0);

        std::vector<uint8_t> decrypted(pt_len);
        unsigned long long mlen = 0;
        result = keylock::crypto::aead_aes256gcm::decrypt(decrypted.data(), &mlen, nullptr, ciphertext.data(), clen,
                                                          nullptr, 0, nonce.data(), key.data());
        CHECK(result == 0);
        CHECK(std::memcmp(decrypted.data(), plaintext, pt_len) == 0);
    }

    TEST_CASE("AES-256-GCM wrong key fails") {
        auto key1 = hex_to_bytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        auto key2 = hex_to_bytes("1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100");
        auto nonce = hex_to_bytes("040506070809101112131415");
        const uint8_t plaintext[] = "Secret";
        size_t pt_len = sizeof(plaintext) - 1;

        std::vector<uint8_t> ciphertext(pt_len + keylock::crypto::aead_aes256gcm::ABYTES);
        unsigned long long clen = 0;
        keylock::crypto::aead_aes256gcm::encrypt(ciphertext.data(), &clen, plaintext, pt_len, nullptr, 0, nullptr,
                                                 nonce.data(), key1.data());

        std::vector<uint8_t> decrypted(pt_len);
        unsigned long long mlen = 0;
        int result = keylock::crypto::aead_aes256gcm::decrypt(decrypted.data(), &mlen, nullptr, ciphertext.data(), clen,
                                                              nullptr, 0, nonce.data(), key2.data());
        CHECK(result != 0);
    }

    TEST_CASE("AES-256-GCM wrong nonce fails") {
        auto key = hex_to_bytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        auto nonce1 = hex_to_bytes("050607080910111213141516");
        auto nonce2 = hex_to_bytes("060708091011121314151617");
        const uint8_t plaintext[] = "Secret";
        size_t pt_len = sizeof(plaintext) - 1;

        std::vector<uint8_t> ciphertext(pt_len + keylock::crypto::aead_aes256gcm::ABYTES);
        unsigned long long clen = 0;
        keylock::crypto::aead_aes256gcm::encrypt(ciphertext.data(), &clen, plaintext, pt_len, nullptr, 0, nullptr,
                                                 nonce1.data(), key.data());

        std::vector<uint8_t> decrypted(pt_len);
        unsigned long long mlen = 0;
        int result = keylock::crypto::aead_aes256gcm::decrypt(decrypted.data(), &mlen, nullptr, ciphertext.data(), clen,
                                                              nullptr, 0, nonce2.data(), key.data());
        CHECK(result != 0);
    }

    TEST_CASE("AES-256-GCM modified ciphertext fails") {
        auto key = hex_to_bytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        auto nonce = hex_to_bytes("070809101112131415161718");
        const uint8_t plaintext[] = "Secret message";
        size_t pt_len = sizeof(plaintext) - 1;

        std::vector<uint8_t> ciphertext(pt_len + keylock::crypto::aead_aes256gcm::ABYTES);
        unsigned long long clen = 0;
        keylock::crypto::aead_aes256gcm::encrypt(ciphertext.data(), &clen, plaintext, pt_len, nullptr, 0, nullptr,
                                                 nonce.data(), key.data());

        // Modify ciphertext
        ciphertext[0] ^= 0x01;

        std::vector<uint8_t> decrypted(pt_len);
        unsigned long long mlen = 0;
        int result = keylock::crypto::aead_aes256gcm::decrypt(decrypted.data(), &mlen, nullptr, ciphertext.data(), clen,
                                                              nullptr, 0, nonce.data(), key.data());
        CHECK(result != 0);
    }

    TEST_CASE("AES-256-GCM modified AD fails") {
        auto key = hex_to_bytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        auto nonce = hex_to_bytes("080910111213141516171819");
        const uint8_t plaintext[] = "Secret";
        size_t pt_len = sizeof(plaintext) - 1;
        uint8_t ad[] = "associated data";
        size_t ad_len = sizeof(ad) - 1;

        std::vector<uint8_t> ciphertext(pt_len + keylock::crypto::aead_aes256gcm::ABYTES);
        unsigned long long clen = 0;
        keylock::crypto::aead_aes256gcm::encrypt(ciphertext.data(), &clen, plaintext, pt_len, ad, ad_len, nullptr,
                                                 nonce.data(), key.data());

        // Modify AD
        ad[0] ^= 0x01;

        std::vector<uint8_t> decrypted(pt_len);
        unsigned long long mlen = 0;
        int result = keylock::crypto::aead_aes256gcm::decrypt(decrypted.data(), &mlen, nullptr, ciphertext.data(), clen,
                                                              ad, ad_len, nonce.data(), key.data());
        CHECK(result != 0);
    }

    TEST_CASE("AES-256-GCM large message") {
        auto key = hex_to_bytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        auto nonce = hex_to_bytes("091011121314151617181920");
        std::vector<uint8_t> plaintext(10000, 0x42);

        std::vector<uint8_t> ciphertext(plaintext.size() + keylock::crypto::aead_aes256gcm::ABYTES);
        unsigned long long clen = 0;
        int result = keylock::crypto::aead_aes256gcm::encrypt(ciphertext.data(), &clen, plaintext.data(),
                                                              plaintext.size(), nullptr, 0, nullptr, nonce.data(),
                                                              key.data());
        CHECK(result == 0);

        std::vector<uint8_t> decrypted(plaintext.size());
        unsigned long long mlen = 0;
        result = keylock::crypto::aead_aes256gcm::decrypt(decrypted.data(), &mlen, nullptr, ciphertext.data(), clen,
                                                          nullptr, 0, nonce.data(), key.data());
        CHECK(result == 0);
        CHECK(std::memcmp(decrypted.data(), plaintext.data(), plaintext.size()) == 0);
    }

    TEST_CASE("AES-256-GCM constants") {
        CHECK(keylock::crypto::aead_aes256gcm::KEYBYTES == 32);
        CHECK(keylock::crypto::aead_aes256gcm::NPUBBYTES == 12);
        CHECK(keylock::crypto::aead_aes256gcm::ABYTES == 16);
    }
}
