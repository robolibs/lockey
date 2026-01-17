#include "keylock/crypto/aes/aes.hpp"
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

TEST_SUITE("AES Block Cipher") {

    TEST_CASE("AES-128 block encryption NIST test vector") {
        // NIST FIPS 197 Appendix B test vector
        auto key = hex_to_bytes("2b7e151628aed2a6abf7158809cf4f3c");
        auto plaintext = hex_to_bytes("3243f6a8885a308d313198a2e0370734");

        keylock::crypto::aes::Context ctx;
        bool ok = keylock::crypto::aes::init(&ctx, key.data(), 16);
        CHECK(ok);

        uint8_t ciphertext[16];
        keylock::crypto::aes::encrypt_block(&ctx, plaintext.data(), ciphertext);

        std::string result = bytes_to_hex(ciphertext, 16);
        CHECK(result == "3925841d02dc09fbdc118597196a0b32");
    }

    TEST_CASE("AES-128 block decryption NIST test vector") {
        auto key = hex_to_bytes("2b7e151628aed2a6abf7158809cf4f3c");
        auto ciphertext = hex_to_bytes("3925841d02dc09fbdc118597196a0b32");

        keylock::crypto::aes::Context ctx;
        keylock::crypto::aes::init(&ctx, key.data(), 16);

        uint8_t plaintext[16];
        keylock::crypto::aes::decrypt_block(&ctx, ciphertext.data(), plaintext);

        std::string result = bytes_to_hex(plaintext, 16);
        CHECK(result == "3243f6a8885a308d313198a2e0370734");
    }

    TEST_CASE("AES-192 block encryption") {
        auto key = hex_to_bytes("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b");
        auto plaintext = hex_to_bytes("6bc1bee22e409f96e93d7e117393172a");

        keylock::crypto::aes::Context ctx;
        bool ok = keylock::crypto::aes::init(&ctx, key.data(), 24);
        CHECK(ok);

        uint8_t ciphertext[16];
        keylock::crypto::aes::encrypt_block(&ctx, plaintext.data(), ciphertext);

        std::string result = bytes_to_hex(ciphertext, 16);
        CHECK(result == "bd334f1d6e45f25ff712a214571fa5cc");
    }

    TEST_CASE("AES-256 block encryption") {
        auto key = hex_to_bytes("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4");
        auto plaintext = hex_to_bytes("6bc1bee22e409f96e93d7e117393172a");

        keylock::crypto::aes::Context ctx;
        bool ok = keylock::crypto::aes::init(&ctx, key.data(), 32);
        CHECK(ok);

        uint8_t ciphertext[16];
        keylock::crypto::aes::encrypt_block(&ctx, plaintext.data(), ciphertext);

        std::string result = bytes_to_hex(ciphertext, 16);
        CHECK(result == "f3eed1bdb5d2a03c064b5a7e3db181f8");
    }

    TEST_CASE("AES encrypt/decrypt round trip") {
        auto key = hex_to_bytes("000102030405060708090a0b0c0d0e0f");
        auto plaintext = hex_to_bytes("00112233445566778899aabbccddeeff");

        keylock::crypto::aes::Context ctx;
        keylock::crypto::aes::init(&ctx, key.data(), 16);

        uint8_t ciphertext[16];
        keylock::crypto::aes::encrypt_block(&ctx, plaintext.data(), ciphertext);

        uint8_t recovered[16];
        keylock::crypto::aes::decrypt_block(&ctx, ciphertext, recovered);

        CHECK(std::memcmp(recovered, plaintext.data(), 16) == 0);
    }

    TEST_CASE("AES-128-CTR encryption") {
        // NIST SP 800-38A test vector
        auto key = hex_to_bytes("2b7e151628aed2a6abf7158809cf4f3c");
        auto nonce = hex_to_bytes("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
        auto plaintext = hex_to_bytes("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710");

        keylock::crypto::aes::Context ctx;
        keylock::crypto::aes::init(&ctx, key.data(), 16);

        std::vector<uint8_t> ciphertext(plaintext.size());
        keylock::crypto::aes::ctr_crypt(&ctx, nonce.data(), plaintext.data(), ciphertext.data(), plaintext.size());

        std::string result = bytes_to_hex(ciphertext.data(), ciphertext.size());
        CHECK(result == "874d6191b620e3261bef6864990db6ce9806f66b7970fdff8617187bb9fffdff5ae4df3edbd5d35e5b4f09020db03eab1e031dda2fbe03d1792170a0f3009cee");
    }

    TEST_CASE("AES-CTR encryption/decryption round trip") {
        auto key = hex_to_bytes("000102030405060708090a0b0c0d0e0f");
        auto nonce = hex_to_bytes("00000000000000000000000000000000");
        const uint8_t plaintext[] = "Hello, World! This is a test message for AES-CTR.";

        keylock::crypto::aes::Context ctx;
        keylock::crypto::aes::init(&ctx, key.data(), 16);

        std::vector<uint8_t> ciphertext(sizeof(plaintext) - 1);
        keylock::crypto::aes::ctr_crypt(&ctx, nonce.data(), plaintext, ciphertext.data(), sizeof(plaintext) - 1);

        // CTR mode is symmetric - decrypt by encrypting again
        std::vector<uint8_t> recovered(sizeof(plaintext) - 1);
        keylock::crypto::aes::ctr_crypt(&ctx, nonce.data(), ciphertext.data(), recovered.data(), ciphertext.size());

        CHECK(std::memcmp(recovered.data(), plaintext, sizeof(plaintext) - 1) == 0);
    }

    TEST_CASE("AES-128-CBC encryption") {
        // NIST SP 800-38A test vector
        auto key = hex_to_bytes("2b7e151628aed2a6abf7158809cf4f3c");
        auto iv = hex_to_bytes("000102030405060708090a0b0c0d0e0f");
        auto plaintext = hex_to_bytes("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710");

        keylock::crypto::aes::Context ctx;
        keylock::crypto::aes::init(&ctx, key.data(), 16);

        std::vector<uint8_t> ciphertext(plaintext.size());
        keylock::crypto::aes::cbc_encrypt(&ctx, iv.data(), plaintext.data(), ciphertext.data(), plaintext.size());

        std::string result = bytes_to_hex(ciphertext.data(), ciphertext.size());
        CHECK(result == "7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b273bed6b8e3c1743b7116e69e222295163ff1caa1681fac09120eca307586e1a7");
    }

    TEST_CASE("AES-128-CBC decryption") {
        auto key = hex_to_bytes("2b7e151628aed2a6abf7158809cf4f3c");
        auto iv = hex_to_bytes("000102030405060708090a0b0c0d0e0f");
        auto ciphertext = hex_to_bytes("7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b273bed6b8e3c1743b7116e69e222295163ff1caa1681fac09120eca307586e1a7");

        keylock::crypto::aes::Context ctx;
        keylock::crypto::aes::init(&ctx, key.data(), 16);

        std::vector<uint8_t> plaintext(ciphertext.size());
        keylock::crypto::aes::cbc_decrypt(&ctx, iv.data(), ciphertext.data(), plaintext.data(), ciphertext.size());

        std::string result = bytes_to_hex(plaintext.data(), plaintext.size());
        CHECK(result == "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710");
    }

    TEST_CASE("AES-CBC encryption/decryption round trip") {
        auto key = hex_to_bytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        auto iv = hex_to_bytes("00000000000000000000000000000000");
        auto plaintext = hex_to_bytes("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");

        keylock::crypto::aes::Context ctx;
        keylock::crypto::aes::init(&ctx, key.data(), 32);

        std::vector<uint8_t> ciphertext(plaintext.size());
        keylock::crypto::aes::cbc_encrypt(&ctx, iv.data(), plaintext.data(), ciphertext.data(), plaintext.size());

        std::vector<uint8_t> recovered(plaintext.size());
        keylock::crypto::aes::cbc_decrypt(&ctx, iv.data(), ciphertext.data(), recovered.data(), ciphertext.size());

        CHECK(std::memcmp(recovered.data(), plaintext.data(), plaintext.size()) == 0);
    }

    TEST_CASE("AES invalid key size") {
        uint8_t key[15] = {0}; // Invalid size (not 16, 24, or 32)
        keylock::crypto::aes::Context ctx;
        bool ok = keylock::crypto::aes::init(&ctx, key, 15);
        CHECK(!ok);
    }

    TEST_CASE("AES-256-CTR with 256-bit key") {
        auto key = hex_to_bytes("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4");
        auto nonce = hex_to_bytes("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
        auto plaintext = hex_to_bytes("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51");

        keylock::crypto::aes::Context ctx;
        keylock::crypto::aes::init(&ctx, key.data(), 32);

        std::vector<uint8_t> ciphertext(plaintext.size());
        keylock::crypto::aes::ctr_crypt(&ctx, nonce.data(), plaintext.data(), ciphertext.data(), plaintext.size());

        // Verify decryption works
        std::vector<uint8_t> recovered(plaintext.size());
        keylock::crypto::aes::ctr_crypt(&ctx, nonce.data(), ciphertext.data(), recovered.data(), ciphertext.size());

        CHECK(std::memcmp(recovered.data(), plaintext.data(), plaintext.size()) == 0);
    }

    TEST_CASE("AES different keys produce different ciphertext") {
        auto key1 = hex_to_bytes("00000000000000000000000000000001");
        auto key2 = hex_to_bytes("00000000000000000000000000000002");
        auto plaintext = hex_to_bytes("00000000000000000000000000000000");

        keylock::crypto::aes::Context ctx1, ctx2;
        keylock::crypto::aes::init(&ctx1, key1.data(), 16);
        keylock::crypto::aes::init(&ctx2, key2.data(), 16);

        uint8_t ciphertext1[16], ciphertext2[16];
        keylock::crypto::aes::encrypt_block(&ctx1, plaintext.data(), ciphertext1);
        keylock::crypto::aes::encrypt_block(&ctx2, plaintext.data(), ciphertext2);

        CHECK(std::memcmp(ciphertext1, ciphertext2, 16) != 0);
    }
}
