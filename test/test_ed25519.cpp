#include "keylock/crypto/sign_ed25519/ed25519.hpp"
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

TEST_SUITE("Ed25519 Digital Signatures") {

    TEST_CASE("Ed25519 seed keypair generation") {
        // RFC 8032 test vector 1
        auto seed = hex_to_bytes("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
        uint8_t pk[32], sk[64];

        keylock::crypto::ed25519::seed_keypair(pk, sk, seed.data());

        std::string pk_hex = bytes_to_hex(pk, 32);
        CHECK(pk_hex == "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
    }

    TEST_CASE("Ed25519 sign and verify empty message") {
        // RFC 8032 test vector 1
        auto seed = hex_to_bytes("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
        uint8_t pk[32], sk[64];
        keylock::crypto::ed25519::seed_keypair(pk, sk, seed.data());

        uint8_t sig[64];
        keylock::crypto::ed25519::sign_detached(sig, nullptr, nullptr, 0, sk);

        std::string sig_hex = bytes_to_hex(sig, 64);
        CHECK(sig_hex == "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b");

        // Verify
        int result = keylock::crypto::ed25519::verify_detached(sig, nullptr, 0, pk);
        CHECK(result == 0);
    }

    TEST_CASE("Ed25519 sign and verify message") {
        // RFC 8032 test vector 2
        auto seed = hex_to_bytes("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb");
        uint8_t pk[32], sk[64];
        keylock::crypto::ed25519::seed_keypair(pk, sk, seed.data());

        const uint8_t msg[] = {0x72};
        uint8_t sig[64];
        keylock::crypto::ed25519::sign_detached(sig, nullptr, msg, 1, sk);

        std::string sig_hex = bytes_to_hex(sig, 64);
        CHECK(sig_hex == "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00");

        // Verify
        int result = keylock::crypto::ed25519::verify_detached(sig, msg, 1, pk);
        CHECK(result == 0);
    }

    TEST_CASE("Ed25519 random keypair") {
        uint8_t pk[32], sk[64];
        keylock::crypto::ed25519::keypair(pk, sk);

        // Both should be non-zero
        bool pk_non_zero = false, sk_non_zero = false;
        for (int i = 0; i < 32; ++i) {
            if (pk[i] != 0)
                pk_non_zero = true;
        }
        for (int i = 0; i < 64; ++i) {
            if (sk[i] != 0)
                sk_non_zero = true;
        }
        CHECK(pk_non_zero);
        CHECK(sk_non_zero);
    }

    TEST_CASE("Ed25519 sign/verify round trip") {
        uint8_t pk[32], sk[64];
        keylock::crypto::ed25519::keypair(pk, sk);

        const uint8_t msg[] = "Hello, Ed25519!";
        uint8_t sig[64];

        keylock::crypto::ed25519::sign_detached(sig, nullptr, msg, sizeof(msg) - 1, sk);
        int result = keylock::crypto::ed25519::verify_detached(sig, msg, sizeof(msg) - 1, pk);
        CHECK(result == 0);
    }

    TEST_CASE("Ed25519 wrong public key fails verification") {
        uint8_t pk1[32], sk1[64], pk2[32], sk2[64];
        keylock::crypto::ed25519::keypair(pk1, sk1);
        keylock::crypto::ed25519::keypair(pk2, sk2);

        const uint8_t msg[] = "Test message";
        uint8_t sig[64];

        keylock::crypto::ed25519::sign_detached(sig, nullptr, msg, sizeof(msg) - 1, sk1);

        // Verify with wrong public key should fail
        int result = keylock::crypto::ed25519::verify_detached(sig, msg, sizeof(msg) - 1, pk2);
        CHECK(result != 0);
    }

    TEST_CASE("Ed25519 modified message fails verification") {
        uint8_t pk[32], sk[64];
        keylock::crypto::ed25519::keypair(pk, sk);

        const uint8_t msg[] = "Original message";
        uint8_t sig[64];
        keylock::crypto::ed25519::sign_detached(sig, nullptr, msg, sizeof(msg) - 1, sk);

        // Modify message
        uint8_t modified_msg[] = "Modified message";
        int result = keylock::crypto::ed25519::verify_detached(sig, modified_msg, sizeof(modified_msg) - 1, pk);
        CHECK(result != 0);
    }

    TEST_CASE("Ed25519 modified signature fails verification") {
        uint8_t pk[32], sk[64];
        keylock::crypto::ed25519::keypair(pk, sk);

        const uint8_t msg[] = "Test message";
        uint8_t sig[64];
        keylock::crypto::ed25519::sign_detached(sig, nullptr, msg, sizeof(msg) - 1, sk);

        // Modify signature
        sig[0] ^= 0x01;
        int result = keylock::crypto::ed25519::verify_detached(sig, msg, sizeof(msg) - 1, pk);
        CHECK(result != 0);
    }

    TEST_CASE("Ed25519 deterministic signatures") {
        uint8_t pk[32], sk[64];
        keylock::crypto::ed25519::keypair(pk, sk);

        const uint8_t msg[] = "Same message";
        uint8_t sig1[64], sig2[64];

        keylock::crypto::ed25519::sign_detached(sig1, nullptr, msg, sizeof(msg) - 1, sk);
        keylock::crypto::ed25519::sign_detached(sig2, nullptr, msg, sizeof(msg) - 1, sk);

        // Ed25519 is deterministic
        CHECK(std::memcmp(sig1, sig2, 64) == 0);
    }

    TEST_CASE("Ed25519 large message") {
        uint8_t pk[32], sk[64];
        keylock::crypto::ed25519::keypair(pk, sk);

        std::vector<uint8_t> large_msg(10000, 0x42);
        uint8_t sig[64];

        keylock::crypto::ed25519::sign_detached(sig, nullptr, large_msg.data(), large_msg.size(), sk);
        int result = keylock::crypto::ed25519::verify_detached(sig, large_msg.data(), large_msg.size(), pk);
        CHECK(result == 0);
    }

    TEST_CASE("Ed25519 constants") {
        CHECK(keylock::crypto::ed25519::PUBLICKEYBYTES == 32);
        CHECK(keylock::crypto::ed25519::SECRETKEYBYTES == 64);
        CHECK(keylock::crypto::ed25519::BYTES == 64);
        CHECK(keylock::crypto::ed25519::SEEDBYTES == 32);
    }
}
