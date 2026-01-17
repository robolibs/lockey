#include "keylock/crypto/box_seal_x25519/seal.hpp"
#include "keylock/crypto/box_seal_x25519/x25519.hpp"
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

TEST_SUITE("X25519 Key Exchange") {

    TEST_CASE("X25519 public key derivation") {
        // RFC 7748 test vector
        auto sk = hex_to_bytes("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        uint8_t pk[32];

        keylock::crypto::x25519::public_key(pk, sk.data());

        std::string result = bytes_to_hex(pk, 32);
        CHECK(result == "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
    }

    TEST_CASE("X25519 scalar multiplication") {
        // RFC 7748 test vector - Bob's private key with Alice's public key
        auto bob_sk = hex_to_bytes("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
        auto alice_pk = hex_to_bytes("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
        uint8_t shared[32];

        keylock::crypto::x25519::scalarmult(shared, bob_sk.data(), alice_pk.data());

        std::string result = bytes_to_hex(shared, 32);
        CHECK(result == "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");
    }

    TEST_CASE("X25519 public_key consistency") {
        auto sk = hex_to_bytes("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        uint8_t pk1[32], pk2[32];

        // Calling public_key twice should produce the same result
        keylock::crypto::x25519::public_key(pk1, sk.data());
        keylock::crypto::x25519::public_key(pk2, sk.data());

        CHECK(std::memcmp(pk1, pk2, 32) == 0);
    }

    TEST_CASE("X25519 key exchange symmetry") {
        // Alice's keypair
        auto alice_sk = hex_to_bytes("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        uint8_t alice_pk[32];
        keylock::crypto::x25519::public_key(alice_pk, alice_sk.data());

        // Bob's keypair
        auto bob_sk = hex_to_bytes("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
        uint8_t bob_pk[32];
        keylock::crypto::x25519::public_key(bob_pk, bob_sk.data());

        // Shared secrets should match
        uint8_t alice_shared[32], bob_shared[32];
        keylock::crypto::x25519::scalarmult(alice_shared, alice_sk.data(), bob_pk);
        keylock::crypto::x25519::scalarmult(bob_shared, bob_sk.data(), alice_pk);

        CHECK(std::memcmp(alice_shared, bob_shared, 32) == 0);
    }

    TEST_CASE("X25519 different keys produce different shared secrets") {
        auto alice_sk = hex_to_bytes("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        auto bob_sk = hex_to_bytes("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
        auto eve_sk = hex_to_bytes("0000000000000000000000000000000000000000000000000000000000000001");

        uint8_t alice_pk[32], bob_pk[32], eve_pk[32];
        keylock::crypto::x25519::public_key(alice_pk, alice_sk.data());
        keylock::crypto::x25519::public_key(bob_pk, bob_sk.data());
        keylock::crypto::x25519::public_key(eve_pk, eve_sk.data());

        uint8_t shared_ab[32], shared_ae[32];
        keylock::crypto::x25519::scalarmult(shared_ab, alice_sk.data(), bob_pk);
        keylock::crypto::x25519::scalarmult(shared_ae, alice_sk.data(), eve_pk);

        CHECK(std::memcmp(shared_ab, shared_ae, 32) != 0);
    }

    TEST_CASE("Box seal keypair generation") {
        uint8_t pk[32], sk[32];
        keylock::crypto::box_seal::keypair(pk, sk);

        // Both should be non-zero
        bool pk_non_zero = false, sk_non_zero = false;
        for (int i = 0; i < 32; ++i) {
            if (pk[i] != 0)
                pk_non_zero = true;
            if (sk[i] != 0)
                sk_non_zero = true;
        }
        CHECK(pk_non_zero);
        CHECK(sk_non_zero);

        // Verify public key matches derived
        uint8_t derived_pk[32];
        keylock::crypto::x25519::public_key(derived_pk, sk);
        CHECK(std::memcmp(pk, derived_pk, 32) == 0);
    }

    TEST_CASE("Box seal encrypt/decrypt") {
        uint8_t pk[32], sk[32];
        keylock::crypto::box_seal::keypair(pk, sk);

        const uint8_t plaintext[] = "Hello, sealed box!";
        size_t pt_len = sizeof(plaintext) - 1;
        size_t ct_len = pt_len + keylock::crypto::box_seal::SEALBYTES;

        std::vector<uint8_t> ciphertext(ct_len);
        int seal_result = keylock::crypto::box_seal::seal(ciphertext.data(), plaintext, pt_len, pk);
        CHECK(seal_result == 0);

        std::vector<uint8_t> decrypted(pt_len);
        int open_result = keylock::crypto::box_seal::seal_open(decrypted.data(), ciphertext.data(), ct_len, pk, sk);
        CHECK(open_result == 0);
        CHECK(std::memcmp(decrypted.data(), plaintext, pt_len) == 0);
    }

    TEST_CASE("Box seal wrong key fails") {
        uint8_t pk1[32], sk1[32], pk2[32], sk2[32];
        keylock::crypto::box_seal::keypair(pk1, sk1);
        keylock::crypto::box_seal::keypair(pk2, sk2);

        const uint8_t plaintext[] = "Secret message";
        size_t pt_len = sizeof(plaintext) - 1;
        size_t ct_len = pt_len + keylock::crypto::box_seal::SEALBYTES;

        std::vector<uint8_t> ciphertext(ct_len);
        keylock::crypto::box_seal::seal(ciphertext.data(), plaintext, pt_len, pk1);

        // Try to open with wrong key
        std::vector<uint8_t> decrypted(pt_len);
        int result = keylock::crypto::box_seal::seal_open(decrypted.data(), ciphertext.data(), ct_len, pk2, sk2);
        CHECK(result != 0);
    }

    TEST_CASE("Box seal constants") {
        CHECK(keylock::crypto::box_seal::PUBLICKEYBYTES == 32);
        CHECK(keylock::crypto::box_seal::SECRETKEYBYTES == 32);
        CHECK(keylock::crypto::box_seal::SEALBYTES == 48); // 32 ephemeral pk + 16 MAC
    }
}
