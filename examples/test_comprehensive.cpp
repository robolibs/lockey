#include "keylock/keylock.hpp"
#include <cassert>
#include <cstdio>
#include <iostream>

void print_hex(const std::string &label, const std::vector<uint8_t> &data) {
    std::cout << label << ": ";
    for (uint8_t byte : data)
        printf("%02x", byte);
    std::cout << '\n';
}

int main() {
    std::cout << "Comprehensive keylock (libsodium) demo\n";
    std::cout << "=====================================\n\n";

    const std::string message = "Test message for libsodium-backed keylock";
    const std::vector<uint8_t> payload(message.begin(), message.end());

    // Symmetric encryption with XChaCha20-Poly1305
    {
        keylock::keylock crypto(keylock::keylock::Algorithm::XChaCha20_Poly1305);
        auto key = crypto.generate_symmetric_key(keylock::utils::Common::XCHACHA20_KEY_SIZE);
        assert(key.success);

        auto ciphertext = crypto.encrypt(payload, key.data);
        assert(ciphertext.success);
        auto plaintext = crypto.decrypt(ciphertext.data, key.data);
        assert(plaintext.success && plaintext.data == payload);

        std::cout << "✓ XChaCha20-Poly1305 round-trip succeeded\n";
    }

    // SecretBox XSalsa20-Poly1305
    {
        keylock::keylock crypto(keylock::keylock::Algorithm::SecretBox_XSalsa20);
        auto key = crypto.generate_symmetric_key(keylock::utils::Common::SECRETBOX_KEY_SIZE);
        assert(key.success);
        auto ciphertext = crypto.encrypt(payload, key.data);
        assert(ciphertext.success);
        auto plaintext = crypto.decrypt(ciphertext.data, key.data);
        assert(plaintext.success && plaintext.data == payload);
        std::cout << "✓ SecretBox XSalsa20-Poly1305 round-trip succeeded\n";
    }

    // Hashing
    {
        keylock::keylock sha256(keylock::keylock::Algorithm::XChaCha20_Poly1305,
                              keylock::keylock::HashAlgorithm::SHA256);
        auto digest256 = sha256.hash(payload);
        assert(digest256.success && digest256.data.size() == keylock::utils::Common::SHA256_DIGEST_SIZE);

        keylock::keylock blake(keylock::keylock::Algorithm::XChaCha20_Poly1305,
                             keylock::keylock::HashAlgorithm::BLAKE2b);
        auto digestBlake = blake.hash(payload);
        assert(digestBlake.success && digestBlake.data.size() == keylock::utils::Common::BLAKE2B_DIGEST_SIZE);

        std::cout << "✓ Hashing (SHA-256 + BLAKE2b) succeeded\n";
    }

    // X25519 Box encryption
    {
        keylock::keylock box(keylock::keylock::Algorithm::X25519_Box);
        auto sender = box.generate_keypair();
        auto ciphertext = box.encrypt_asymmetric(payload, sender.public_key);
        assert(ciphertext.success);
        auto plaintext = box.decrypt_asymmetric(ciphertext.data, sender.private_key);
        assert(plaintext.success && plaintext.data == payload);
        std::cout << "✓ X25519 box seal/open succeeded\n";
    }

    // Ed25519 signatures
    {
        keylock::keylock signer(keylock::keylock::Algorithm::Ed25519);
        auto keypair = signer.generate_keypair();

        auto signature = signer.sign(payload, keypair.private_key);
        assert(signature.success && signature.data.size() == crypto_sign_ed25519_BYTES);

        auto verified = signer.verify(payload, signature.data, keypair.public_key);
        assert(verified.success);

        std::cout << "✓ Ed25519 signing/verification succeeded\n";
    }

    // Utility helpers
    {
        auto hex = keylock::keylock::to_hex(payload);
        auto decoded = keylock::keylock::from_hex(hex);
        assert(decoded == payload);

        std::cout << "✓ Utility conversions round-trip\n";
        print_hex("Payload hex", payload);
    }

    std::cout << "\nAll libsodium-backed demonstrations passed.\n";
    return 0;
}
