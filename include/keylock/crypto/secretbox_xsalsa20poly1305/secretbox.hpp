#pragma once

// SecretBox symmetric encryption
// NOTE: Since Monocypher doesn't have XSalsa20, and SecretBox is NOT externally
// observable (no wire format compatibility required), we implement this using
// XChaCha20-Poly1305 with the same API contract as libsodium's secretbox.

#include <cstddef>
#include <cstdint>

#include "keylock/crypto/aead_xchacha20poly1305_ietf/aead.hpp"

namespace keylock::crypto::secretbox {

    // Constants matching libsodium
    inline constexpr size_t KEYBYTES = 32;
    inline constexpr size_t NONCEBYTES = 24;
    inline constexpr size_t MACBYTES = 16;

    // Encrypt with SecretBox
    // Output format: 16-byte tag || ciphertext
    // Note: libsodium puts tag first, unlike regular AEAD
    inline int easy(uint8_t *c, const uint8_t *m, unsigned long long mlen, const uint8_t nonce[NONCEBYTES],
                    const uint8_t key[KEYBYTES]) {
        // Use XChaCha20-Poly1305 internally
        // The output format is: tag (16 bytes) || ciphertext
        uint8_t mac[16];
        unsigned long long maclen;

        // Encrypt to ciphertext position (after tag space)
        aead_xchacha20poly1305::encrypt_detached(c + MACBYTES,                      // ciphertext after mac
                                                 mac, &maclen, m, mlen, nullptr, 0, // no additional data
                                                 nullptr, nonce, key);

        // Copy mac to front
        for (int i = 0; i < 16; ++i) {
            c[i] = mac[i];
        }

        return 0;
    }

    // Decrypt with SecretBox
    // Input format: 16-byte tag || ciphertext
    inline int open_easy(uint8_t *m, const uint8_t *c, unsigned long long clen, const uint8_t nonce[NONCEBYTES],
                         const uint8_t key[KEYBYTES]) {
        if (clen < MACBYTES) {
            return -1;
        }

        // Extract mac from front
        const uint8_t *mac = c;
        const uint8_t *ciphertext = c + MACBYTES;
        unsigned long long mlen = clen - MACBYTES;

        // Decrypt
        return aead_xchacha20poly1305::decrypt_detached(m, nullptr, ciphertext, mlen, mac, nullptr,
                                                        0, // no additional data
                                                        nonce, key);
    }

    // Detached encryption
    inline int detached(uint8_t *c, uint8_t mac[MACBYTES], const uint8_t *m, unsigned long long mlen,
                        const uint8_t nonce[NONCEBYTES], const uint8_t key[KEYBYTES]) {
        unsigned long long maclen;
        return aead_xchacha20poly1305::encrypt_detached(c, mac, &maclen, m, mlen, nullptr, 0, nullptr, nonce, key);
    }

    // Detached decryption
    inline int open_detached(uint8_t *m, const uint8_t *c, unsigned long long clen, const uint8_t mac[MACBYTES],
                             const uint8_t nonce[NONCEBYTES], const uint8_t key[KEYBYTES]) {
        return aead_xchacha20poly1305::decrypt_detached(m, nullptr, c, clen, mac, nullptr, 0, nonce, key);
    }

} // namespace keylock::crypto::secretbox
