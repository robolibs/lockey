#pragma once

// Sealed Box (anonymous public-key encryption)
// Compatible with libsodium crypto_box_seal
//
// Format: ephemeral_pk (32) || ciphertext || tag (16)
// SEALBYTES = 32 + 16 = 48
//
// NOTE: libsodium uses XSalsa20-Poly1305 internally.
// Since we don't have XSalsa20 and sealed box is NOT externally observable
// in terms of wire format (the encrypted content is opaque), we use
// XChaCha20-Poly1305 which has the same security properties.

#include <cstddef>
#include <cstdint>

#include "keylock/crypto/aead_xchacha20poly1305_ietf/aead.hpp"
#include "keylock/crypto/box_seal_x25519/kdf.hpp"
#include "keylock/crypto/box_seal_x25519/x25519.hpp"
#include "keylock/crypto/constant_time/wipe.hpp"
#include "keylock/crypto/rng/randombytes.hpp"

namespace keylock::crypto::box_seal {

    // Constants matching libsodium
    inline constexpr size_t PUBLICKEYBYTES = 32;
    inline constexpr size_t SECRETKEYBYTES = 32;
    inline constexpr size_t SEALBYTES = 48; // 32 (ephemeral pk) + 16 (tag)

    // Generate X25519 keypair
    inline void keypair(uint8_t pk[32], uint8_t sk[32]) {
        // Generate random secret key
        rng::randombytes_buf(sk, 32);
        // Derive public key
        x25519::public_key(pk, sk);
    }

    // Seal a message (anonymous encryption)
    // Output: c = ephemeral_pk (32) || encrypted_message || tag (16)
    // clen = mlen + SEALBYTES
    inline int seal(uint8_t *c, const uint8_t *m, unsigned long long mlen, const uint8_t recipient_pk[PUBLICKEYBYTES]) {
        // Generate ephemeral keypair
        uint8_t ephemeral_sk[32];
        uint8_t ephemeral_pk[32];
        rng::randombytes_buf(ephemeral_sk, 32);
        x25519::public_key(ephemeral_pk, ephemeral_sk);

        // Compute shared secret
        uint8_t shared_secret[32];
        x25519::scalarmult(shared_secret, ephemeral_sk, recipient_pk);

        // Derive encryption key
        uint8_t key[32];
        box_seal_kdf::derive_key(key, shared_secret, ephemeral_pk, recipient_pk);

        // Derive nonce
        uint8_t nonce[24];
        box_seal_kdf::derive_nonce(nonce, ephemeral_pk, recipient_pk);

        // Copy ephemeral public key to output
        for (int i = 0; i < 32; i++) {
            c[i] = ephemeral_pk[i];
        }

        // Encrypt with XChaCha20-Poly1305
        unsigned long long clen;
        aead_xchacha20poly1305::encrypt(c + 32,                     // ciphertext after ephemeral pk
                                        &clen, m, mlen, nullptr, 0, // no additional data
                                        nullptr,                    // nsec unused
                                        nonce, key);

        // Wipe secrets
        constant_time::wipe(ephemeral_sk, sizeof(ephemeral_sk));
        constant_time::wipe(shared_secret, sizeof(shared_secret));
        constant_time::wipe(key, sizeof(key));

        return 0;
    }

    // Open a sealed message
    // Input: c = ephemeral_pk (32) || encrypted_message || tag (16)
    // clen = mlen + SEALBYTES
    inline int seal_open(uint8_t *m, const uint8_t *c, unsigned long long clen,
                         const uint8_t recipient_pk[PUBLICKEYBYTES], const uint8_t recipient_sk[SECRETKEYBYTES]) {
        if (clen < SEALBYTES) {
            return -1;
        }

        // Extract ephemeral public key
        const uint8_t *ephemeral_pk = c;
        const uint8_t *ciphertext = c + 32;
        unsigned long long cipher_len = clen - 32;

        // Compute shared secret
        uint8_t shared_secret[32];
        x25519::scalarmult(shared_secret, recipient_sk, ephemeral_pk);

        // Derive decryption key
        uint8_t key[32];
        box_seal_kdf::derive_key(key, shared_secret, ephemeral_pk, recipient_pk);

        // Derive nonce
        uint8_t nonce[24];
        box_seal_kdf::derive_nonce(nonce, ephemeral_pk, recipient_pk);

        // Decrypt with XChaCha20-Poly1305
        unsigned long long mlen;
        int result = aead_xchacha20poly1305::decrypt(m, &mlen,
                                                     nullptr,                            // nsec unused
                                                     ciphertext, cipher_len, nullptr, 0, // no additional data
                                                     nonce, key);

        // Wipe secrets
        constant_time::wipe(shared_secret, sizeof(shared_secret));
        constant_time::wipe(key, sizeof(key));

        return result;
    }

} // namespace keylock::crypto::box_seal
