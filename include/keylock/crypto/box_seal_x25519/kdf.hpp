#pragma once

// Key derivation for sealed box
// This matches libsodium's crypto_box_seal key derivation:
// key = BLAKE2b(shared_secret || ephemeral_pk || recipient_pk)

#include <cstddef>
#include <cstdint>

#include "keylock/hash/blake2b/blake2b.hpp"

namespace keylock::crypto::box_seal_kdf {

    // Derive encryption key for sealed box
    // Key derivation matches libsodium:
    // key = BLAKE2b-256(shared_secret || ephemeral_pk || recipient_pk)
    inline void derive_key(uint8_t key[32], const uint8_t shared_secret[32], const uint8_t ephemeral_pk[32],
                           const uint8_t recipient_pk[32]) {
        // Create input: shared_secret || ephemeral_pk || recipient_pk
        uint8_t input[96];
        for (int i = 0; i < 32; i++)
            input[i] = shared_secret[i];
        for (int i = 0; i < 32; i++)
            input[32 + i] = ephemeral_pk[i];
        for (int i = 0; i < 32; i++)
            input[64 + i] = recipient_pk[i];

        // Hash with BLAKE2b-256
        keylock::hash::blake2b::hash(key, 32, input, 96);

        // Wipe input
        for (int i = 0; i < 96; i++) {
            volatile uint8_t *p = &input[i];
            *p = 0;
        }
    }

    // Derive nonce for sealed box encryption
    // Nonce derivation matches libsodium (24 bytes for XSalsa20 / XChaCha20):
    // nonce = BLAKE2b-192(ephemeral_pk || recipient_pk)
    inline void derive_nonce(uint8_t nonce[24], const uint8_t ephemeral_pk[32], const uint8_t recipient_pk[32]) {
        // Create input: ephemeral_pk || recipient_pk
        uint8_t input[64];
        for (int i = 0; i < 32; i++)
            input[i] = ephemeral_pk[i];
        for (int i = 0; i < 32; i++)
            input[32 + i] = recipient_pk[i];

        // Hash with BLAKE2b-192 (24 bytes)
        keylock::hash::blake2b::hash(nonce, 24, input, 64);

        // Wipe input
        for (int i = 0; i < 64; i++) {
            volatile uint8_t *p = &input[i];
            *p = 0;
        }
    }

} // namespace keylock::crypto::box_seal_kdf
