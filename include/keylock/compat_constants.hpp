#pragma once

// Compatibility constants and function wrappers for code that expects libsodium names.
// Provides libsodium-compatible API through our implementations.

#include <cstddef>
#include <cstdint>

#include "keylock/crypto/rng/randombytes.hpp"
#include "keylock/crypto/sign_ed25519/ed25519.hpp"

// Generic hash (BLAKE2b)
constexpr size_t crypto_generichash_BYTES = 32;
constexpr size_t crypto_generichash_BYTES_MIN = 16;
constexpr size_t crypto_generichash_BYTES_MAX = 64;
constexpr size_t crypto_generichash_KEYBYTES = 32;
constexpr size_t crypto_generichash_KEYBYTES_MIN = 16;
constexpr size_t crypto_generichash_KEYBYTES_MAX = 64;

// SHA-256
constexpr size_t crypto_hash_sha256_BYTES = 32;

// SHA-512
constexpr size_t crypto_hash_sha512_BYTES = 64;

// Ed25519 signatures
constexpr size_t crypto_sign_BYTES = 64;
constexpr size_t crypto_sign_PUBLICKEYBYTES = 32;
constexpr size_t crypto_sign_SECRETKEYBYTES = 64;
constexpr size_t crypto_sign_ed25519_BYTES = 64;
constexpr size_t crypto_sign_ed25519_PUBLICKEYBYTES = 32;
constexpr size_t crypto_sign_ed25519_SECRETKEYBYTES = 64;

// X25519 / sealed box
constexpr size_t crypto_box_PUBLICKEYBYTES = 32;
constexpr size_t crypto_box_SECRETKEYBYTES = 32;
constexpr size_t crypto_box_SEALBYTES = 48; // ephemeral pubkey (32) + MAC (16)

// Function wrappers

inline void randombytes_buf(void *buf, size_t size) { keylock::crypto::rng::randombytes_buf(buf, size); }

inline int crypto_sign_keypair(uint8_t *pk, uint8_t *sk) {
    keylock::crypto::ed25519::keypair(pk, sk);
    return 0;
}

inline int crypto_sign_ed25519_keypair(uint8_t *pk, uint8_t *sk) {
    keylock::crypto::ed25519::keypair(pk, sk);
    return 0;
}

inline int crypto_sign_detached(uint8_t *sig, unsigned long long *siglen, const uint8_t *m, unsigned long long mlen,
                                const uint8_t *sk) {
    return keylock::crypto::ed25519::sign_detached(sig, siglen, m, mlen, sk);
}

inline int crypto_sign_verify_detached(const uint8_t *sig, const uint8_t *m, unsigned long long mlen,
                                       const uint8_t *pk) {
    return keylock::crypto::ed25519::verify_detached(sig, m, mlen, pk);
}
