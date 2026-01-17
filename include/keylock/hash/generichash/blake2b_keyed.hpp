#pragma once

// Keyed BLAKE2b (generic hash with key)
// Compatible with libsodium crypto_generichash

#include <cstddef>
#include <cstdint>

#include "keylock/hash/blake2b/blake2b.hpp"

namespace keylock::hash::generichash {

    // Constants matching libsodium
    inline constexpr size_t BYTES = 32; // Default output size
    inline constexpr size_t BYTES_MIN = 16;
    inline constexpr size_t BYTES_MAX = 64;
    inline constexpr size_t KEYBYTES = 32; // Default key size
    inline constexpr size_t KEYBYTES_MIN = 16;
    inline constexpr size_t KEYBYTES_MAX = 64;

    using Context = blake2b::Context;

    // Initialize keyed hash
    inline void init(Context *ctx, size_t hash_size, const uint8_t *key, size_t key_size) {
        blake2b::keyed_init(ctx, hash_size, key, key_size);
    }

    // Initialize unkeyed hash
    inline void init(Context *ctx, size_t hash_size) { blake2b::init(ctx, hash_size); }

    inline void update(Context *ctx, const uint8_t *message, size_t message_size) {
        blake2b::update(ctx, message, message_size);
    }

    inline void final(Context *ctx, uint8_t *hash) { blake2b::final(ctx, hash); }

    // One-shot keyed hash
    inline void hash(uint8_t *out, size_t out_size, const uint8_t *in, size_t in_size, const uint8_t *key,
                     size_t key_size) {
        blake2b::keyed(out, out_size, key, key_size, in, in_size);
    }

    // One-shot unkeyed hash (libsodium crypto_generichash compatible)
    inline void hash(uint8_t *out, size_t out_size, const uint8_t *in, size_t in_size) {
        blake2b::hash(out, out_size, in, in_size);
    }

    // Default 32-byte output (matching crypto_generichash_BYTES)
    inline void generichash(uint8_t out[32], const uint8_t *in, size_t in_size) { blake2b::hash(out, 32, in, in_size); }

    // Default 32-byte output with key
    inline void generichash(uint8_t out[32], const uint8_t *in, size_t in_size, const uint8_t *key, size_t key_size) {
        blake2b::keyed(out, 32, key, key_size, in, in_size);
    }

} // namespace keylock::hash::generichash
