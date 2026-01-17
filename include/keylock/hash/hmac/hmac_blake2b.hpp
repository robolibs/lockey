#pragma once

// HMAC-BLAKE2b
// Note: BLAKE2b has built-in keying, but this provides HMAC compatibility

#include <cstddef>
#include <cstdint>
#include <cstring>

#include "keylock/crypto/constant_time/wipe.hpp"
#include "keylock/hash/blake2b/blake2b.hpp"

namespace keylock::hash::hmac_blake2b {

    inline constexpr size_t BYTES = 64;
    inline constexpr size_t KEYBYTES_MAX = 128;

    struct Context {
        uint8_t key[128];
        blake2b::Context ctx;
    };

    inline void init(Context *ctx, const uint8_t *key, size_t key_size) {
        // Hash key if too long
        if (key_size > 128) {
            blake2b::hash(ctx->key, 64, key, key_size);
            key = ctx->key;
            key_size = 64;
        }

        // Compute inner key: padded key XOR 0x36
        for (size_t i = 0; i < key_size; ++i) {
            ctx->key[i] = key[i] ^ 0x36;
        }
        for (size_t i = key_size; i < 128; ++i) {
            ctx->key[i] = 0x36;
        }

        // Start computing inner hash
        blake2b::init(&ctx->ctx, 64);
        blake2b::update(&ctx->ctx, ctx->key, 128);
    }

    inline void update(Context *ctx, const uint8_t *message, size_t message_size) {
        blake2b::update(&ctx->ctx, message, message_size);
    }

    inline void final(Context *ctx, uint8_t hmac[64]) {
        // Finish computing inner hash
        blake2b::final(&ctx->ctx, hmac);

        // Compute outer key: padded key XOR 0x5c
        for (size_t i = 0; i < 128; ++i) {
            ctx->key[i] ^= 0x36 ^ 0x5c;
        }

        // Compute outer hash
        blake2b::init(&ctx->ctx, 64);
        blake2b::update(&ctx->ctx, ctx->key, 128);
        blake2b::update(&ctx->ctx, hmac, 64);
        blake2b::final(&ctx->ctx, hmac);

        crypto::constant_time::wipe(ctx, sizeof(*ctx));
    }

    // One-shot HMAC
    inline void hmac(uint8_t hmac[64], const uint8_t *key, size_t key_size, const uint8_t *message,
                     size_t message_size) {
        Context ctx;
        init(&ctx, key, key_size);
        update(&ctx, message, message_size);
        final(&ctx, hmac);
    }

} // namespace keylock::hash::hmac_blake2b
