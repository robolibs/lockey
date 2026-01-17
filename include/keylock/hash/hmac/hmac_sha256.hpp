#pragma once

// HMAC-SHA256

#include <cstddef>
#include <cstdint>
#include <cstring>

#include "keylock/crypto/constant_time/wipe.hpp"
#include "keylock/hash/sha256/sha256.hpp"

namespace keylock::hash::hmac_sha256 {

    inline constexpr size_t BYTES = 32;
    inline constexpr size_t KEYBYTES_MAX = 64;

    struct Context {
        uint8_t key[64];
        sha256::Context ctx;
    };

    inline void init(Context *ctx, const uint8_t *key, size_t key_size) {
        // Hash key if too long
        if (key_size > 64) {
            sha256::hash(ctx->key, key, key_size);
            key = ctx->key;
            key_size = 32;
        }

        // Compute inner key: padded key XOR 0x36
        for (size_t i = 0; i < key_size; ++i) {
            ctx->key[i] = key[i] ^ 0x36;
        }
        for (size_t i = key_size; i < 64; ++i) {
            ctx->key[i] = 0x36;
        }

        // Start computing inner hash
        sha256::init(&ctx->ctx);
        sha256::update(&ctx->ctx, ctx->key, 64);
    }

    inline void update(Context *ctx, const uint8_t *message, size_t message_size) {
        sha256::update(&ctx->ctx, message, message_size);
    }

    inline void final(Context *ctx, uint8_t hmac[32]) {
        // Finish computing inner hash
        sha256::final(&ctx->ctx, hmac);

        // Compute outer key: padded key XOR 0x5c
        for (size_t i = 0; i < 64; ++i) {
            ctx->key[i] ^= 0x36 ^ 0x5c;
        }

        // Compute outer hash
        sha256::init(&ctx->ctx);
        sha256::update(&ctx->ctx, ctx->key, 64);
        sha256::update(&ctx->ctx, hmac, 32);
        sha256::final(&ctx->ctx, hmac);

        crypto::constant_time::wipe(ctx, sizeof(*ctx));
    }

    // One-shot HMAC
    inline void hmac(uint8_t hmac[32], const uint8_t *key, size_t key_size, const uint8_t *message,
                     size_t message_size) {
        Context ctx;
        init(&ctx, key, key_size);
        update(&ctx, message, message_size);
        final(&ctx, hmac);
    }

} // namespace keylock::hash::hmac_sha256
