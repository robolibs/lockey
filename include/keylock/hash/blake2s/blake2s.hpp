#pragma once

// BLAKE2s hash function (32-bit optimized variant)
// RFC 7693 compliant

#include <cstddef>
#include <cstdint>
#include <cstring>

#include "keylock/crypto/constant_time/wipe.hpp"

namespace keylock::hash::blake2s {

    inline constexpr size_t BYTES = 32; // Max output size
    inline constexpr size_t BYTES_MIN = 1;
    inline constexpr size_t BYTES_MAX = 32;
    inline constexpr size_t KEYBYTES = 32; // Max key size
    inline constexpr size_t KEYBYTES_MAX = 32;
    inline constexpr size_t BLOCKBYTES = 64;
    inline constexpr size_t SALTBYTES = 8;
    inline constexpr size_t PERSONALBYTES = 8;

    namespace detail {

        inline constexpr uint32_t iv[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                                           0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};

        inline constexpr uint8_t sigma[10][16] = {{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
                                                  {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
                                                  {11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4},
                                                  {7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8},
                                                  {9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13},
                                                  {2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9},
                                                  {12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11},
                                                  {13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10},
                                                  {6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5},
                                                  {10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0}};

        inline uint32_t load32_le(const uint8_t s[4]) {
            return static_cast<uint32_t>(s[0]) | (static_cast<uint32_t>(s[1]) << 8) |
                   (static_cast<uint32_t>(s[2]) << 16) | (static_cast<uint32_t>(s[3]) << 24);
        }

        inline void store32_le(uint8_t out[4], uint32_t in) {
            out[0] = static_cast<uint8_t>(in & 0xff);
            out[1] = static_cast<uint8_t>((in >> 8) & 0xff);
            out[2] = static_cast<uint8_t>((in >> 16) & 0xff);
            out[3] = static_cast<uint8_t>((in >> 24) & 0xff);
        }

        inline uint32_t rotr32(uint32_t x, uint32_t n) { return (x >> n) | (x << (32 - n)); }

    } // namespace detail

    struct Context {
        uint32_t hash[8];
        uint64_t t; // Total bytes counter
        uint8_t buffer[64];
        size_t buffer_len;
        size_t hash_size;
    };

    namespace detail {

        inline void compress(Context *ctx, const uint8_t block[64], bool is_last) {
            uint32_t m[16];
            for (int i = 0; i < 16; ++i) {
                m[i] = load32_le(block + i * 4);
            }

            uint32_t v0 = ctx->hash[0], v8 = iv[0];
            uint32_t v1 = ctx->hash[1], v9 = iv[1];
            uint32_t v2 = ctx->hash[2], v10 = iv[2];
            uint32_t v3 = ctx->hash[3], v11 = iv[3];
            uint32_t v4 = ctx->hash[4], v12 = iv[4] ^ static_cast<uint32_t>(ctx->t);
            uint32_t v5 = ctx->hash[5], v13 = iv[5] ^ static_cast<uint32_t>(ctx->t >> 32);
            uint32_t v6 = ctx->hash[6], v14 = iv[6] ^ (is_last ? 0xFFFFFFFF : 0);
            uint32_t v7 = ctx->hash[7], v15 = iv[7];

#define BLAKE2S_G(a, b, c, d, x, y)                                                                                    \
    a = a + b + x;                                                                                                     \
    d = rotr32(d ^ a, 16);                                                                                             \
    c = c + d;                                                                                                         \
    b = rotr32(b ^ c, 12);                                                                                             \
    a = a + b + y;                                                                                                     \
    d = rotr32(d ^ a, 8);                                                                                              \
    c = c + d;                                                                                                         \
    b = rotr32(b ^ c, 7)

#define BLAKE2S_ROUND(i)                                                                                               \
    BLAKE2S_G(v0, v4, v8, v12, m[sigma[i][0]], m[sigma[i][1]]);                                                        \
    BLAKE2S_G(v1, v5, v9, v13, m[sigma[i][2]], m[sigma[i][3]]);                                                        \
    BLAKE2S_G(v2, v6, v10, v14, m[sigma[i][4]], m[sigma[i][5]]);                                                       \
    BLAKE2S_G(v3, v7, v11, v15, m[sigma[i][6]], m[sigma[i][7]]);                                                       \
    BLAKE2S_G(v0, v5, v10, v15, m[sigma[i][8]], m[sigma[i][9]]);                                                       \
    BLAKE2S_G(v1, v6, v11, v12, m[sigma[i][10]], m[sigma[i][11]]);                                                     \
    BLAKE2S_G(v2, v7, v8, v13, m[sigma[i][12]], m[sigma[i][13]]);                                                      \
    BLAKE2S_G(v3, v4, v9, v14, m[sigma[i][14]], m[sigma[i][15]])

            BLAKE2S_ROUND(0);
            BLAKE2S_ROUND(1);
            BLAKE2S_ROUND(2);
            BLAKE2S_ROUND(3);
            BLAKE2S_ROUND(4);
            BLAKE2S_ROUND(5);
            BLAKE2S_ROUND(6);
            BLAKE2S_ROUND(7);
            BLAKE2S_ROUND(8);
            BLAKE2S_ROUND(9);

#undef BLAKE2S_G
#undef BLAKE2S_ROUND

            ctx->hash[0] ^= v0 ^ v8;
            ctx->hash[1] ^= v1 ^ v9;
            ctx->hash[2] ^= v2 ^ v10;
            ctx->hash[3] ^= v3 ^ v11;
            ctx->hash[4] ^= v4 ^ v12;
            ctx->hash[5] ^= v5 ^ v13;
            ctx->hash[6] ^= v6 ^ v14;
            ctx->hash[7] ^= v7 ^ v15;
        }

    } // namespace detail

    inline void keyed_init(Context *ctx, size_t hash_size, const uint8_t *key, size_t key_size) {
        for (int i = 0; i < 8; ++i) {
            ctx->hash[i] = detail::iv[i];
        }
        // Parameter block: hash_size || key_size || fanout=1 || depth=1
        ctx->hash[0] ^= 0x01010000 ^ (static_cast<uint32_t>(key_size) << 8) ^ static_cast<uint32_t>(hash_size);
        ctx->t = 0;
        ctx->buffer_len = 0;
        ctx->hash_size = hash_size;
        std::memset(ctx->buffer, 0, sizeof(ctx->buffer));

        if (key_size > 0) {
            uint8_t key_block[64] = {0};
            std::memcpy(key_block, key, key_size);
            ctx->t = 64;
            detail::compress(ctx, key_block, false);
            crypto::constant_time::wipe(key_block, sizeof(key_block));
        }
    }

    inline void init(Context *ctx, size_t hash_size = BYTES) { keyed_init(ctx, hash_size, nullptr, 0); }

    inline void update(Context *ctx, const uint8_t *message, size_t message_size) {
        if (message_size == 0) {
            return;
        }

        // Fill buffer if partially filled
        if (ctx->buffer_len > 0) {
            size_t fill = 64 - ctx->buffer_len;
            if (fill > message_size) {
                fill = message_size;
            }
            std::memcpy(ctx->buffer + ctx->buffer_len, message, fill);
            ctx->buffer_len += fill;
            message += fill;
            message_size -= fill;

            if (ctx->buffer_len == 64 && message_size > 0) {
                ctx->t += 64;
                detail::compress(ctx, ctx->buffer, false);
                ctx->buffer_len = 0;
            }
        }

        // Process full blocks, keeping last block for final
        while (message_size > 64) {
            ctx->t += 64;
            detail::compress(ctx, message, false);
            message += 64;
            message_size -= 64;
        }

        // Buffer remaining bytes (always at least 1 if we had data)
        if (message_size > 0) {
            std::memcpy(ctx->buffer + ctx->buffer_len, message, message_size);
            ctx->buffer_len += message_size;
        }
    }

    inline void final(Context *ctx, uint8_t *hash) {
        ctx->t += ctx->buffer_len;

        // Pad with zeros
        if (ctx->buffer_len < 64) {
            std::memset(ctx->buffer + ctx->buffer_len, 0, 64 - ctx->buffer_len);
        }

        detail::compress(ctx, ctx->buffer, true);

        // Output
        for (size_t i = 0; i < ctx->hash_size / 4; ++i) {
            detail::store32_le(hash + i * 4, ctx->hash[i]);
        }
        // Handle partial last word
        size_t remaining = ctx->hash_size % 4;
        if (remaining > 0) {
            uint8_t temp[4];
            detail::store32_le(temp, ctx->hash[ctx->hash_size / 4]);
            std::memcpy(hash + (ctx->hash_size / 4) * 4, temp, remaining);
        }

        crypto::constant_time::wipe(ctx, sizeof(*ctx));
    }

    // One-shot keyed hash
    inline void keyed(uint8_t *hash, size_t hash_size, const uint8_t *key, size_t key_size, const uint8_t *message,
                      size_t message_size) {
        Context ctx;
        keyed_init(&ctx, hash_size, key, key_size);
        update(&ctx, message, message_size);
        final(&ctx, hash);
    }

    // One-shot unkeyed hash
    inline void hash(uint8_t *hash, size_t hash_size, const uint8_t *message, size_t message_size) {
        keyed(hash, hash_size, nullptr, 0, message, message_size);
    }

    // Convenience: default 32-byte output
    inline void hash(uint8_t hash[32], const uint8_t *message, size_t message_size) {
        keyed(hash, 32, nullptr, 0, message, message_size);
    }

    // Convenience: keyed with default 32-byte output
    inline void keyed(uint8_t hash[32], const uint8_t *key, size_t key_size, const uint8_t *message,
                      size_t message_size) {
        keyed(hash, 32, key, key_size, message, message_size);
    }

} // namespace keylock::hash::blake2s
