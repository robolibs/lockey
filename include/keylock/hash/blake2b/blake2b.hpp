#pragma once

// BLAKE2b hash function
// Adapted from Monocypher (public domain)

#include <cstddef>
#include <cstdint>
#include <cstring>

#include "keylock/crypto/constant_time/wipe.hpp"

namespace keylock::hash::blake2b {

    inline constexpr size_t BYTES = 64; // Max output size
    inline constexpr size_t BYTES_MIN = 1;
    inline constexpr size_t BYTES_MAX = 64;
    inline constexpr size_t KEYBYTES = 64; // Max key size
    inline constexpr size_t KEYBYTES_MIN = 0;
    inline constexpr size_t KEYBYTES_MAX = 64;

    namespace detail {

        inline constexpr uint64_t iv[8] = {
            0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL, 0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
            0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL, 0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL,
        };

        inline constexpr uint8_t sigma[12][16] = {
            {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
            {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
            {11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4},
            {7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8},
            {9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13},
            {2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9},
            {12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11},
            {13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10},
            {6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5},
            {10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0},
            {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
            {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
        };

        inline uint64_t load64_le(const uint8_t s[8]) {
            return static_cast<uint64_t>(s[0]) | (static_cast<uint64_t>(s[1]) << 8) |
                   (static_cast<uint64_t>(s[2]) << 16) | (static_cast<uint64_t>(s[3]) << 24) |
                   (static_cast<uint64_t>(s[4]) << 32) | (static_cast<uint64_t>(s[5]) << 40) |
                   (static_cast<uint64_t>(s[6]) << 48) | (static_cast<uint64_t>(s[7]) << 56);
        }

        inline void store64_le(uint8_t out[8], uint64_t in) {
            out[0] = static_cast<uint8_t>(in & 0xff);
            out[1] = static_cast<uint8_t>((in >> 8) & 0xff);
            out[2] = static_cast<uint8_t>((in >> 16) & 0xff);
            out[3] = static_cast<uint8_t>((in >> 24) & 0xff);
            out[4] = static_cast<uint8_t>((in >> 32) & 0xff);
            out[5] = static_cast<uint8_t>((in >> 40) & 0xff);
            out[6] = static_cast<uint8_t>((in >> 48) & 0xff);
            out[7] = static_cast<uint8_t>((in >> 56) & 0xff);
        }

        inline void load64_le_buf(uint64_t *dst, const uint8_t *src, size_t size) {
            for (size_t i = 0; i < size; ++i) {
                dst[i] = load64_le(src + i * 8);
            }
        }

        inline void store64_le_buf(uint8_t *dst, const uint64_t *src, size_t size) {
            for (size_t i = 0; i < size; ++i) {
                store64_le(dst + i * 8, src[i]);
            }
        }

        inline uint64_t rotr64(uint64_t x, uint64_t n) { return (x >> n) | (x << (64 - n)); }

        inline size_t gap(size_t x, size_t pow_2) { return (~x + 1) & (pow_2 - 1); }

        inline size_t min_val(size_t a, size_t b) { return a <= b ? a : b; }

    } // namespace detail

    struct Context {
        uint64_t hash[8];
        uint64_t input_offset[2];
        uint64_t input[16];
        size_t input_idx;
        size_t hash_size;
    };

    namespace detail {

        inline void compress(Context *ctx, int is_last_block) {
            uint64_t *x = ctx->input_offset;
            size_t y = ctx->input_idx;
            x[0] += y;
            if (x[0] < y) {
                x[1]++;
            }

            uint64_t v0 = ctx->hash[0], v8 = iv[0];
            uint64_t v1 = ctx->hash[1], v9 = iv[1];
            uint64_t v2 = ctx->hash[2], v10 = iv[2];
            uint64_t v3 = ctx->hash[3], v11 = iv[3];
            uint64_t v4 = ctx->hash[4], v12 = iv[4] ^ ctx->input_offset[0];
            uint64_t v5 = ctx->hash[5], v13 = iv[5] ^ ctx->input_offset[1];
            uint64_t v6 = ctx->hash[6], v14 = iv[6] ^ static_cast<uint64_t>(~(is_last_block - 1));
            uint64_t v7 = ctx->hash[7], v15 = iv[7];

            uint64_t *input = ctx->input;

#define BLAKE2_G(a, b, c, d, x, y)                                                                                     \
    a += b + x;                                                                                                        \
    d = rotr64(d ^ a, 32);                                                                                             \
    c += d;                                                                                                            \
    b = rotr64(b ^ c, 24);                                                                                             \
    a += b + y;                                                                                                        \
    d = rotr64(d ^ a, 16);                                                                                             \
    c += d;                                                                                                            \
    b = rotr64(b ^ c, 63)

#define BLAKE2_ROUND(i)                                                                                                \
    BLAKE2_G(v0, v4, v8, v12, input[sigma[i][0]], input[sigma[i][1]]);                                                 \
    BLAKE2_G(v1, v5, v9, v13, input[sigma[i][2]], input[sigma[i][3]]);                                                 \
    BLAKE2_G(v2, v6, v10, v14, input[sigma[i][4]], input[sigma[i][5]]);                                                \
    BLAKE2_G(v3, v7, v11, v15, input[sigma[i][6]], input[sigma[i][7]]);                                                \
    BLAKE2_G(v0, v5, v10, v15, input[sigma[i][8]], input[sigma[i][9]]);                                                \
    BLAKE2_G(v1, v6, v11, v12, input[sigma[i][10]], input[sigma[i][11]]);                                              \
    BLAKE2_G(v2, v7, v8, v13, input[sigma[i][12]], input[sigma[i][13]]);                                               \
    BLAKE2_G(v3, v4, v9, v14, input[sigma[i][14]], input[sigma[i][15]])

            BLAKE2_ROUND(0);
            BLAKE2_ROUND(1);
            BLAKE2_ROUND(2);
            BLAKE2_ROUND(3);
            BLAKE2_ROUND(4);
            BLAKE2_ROUND(5);
            BLAKE2_ROUND(6);
            BLAKE2_ROUND(7);
            BLAKE2_ROUND(8);
            BLAKE2_ROUND(9);
            BLAKE2_ROUND(10);
            BLAKE2_ROUND(11);

#undef BLAKE2_G
#undef BLAKE2_ROUND

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
        ctx->hash[0] ^= 0x01010000 ^ (key_size << 8) ^ hash_size;

        ctx->input_offset[0] = 0;
        ctx->input_offset[1] = 0;
        ctx->hash_size = hash_size;
        ctx->input_idx = 0;
        std::memset(ctx->input, 0, sizeof(ctx->input));

        if (key_size > 0) {
            uint8_t key_block[128] = {0};
            std::memcpy(key_block, key, key_size);
            detail::load64_le_buf(ctx->input, key_block, 16);
            ctx->input_idx = 128;
            crypto::constant_time::wipe(key_block, sizeof(key_block));
        }
    }

    inline void init(Context *ctx, size_t hash_size) { keyed_init(ctx, hash_size, nullptr, 0); }

    inline void update(Context *ctx, const uint8_t *message, size_t message_size) {
        if (message_size == 0) {
            return;
        }

        // Align with word boundaries
        if ((ctx->input_idx & 7) != 0) {
            size_t nb_bytes = detail::min_val(detail::gap(ctx->input_idx, 8), message_size);
            size_t word = ctx->input_idx >> 3;
            size_t byte = ctx->input_idx & 7;
            for (size_t i = 0; i < nb_bytes; ++i) {
                ctx->input[word] |= static_cast<uint64_t>(message[i]) << ((byte + i) << 3);
            }
            ctx->input_idx += nb_bytes;
            message += nb_bytes;
            message_size -= nb_bytes;
        }

        // Align with block boundaries
        if ((ctx->input_idx & 127) != 0) {
            size_t nb_words = detail::min_val(detail::gap(ctx->input_idx, 128), message_size) >> 3;
            detail::load64_le_buf(ctx->input + (ctx->input_idx >> 3), message, nb_words);
            ctx->input_idx += nb_words << 3;
            message += nb_words << 3;
            message_size -= nb_words << 3;
        }

        // Process block by block
        size_t nb_blocks = message_size >> 7;
        for (size_t i = 0; i < nb_blocks; ++i) {
            if (ctx->input_idx == 128) {
                detail::compress(ctx, 0);
            }
            detail::load64_le_buf(ctx->input, message, 16);
            message += 128;
            ctx->input_idx = 128;
        }
        message_size &= 127;

        if (message_size != 0) {
            if (ctx->input_idx == 128) {
                detail::compress(ctx, 0);
                ctx->input_idx = 0;
            }
            if (ctx->input_idx == 0) {
                std::memset(ctx->input, 0, sizeof(ctx->input));
            }
            size_t nb_words = message_size >> 3;
            detail::load64_le_buf(ctx->input, message, nb_words);
            ctx->input_idx += nb_words << 3;
            message += nb_words << 3;
            message_size -= nb_words << 3;

            for (size_t i = 0; i < message_size; ++i) {
                size_t word = ctx->input_idx >> 3;
                size_t byte = ctx->input_idx & 7;
                ctx->input[word] |= static_cast<uint64_t>(message[i]) << (byte << 3);
                ctx->input_idx++;
            }
        }
    }

    inline void final(Context *ctx, uint8_t *hash) {
        detail::compress(ctx, 1);
        size_t hash_size = detail::min_val(ctx->hash_size, 64);
        size_t nb_words = hash_size >> 3;
        detail::store64_le_buf(hash, ctx->hash, nb_words);
        for (size_t i = nb_words << 3; i < hash_size; ++i) {
            hash[i] = static_cast<uint8_t>((ctx->hash[i >> 3] >> (8 * (i & 7))) & 0xff);
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

    // Convenience: default 32-byte output (matching crypto_generichash_BYTES)
    inline void generichash(uint8_t hash[32], const uint8_t *message, size_t message_size) {
        keyed(hash, 32, nullptr, 0, message, message_size);
    }

    // Convenience: keyed with default 32-byte output
    inline void generichash_keyed(uint8_t hash[32], const uint8_t *key, size_t key_size, const uint8_t *message,
                                  size_t message_size) {
        keyed(hash, 32, key, key_size, message, message_size);
    }

} // namespace keylock::hash::blake2b
