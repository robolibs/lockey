#pragma once

// Skein hash function family (Skein-256, Skein-512, Skein-1024)
// SHA-3 finalist based on Threefish block cipher
// Original digestpp implementation by kerukuro (public domain)

#include <cstddef>
#include <cstdint>
#include <cstring>

#include "keylock/crypto/constant_time/wipe.hpp"

namespace keylock::hash::skein {

    namespace detail {

        inline constexpr uint64_t SKEIN_KS_PARITY = 0x1BD11BDAA9FC1A22ULL;

        // Type field values
        inline constexpr uint64_t T_KEY = 0ULL;
        inline constexpr uint64_t T_CFG = 4ULL;
        inline constexpr uint64_t T_PRS = 8ULL;
        inline constexpr uint64_t T_MSG = 48ULL;
        inline constexpr uint64_t T_OUT = 63ULL;

        // Tweak flags
        inline constexpr uint64_t T_FIRST = 1ULL << 62;
        inline constexpr uint64_t T_FINAL = 1ULL << 63;

        inline uint64_t rotate_left(uint64_t x, int n) { return (x << n) | (x >> (64 - n)); }

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

        // Rotation constants for Skein-256 (4 words)
        inline constexpr unsigned C4[8][2] = {{14, 16}, {52, 57}, {23, 40}, {5, 37},
                                              {25, 33}, {46, 12}, {58, 22}, {32, 32}};

        // Rotation constants for Skein-512 (8 words)
        inline constexpr unsigned C8[8][4] = {{46, 36, 19, 37}, {33, 27, 14, 42}, {17, 49, 36, 39}, {44, 9, 54, 56},
                                              {39, 30, 34, 24}, {13, 50, 10, 17}, {25, 29, 39, 43}, {8, 35, 56, 22}};

        // Rotation constants for Skein-1024 (16 words)
        inline constexpr unsigned C16[8][8] = {{24, 13, 8, 47, 8, 17, 22, 37},   {38, 19, 10, 55, 49, 18, 23, 52},
                                               {33, 4, 51, 13, 34, 41, 59, 17},  {5, 20, 48, 41, 47, 28, 16, 25},
                                               {41, 9, 37, 31, 12, 47, 44, 30},  {16, 34, 56, 51, 4, 53, 42, 41},
                                               {31, 44, 47, 46, 19, 42, 44, 25}, {9, 48, 35, 52, 23, 31, 37, 20}};

        // Permutation indices for Skein-256
        inline constexpr unsigned I4[8][4] = {{0, 1, 2, 3}, {0, 3, 2, 1}, {0, 1, 2, 3}, {0, 3, 2, 1},
                                              {0, 1, 2, 3}, {0, 3, 2, 1}, {0, 1, 2, 3}, {0, 3, 2, 1}};

        // Permutation indices for Skein-512
        inline constexpr unsigned I8[8][8] = {
            {0, 1, 2, 3, 4, 5, 6, 7}, {2, 1, 4, 7, 6, 5, 0, 3}, {4, 1, 6, 3, 0, 5, 2, 7}, {6, 1, 0, 7, 2, 5, 4, 3},
            {0, 1, 2, 3, 4, 5, 6, 7}, {2, 1, 4, 7, 6, 5, 0, 3}, {4, 1, 6, 3, 0, 5, 2, 7}, {6, 1, 0, 7, 2, 5, 4, 3}};

        // Permutation indices for Skein-1024
        inline constexpr unsigned I16[8][16] = {{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
                                                {0, 9, 2, 13, 6, 11, 4, 15, 10, 7, 12, 3, 14, 5, 8, 1},
                                                {0, 7, 2, 5, 4, 3, 6, 1, 12, 15, 14, 13, 8, 11, 10, 9},
                                                {0, 15, 2, 11, 6, 13, 4, 9, 14, 1, 8, 5, 10, 3, 12, 7},
                                                {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
                                                {0, 9, 2, 13, 6, 11, 4, 15, 10, 7, 12, 3, 14, 5, 8, 1},
                                                {0, 7, 2, 5, 4, 3, 6, 1, 12, 15, 14, 13, 8, 11, 10, 9},
                                                {0, 15, 2, 11, 6, 13, 4, 9, 14, 1, 8, 5, 10, 3, 12, 7}};

    } // namespace detail

    // Skein-512 context (most common variant)
    struct Context512 {
        uint64_t H[8];      // Chaining value
        uint64_t tweak[2];  // Tweak
        uint8_t buffer[64]; // Message buffer
        size_t buffer_len;
        size_t hash_size; // Output size in bytes
        bool squeezing;
    };

    namespace detail {

        // Threefish-512 block cipher
        inline void threefish512(uint64_t *out, const uint64_t *key, const uint64_t *tweak, const uint64_t *msg) {
            uint64_t keys[9];
            uint64_t tweaks[3];
            uint64_t G[8];

            // Compute key schedule
            std::memcpy(keys, key, 64);
            keys[8] = SKEIN_KS_PARITY;
            for (int i = 0; i < 8; i++) {
                keys[8] ^= keys[i];
            }

            tweaks[0] = tweak[0];
            tweaks[1] = tweak[1];
            tweaks[2] = tweak[0] ^ tweak[1];

            // Initialize G with message XOR first subkey
            for (int i = 0; i < 8; i++) {
                G[i] = msg[i] + keys[i];
            }
            G[5] += tweaks[0];
            G[6] += tweaks[1];

#define MIX(a, b, r)                                                                                                   \
    G[a] += G[b];                                                                                                      \
    G[b] = rotate_left(G[b], r) ^ G[a]

#define ROUND512(r)                                                                                                    \
    MIX(I8[r % 8][0], I8[r % 8][1], C8[r % 8][0]);                                                                     \
    MIX(I8[r % 8][2], I8[r % 8][3], C8[r % 8][1]);                                                                     \
    MIX(I8[r % 8][4], I8[r % 8][5], C8[r % 8][2]);                                                                     \
    MIX(I8[r % 8][6], I8[r % 8][7], C8[r % 8][3])

#define SUBKEY512(s)                                                                                                   \
    G[0] += keys[(s + 0 + 1) % 9];                                                                                     \
    G[1] += keys[(s + 1 + 1) % 9];                                                                                     \
    G[2] += keys[(s + 2 + 1) % 9];                                                                                     \
    G[3] += keys[(s + 3 + 1) % 9];                                                                                     \
    G[4] += keys[(s + 4 + 1) % 9];                                                                                     \
    G[5] += keys[(s + 5 + 1) % 9] + tweaks[(s + 1) % 3];                                                               \
    G[6] += keys[(s + 6 + 1) % 9] + tweaks[(s + 2) % 3];                                                               \
    G[7] += keys[(s + 7 + 1) % 9] + s + 1

            // 72 rounds = 9 sets of 8 rounds
            for (int d = 0; d < 9; d++) {
                ROUND512(0);
                ROUND512(1);
                ROUND512(2);
                ROUND512(3);
                SUBKEY512(d * 2);
                ROUND512(4);
                ROUND512(5);
                ROUND512(6);
                ROUND512(7);
                SUBKEY512(d * 2 + 1);
            }

#undef MIX
#undef ROUND512
#undef SUBKEY512

            for (int i = 0; i < 8; i++) {
                out[i] = G[i] ^ msg[i];
            }
        }

        inline void ubi512(Context512 *ctx, const uint8_t *data, size_t len, uint64_t type_value, bool is_final) {
            uint64_t msg[8];

            // Set up tweak
            ctx->tweak[0] += len;
            ctx->tweak[1] = (type_value << 56) | T_FIRST;
            if (is_final) {
                ctx->tweak[1] |= T_FINAL;
            }

            // Load message block
            for (int i = 0; i < 8; i++) {
                msg[i] = load64_le(data + i * 8);
            }

            // Threefish encryption
            uint64_t result[8];
            threefish512(result, ctx->H, ctx->tweak, msg);

            // Update chaining value
            std::memcpy(ctx->H, result, 64);

            // Clear first block flag for subsequent blocks
            ctx->tweak[1] &= ~T_FIRST;
        }

    } // namespace detail

    inline void init_512(Context512 *ctx, size_t hash_bits = 512) {
        std::memset(ctx->H, 0, sizeof(ctx->H));
        ctx->tweak[0] = 0;
        ctx->tweak[1] = detail::T_FIRST | (detail::T_CFG << 56);
        ctx->buffer_len = 0;
        ctx->hash_size = hash_bits / 8;
        ctx->squeezing = false;

        // Process configuration block
        uint8_t cfg[64] = {0};
        cfg[0] = 'S';
        cfg[1] = 'H';
        cfg[2] = 'A';
        cfg[3] = '3';
        cfg[4] = 1; // Version
        // Output size in bits (little-endian)
        uint64_t out_bits = hash_bits;
        std::memcpy(cfg + 8, &out_bits, 8);

        detail::ubi512(ctx, cfg, 32, detail::T_CFG, true);

        // Reset tweak for message processing
        ctx->tweak[0] = 0;
        ctx->tweak[1] = detail::T_FIRST | (detail::T_MSG << 56);
    }

    inline void update_512(Context512 *ctx, const uint8_t *message, size_t message_size) {
        if (message_size == 0)
            return;

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
                ctx->tweak[0] += 64;
                uint64_t msg[8];
                for (int i = 0; i < 8; i++) {
                    msg[i] = detail::load64_le(ctx->buffer + i * 8);
                }
                uint64_t result[8];
                detail::threefish512(result, ctx->H, ctx->tweak, msg);
                std::memcpy(ctx->H, result, 64);
                ctx->tweak[1] &= ~detail::T_FIRST;
                ctx->buffer_len = 0;
            }
        }

        // Process full blocks
        while (message_size > 64) {
            ctx->tweak[0] += 64;
            uint64_t msg[8];
            for (int i = 0; i < 8; i++) {
                msg[i] = detail::load64_le(message + i * 8);
            }
            uint64_t result[8];
            detail::threefish512(result, ctx->H, ctx->tweak, msg);
            std::memcpy(ctx->H, result, 64);
            ctx->tweak[1] &= ~detail::T_FIRST;
            message += 64;
            message_size -= 64;
        }

        // Buffer remaining bytes
        if (message_size > 0) {
            std::memcpy(ctx->buffer + ctx->buffer_len, message, message_size);
            ctx->buffer_len += message_size;
        }
    }

    inline void final_512(Context512 *ctx, uint8_t *hash) {
        // Pad final block with zeros
        if (ctx->buffer_len < 64) {
            std::memset(ctx->buffer + ctx->buffer_len, 0, 64 - ctx->buffer_len);
        }

        // Process final message block
        ctx->tweak[0] += ctx->buffer_len;
        ctx->tweak[1] |= detail::T_FINAL;

        uint64_t msg[8];
        for (int i = 0; i < 8; i++) {
            msg[i] = detail::load64_le(ctx->buffer + i * 8);
        }
        uint64_t result[8];
        detail::threefish512(result, ctx->H, ctx->tweak, msg);
        std::memcpy(ctx->H, result, 64);

        // Output phase
        std::memset(ctx->buffer, 0, 64);
        ctx->tweak[0] = 8;
        ctx->tweak[1] = detail::T_FIRST | detail::T_FINAL | (detail::T_OUT << 56);

        size_t out_produced = 0;
        uint64_t counter = 0;

        while (out_produced < ctx->hash_size) {
            std::memcpy(ctx->buffer, &counter, 8);
            for (int i = 0; i < 8; i++) {
                msg[i] = detail::load64_le(ctx->buffer + i * 8);
            }
            detail::threefish512(result, ctx->H, ctx->tweak, msg);

            size_t to_copy = ctx->hash_size - out_produced;
            if (to_copy > 64)
                to_copy = 64;

            for (size_t i = 0; i < to_copy / 8; i++) {
                detail::store64_le(hash + out_produced + i * 8, result[i]);
            }
            size_t remaining = to_copy % 8;
            if (remaining > 0) {
                uint8_t temp[8];
                detail::store64_le(temp, result[to_copy / 8]);
                std::memcpy(hash + out_produced + (to_copy / 8) * 8, temp, remaining);
            }

            out_produced += to_copy;
            counter++;
        }

        crypto::constant_time::wipe(ctx, sizeof(*ctx));
    }

    // One-shot Skein-512
    inline void hash_512(uint8_t *hash, size_t hash_bits, const uint8_t *message, size_t message_size) {
        Context512 ctx;
        init_512(&ctx, hash_bits);
        update_512(&ctx, message, message_size);
        final_512(&ctx, hash);
    }

    // Convenience wrappers
    inline void skein512_256(uint8_t hash[32], const uint8_t *message, size_t message_size) {
        hash_512(hash, 256, message, message_size);
    }

    inline void skein512_512(uint8_t hash[64], const uint8_t *message, size_t message_size) {
        hash_512(hash, 512, message, message_size);
    }

    // Skein-256 context
    struct Context256 {
        uint64_t H[4];
        uint64_t tweak[2];
        uint8_t buffer[32];
        size_t buffer_len;
        size_t hash_size;
        bool squeezing;
    };

    namespace detail {

        inline void threefish256(uint64_t *out, const uint64_t *key, const uint64_t *tweak, const uint64_t *msg) {
            uint64_t keys[5];
            uint64_t tweaks[3];
            uint64_t G[4];

            std::memcpy(keys, key, 32);
            keys[4] = SKEIN_KS_PARITY ^ keys[0] ^ keys[1] ^ keys[2] ^ keys[3];

            tweaks[0] = tweak[0];
            tweaks[1] = tweak[1];
            tweaks[2] = tweak[0] ^ tweak[1];

            for (int i = 0; i < 4; i++) {
                G[i] = msg[i] + keys[i];
            }
            G[1] += tweaks[0];
            G[2] += tweaks[1];

#define MIX256(a, b, r)                                                                                                \
    G[a] += G[b];                                                                                                      \
    G[b] = rotate_left(G[b], r) ^ G[a]

#define ROUND256(r)                                                                                                    \
    MIX256(I4[r % 8][0], I4[r % 8][1], C4[r % 8][0]);                                                                  \
    MIX256(I4[r % 8][2], I4[r % 8][3], C4[r % 8][1])

#define SUBKEY256(s)                                                                                                   \
    G[0] += keys[(s + 0 + 1) % 5];                                                                                     \
    G[1] += keys[(s + 1 + 1) % 5] + tweaks[(s + 1) % 3];                                                               \
    G[2] += keys[(s + 2 + 1) % 5] + tweaks[(s + 2) % 3];                                                               \
    G[3] += keys[(s + 3 + 1) % 5] + s + 1

            // 72 rounds
            for (int d = 0; d < 9; d++) {
                ROUND256(0);
                ROUND256(1);
                ROUND256(2);
                ROUND256(3);
                SUBKEY256(d * 2);
                ROUND256(4);
                ROUND256(5);
                ROUND256(6);
                ROUND256(7);
                SUBKEY256(d * 2 + 1);
            }

#undef MIX256
#undef ROUND256
#undef SUBKEY256

            for (int i = 0; i < 4; i++) {
                out[i] = G[i] ^ msg[i];
            }
        }

    } // namespace detail

    inline void init_256(Context256 *ctx, size_t hash_bits = 256) {
        std::memset(ctx->H, 0, sizeof(ctx->H));
        ctx->tweak[0] = 0;
        ctx->tweak[1] = detail::T_FIRST | (detail::T_CFG << 56);
        ctx->buffer_len = 0;
        ctx->hash_size = hash_bits / 8;
        ctx->squeezing = false;

        uint8_t cfg[32] = {0};
        cfg[0] = 'S';
        cfg[1] = 'H';
        cfg[2] = 'A';
        cfg[3] = '3';
        cfg[4] = 1;
        uint64_t out_bits = hash_bits;
        std::memcpy(cfg + 8, &out_bits, 8);

        ctx->tweak[0] = 32;
        ctx->tweak[1] |= detail::T_FINAL;
        uint64_t msg[4];
        for (int i = 0; i < 4; i++) {
            msg[i] = detail::load64_le(cfg + i * 8);
        }
        uint64_t result[4];
        detail::threefish256(result, ctx->H, ctx->tweak, msg);
        std::memcpy(ctx->H, result, 32);

        ctx->tweak[0] = 0;
        ctx->tweak[1] = detail::T_FIRST | (detail::T_MSG << 56);
    }

    inline void update_256(Context256 *ctx, const uint8_t *message, size_t message_size) {
        if (message_size == 0)
            return;

        if (ctx->buffer_len > 0) {
            size_t fill = 32 - ctx->buffer_len;
            if (fill > message_size)
                fill = message_size;
            std::memcpy(ctx->buffer + ctx->buffer_len, message, fill);
            ctx->buffer_len += fill;
            message += fill;
            message_size -= fill;

            if (ctx->buffer_len == 32 && message_size > 0) {
                ctx->tweak[0] += 32;
                uint64_t msg[4];
                for (int i = 0; i < 4; i++) {
                    msg[i] = detail::load64_le(ctx->buffer + i * 8);
                }
                uint64_t result[4];
                detail::threefish256(result, ctx->H, ctx->tweak, msg);
                std::memcpy(ctx->H, result, 32);
                ctx->tweak[1] &= ~detail::T_FIRST;
                ctx->buffer_len = 0;
            }
        }

        while (message_size > 32) {
            ctx->tweak[0] += 32;
            uint64_t msg[4];
            for (int i = 0; i < 4; i++) {
                msg[i] = detail::load64_le(message + i * 8);
            }
            uint64_t result[4];
            detail::threefish256(result, ctx->H, ctx->tweak, msg);
            std::memcpy(ctx->H, result, 32);
            ctx->tweak[1] &= ~detail::T_FIRST;
            message += 32;
            message_size -= 32;
        }

        if (message_size > 0) {
            std::memcpy(ctx->buffer + ctx->buffer_len, message, message_size);
            ctx->buffer_len += message_size;
        }
    }

    inline void final_256(Context256 *ctx, uint8_t *hash) {
        if (ctx->buffer_len < 32) {
            std::memset(ctx->buffer + ctx->buffer_len, 0, 32 - ctx->buffer_len);
        }

        ctx->tweak[0] += ctx->buffer_len;
        ctx->tweak[1] |= detail::T_FINAL;

        uint64_t msg[4];
        for (int i = 0; i < 4; i++) {
            msg[i] = detail::load64_le(ctx->buffer + i * 8);
        }
        uint64_t result[4];
        detail::threefish256(result, ctx->H, ctx->tweak, msg);
        std::memcpy(ctx->H, result, 32);

        // Output
        std::memset(ctx->buffer, 0, 32);
        ctx->tweak[0] = 8;
        ctx->tweak[1] = detail::T_FIRST | detail::T_FINAL | (detail::T_OUT << 56);

        size_t out_produced = 0;
        uint64_t counter = 0;

        while (out_produced < ctx->hash_size) {
            std::memcpy(ctx->buffer, &counter, 8);
            for (int i = 0; i < 4; i++) {
                msg[i] = detail::load64_le(ctx->buffer + i * 8);
            }
            detail::threefish256(result, ctx->H, ctx->tweak, msg);

            size_t to_copy = ctx->hash_size - out_produced;
            if (to_copy > 32)
                to_copy = 32;

            for (size_t i = 0; i < to_copy / 8; i++) {
                detail::store64_le(hash + out_produced + i * 8, result[i]);
            }
            size_t remaining = to_copy % 8;
            if (remaining > 0) {
                uint8_t temp[8];
                detail::store64_le(temp, result[to_copy / 8]);
                std::memcpy(hash + out_produced + (to_copy / 8) * 8, temp, remaining);
            }

            out_produced += to_copy;
            counter++;
        }

        crypto::constant_time::wipe(ctx, sizeof(*ctx));
    }

    inline void hash_256(uint8_t *hash, size_t hash_bits, const uint8_t *message, size_t message_size) {
        Context256 ctx;
        init_256(&ctx, hash_bits);
        update_256(&ctx, message, message_size);
        final_256(&ctx, hash);
    }

    inline void skein256_256(uint8_t hash[32], const uint8_t *message, size_t message_size) {
        hash_256(hash, 256, message, message_size);
    }

    inline void skein256_128(uint8_t hash[16], const uint8_t *message, size_t message_size) {
        hash_256(hash, 128, message, message_size);
    }

} // namespace keylock::hash::skein
