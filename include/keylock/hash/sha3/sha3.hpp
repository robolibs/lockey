#pragma once

// SHA-3 hash function family (SHA3-224, SHA3-256, SHA3-384, SHA3-512)
// Based on the Keccak sponge construction
// Original digestpp implementation by kerukuro (public domain)

#include <cstddef>
#include <cstdint>
#include <cstring>

#include "keylock/crypto/constant_time/wipe.hpp"

namespace keylock::hash::sha3 {

    inline constexpr size_t BYTES_224 = 28;
    inline constexpr size_t BYTES_256 = 32;
    inline constexpr size_t BYTES_384 = 48;
    inline constexpr size_t BYTES_512 = 64;

    namespace detail {

        inline constexpr uint64_t RC[24] = {
            0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808AULL, 0x8000000080008000ULL,
            0x000000000000808BULL, 0x0000000080000001ULL, 0x8000000080008081ULL, 0x8000000000008009ULL,
            0x000000000000008AULL, 0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000AULL,
            0x000000008000808BULL, 0x800000000000008BULL, 0x8000000000008089ULL, 0x8000000000008003ULL,
            0x8000000000008002ULL, 0x8000000000000080ULL, 0x000000000000800AULL, 0x800000008000000AULL,
            0x8000000080008081ULL, 0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL};

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

        // Keccak-f[1600] permutation
        inline void keccak_f(uint64_t A[25]) {
            for (int round = 0; round < 24; round++) {
                uint64_t C[5], D[5];

                // Theta step
                C[0] = A[0] ^ A[5] ^ A[10] ^ A[15] ^ A[20];
                C[1] = A[1] ^ A[6] ^ A[11] ^ A[16] ^ A[21];
                C[2] = A[2] ^ A[7] ^ A[12] ^ A[17] ^ A[22];
                C[3] = A[3] ^ A[8] ^ A[13] ^ A[18] ^ A[23];
                C[4] = A[4] ^ A[9] ^ A[14] ^ A[19] ^ A[24];

                D[0] = C[4] ^ rotate_left(C[1], 1);
                D[1] = C[0] ^ rotate_left(C[2], 1);
                D[2] = C[1] ^ rotate_left(C[3], 1);
                D[3] = C[2] ^ rotate_left(C[4], 1);
                D[4] = C[3] ^ rotate_left(C[0], 1);

                // Rho and Pi steps combined
                uint64_t B00 = A[0] ^ D[0];
                uint64_t B10 = rotate_left(A[1] ^ D[1], 1);
                uint64_t B20 = rotate_left(A[2] ^ D[2], 62);
                uint64_t B5 = rotate_left(A[3] ^ D[3], 28);
                uint64_t B15 = rotate_left(A[4] ^ D[4], 27);

                uint64_t B16 = rotate_left(A[5] ^ D[0], 36);
                uint64_t B1 = rotate_left(A[6] ^ D[1], 44);
                uint64_t B11 = rotate_left(A[7] ^ D[2], 6);
                uint64_t B21 = rotate_left(A[8] ^ D[3], 55);
                uint64_t B6 = rotate_left(A[9] ^ D[4], 20);

                uint64_t B7 = rotate_left(A[10] ^ D[0], 3);
                uint64_t B17 = rotate_left(A[11] ^ D[1], 10);
                uint64_t B2 = rotate_left(A[12] ^ D[2], 43);
                uint64_t B12 = rotate_left(A[13] ^ D[3], 25);
                uint64_t B22 = rotate_left(A[14] ^ D[4], 39);

                uint64_t B23 = rotate_left(A[15] ^ D[0], 41);
                uint64_t B8 = rotate_left(A[16] ^ D[1], 45);
                uint64_t B18 = rotate_left(A[17] ^ D[2], 15);
                uint64_t B3 = rotate_left(A[18] ^ D[3], 21);
                uint64_t B13 = rotate_left(A[19] ^ D[4], 8);

                uint64_t B14 = rotate_left(A[20] ^ D[0], 18);
                uint64_t B24 = rotate_left(A[21] ^ D[1], 2);
                uint64_t B9 = rotate_left(A[22] ^ D[2], 61);
                uint64_t B19 = rotate_left(A[23] ^ D[3], 56);
                uint64_t B4 = rotate_left(A[24] ^ D[4], 14);

                // Chi step
                A[0] = B00 ^ ((~B1) & B2);
                A[1] = B1 ^ ((~B2) & B3);
                A[2] = B2 ^ ((~B3) & B4);
                A[3] = B3 ^ ((~B4) & B00);
                A[4] = B4 ^ ((~B00) & B1);

                A[5] = B5 ^ ((~B6) & B7);
                A[6] = B6 ^ ((~B7) & B8);
                A[7] = B7 ^ ((~B8) & B9);
                A[8] = B8 ^ ((~B9) & B5);
                A[9] = B9 ^ ((~B5) & B6);

                A[10] = B10 ^ ((~B11) & B12);
                A[11] = B11 ^ ((~B12) & B13);
                A[12] = B12 ^ ((~B13) & B14);
                A[13] = B13 ^ ((~B14) & B10);
                A[14] = B14 ^ ((~B10) & B11);

                A[15] = B15 ^ ((~B16) & B17);
                A[16] = B16 ^ ((~B17) & B18);
                A[17] = B17 ^ ((~B18) & B19);
                A[18] = B18 ^ ((~B19) & B15);
                A[19] = B19 ^ ((~B15) & B16);

                A[20] = B20 ^ ((~B21) & B22);
                A[21] = B21 ^ ((~B22) & B23);
                A[22] = B22 ^ ((~B23) & B24);
                A[23] = B23 ^ ((~B24) & B20);
                A[24] = B24 ^ ((~B20) & B21);

                // Iota step
                A[0] ^= RC[round];
            }
        }

        inline void absorb(uint64_t A[25], const uint8_t *data, size_t rate_bytes) {
            size_t rate_words = rate_bytes / 8;
            for (size_t i = 0; i < rate_words; ++i) {
                A[i] ^= load64_le(data + i * 8);
            }
            keccak_f(A);
        }

    } // namespace detail

    struct Context {
        uint64_t A[25];
        uint8_t buffer[144]; // Max rate is 1152 bits = 144 bytes for SHA3-224
        size_t buffer_len;
        size_t rate;      // Rate in bytes (144 for 224, 136 for 256, 104 for 384, 72 for 512)
        size_t hash_size; // Output size in bytes
    };

    inline void init(Context *ctx, size_t hash_bits) {
        std::memset(ctx->A, 0, sizeof(ctx->A));
        ctx->buffer_len = 0;

        switch (hash_bits) {
        case 224:
            ctx->rate = 144;
            ctx->hash_size = BYTES_224;
            break;
        case 256:
            ctx->rate = 136;
            ctx->hash_size = BYTES_256;
            break;
        case 384:
            ctx->rate = 104;
            ctx->hash_size = BYTES_384;
            break;
        case 512:
        default:
            ctx->rate = 72;
            ctx->hash_size = BYTES_512;
            break;
        }
    }

    inline void init_224(Context *ctx) { init(ctx, 224); }
    inline void init_256(Context *ctx) { init(ctx, 256); }
    inline void init_384(Context *ctx) { init(ctx, 384); }
    inline void init_512(Context *ctx) { init(ctx, 512); }

    inline void update(Context *ctx, const uint8_t *message, size_t message_size) {
        size_t rate = ctx->rate;

        // Fill buffer if partially filled
        if (ctx->buffer_len > 0) {
            size_t fill = rate - ctx->buffer_len;
            if (fill > message_size) {
                fill = message_size;
            }
            std::memcpy(ctx->buffer + ctx->buffer_len, message, fill);
            ctx->buffer_len += fill;
            message += fill;
            message_size -= fill;

            if (ctx->buffer_len == rate) {
                detail::absorb(ctx->A, ctx->buffer, rate);
                ctx->buffer_len = 0;
            }
        }

        // Process full blocks
        while (message_size >= rate) {
            detail::absorb(ctx->A, message, rate);
            message += rate;
            message_size -= rate;
        }

        // Buffer remaining bytes
        if (message_size > 0) {
            std::memcpy(ctx->buffer, message, message_size);
            ctx->buffer_len = message_size;
        }
    }

    inline void final(Context *ctx, uint8_t *hash) {
        size_t rate = ctx->rate;

        // Pad: append 0x06, zeros, then 0x80 at end of rate block
        ctx->buffer[ctx->buffer_len++] = 0x06;
        std::memset(ctx->buffer + ctx->buffer_len, 0, rate - ctx->buffer_len);
        ctx->buffer[rate - 1] |= 0x80;

        detail::absorb(ctx->A, ctx->buffer, rate);

        // Squeeze: extract hash bytes
        for (size_t i = 0; i < ctx->hash_size / 8; ++i) {
            detail::store64_le(hash + i * 8, ctx->A[i]);
        }
        // Handle partial last word
        size_t remaining = ctx->hash_size % 8;
        if (remaining > 0) {
            uint8_t temp[8];
            detail::store64_le(temp, ctx->A[ctx->hash_size / 8]);
            std::memcpy(hash + (ctx->hash_size / 8) * 8, temp, remaining);
        }

        crypto::constant_time::wipe(ctx, sizeof(*ctx));
    }

    // One-shot hash functions
    inline void hash_224(uint8_t hash[28], const uint8_t *message, size_t message_size) {
        Context ctx;
        init_224(&ctx);
        update(&ctx, message, message_size);
        final(&ctx, hash);
    }

    inline void hash_256(uint8_t hash[32], const uint8_t *message, size_t message_size) {
        Context ctx;
        init_256(&ctx);
        update(&ctx, message, message_size);
        final(&ctx, hash);
    }

    inline void hash_384(uint8_t hash[48], const uint8_t *message, size_t message_size) {
        Context ctx;
        init_384(&ctx);
        update(&ctx, message, message_size);
        final(&ctx, hash);
    }

    inline void hash_512(uint8_t hash[64], const uint8_t *message, size_t message_size) {
        Context ctx;
        init_512(&ctx);
        update(&ctx, message, message_size);
        final(&ctx, hash);
    }

    // Generic one-shot
    inline void hash(uint8_t *hash, size_t hash_bits, const uint8_t *message, size_t message_size) {
        Context ctx;
        init(&ctx, hash_bits);
        update(&ctx, message, message_size);
        final(&ctx, hash);
    }

} // namespace keylock::hash::sha3
