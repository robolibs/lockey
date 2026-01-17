#pragma once

// SM3 Cryptographic Hash Algorithm
// Chinese National Standard (GB/T 32905-2016)
// Original digestpp implementation by kerukuro (public domain)

#include <cstddef>
#include <cstdint>
#include <cstring>

#include "keylock/crypto/constant_time/wipe.hpp"

namespace keylock::hash::sm3 {

    inline constexpr size_t BYTES = 32;
    inline constexpr size_t BLOCK_SIZE = 64;

    namespace detail {

        inline uint32_t rotate_left(uint32_t x, int n) { return (x << n) | (x >> (32 - n)); }

        inline uint32_t load32_be(const uint8_t s[4]) {
            return (static_cast<uint32_t>(s[0]) << 24) | (static_cast<uint32_t>(s[1]) << 16) |
                   (static_cast<uint32_t>(s[2]) << 8) | static_cast<uint32_t>(s[3]);
        }

        inline void store32_be(uint8_t out[4], uint32_t in) {
            out[0] = static_cast<uint8_t>((in >> 24) & 0xff);
            out[1] = static_cast<uint8_t>((in >> 16) & 0xff);
            out[2] = static_cast<uint8_t>((in >> 8) & 0xff);
            out[3] = static_cast<uint8_t>(in & 0xff);
        }

        inline void store64_be(uint8_t out[8], uint64_t in) {
            out[0] = static_cast<uint8_t>((in >> 56) & 0xff);
            out[1] = static_cast<uint8_t>((in >> 48) & 0xff);
            out[2] = static_cast<uint8_t>((in >> 40) & 0xff);
            out[3] = static_cast<uint8_t>((in >> 32) & 0xff);
            out[4] = static_cast<uint8_t>((in >> 24) & 0xff);
            out[5] = static_cast<uint8_t>((in >> 16) & 0xff);
            out[6] = static_cast<uint8_t>((in >> 8) & 0xff);
            out[7] = static_cast<uint8_t>(in & 0xff);
        }

        // Boolean functions
        inline uint32_t ff0(uint32_t x, uint32_t y, uint32_t z) { return x ^ y ^ z; }

        inline uint32_t ff1(uint32_t x, uint32_t y, uint32_t z) { return (x & y) ^ (x & z) ^ (y & z); }

        inline uint32_t gg0(uint32_t x, uint32_t y, uint32_t z) { return x ^ y ^ z; }

        inline uint32_t gg1(uint32_t x, uint32_t y, uint32_t z) { return (x & y) ^ (~x & z); }

        // Permutation functions
        inline uint32_t p0(uint32_t x) { return x ^ rotate_left(x, 9) ^ rotate_left(x, 17); }

        inline uint32_t p1(uint32_t x) { return x ^ rotate_left(x, 15) ^ rotate_left(x, 23); }

    } // namespace detail

    struct Context {
        uint32_t H[8];
        uint8_t buffer[64];
        size_t buffer_len;
        uint64_t total_bits;
    };

    namespace detail {

        inline void transform(Context *ctx, const uint8_t *block) {
            uint32_t W[68], W2[64];

            // Message expansion
            for (int i = 0; i < 16; i++) {
                W[i] = load32_be(block + i * 4);
            }
            for (int i = 16; i < 68; i++) {
                W[i] = p1(W[i - 16] ^ W[i - 9] ^ rotate_left(W[i - 3], 15)) ^ rotate_left(W[i - 13], 7) ^ W[i - 6];
            }
            for (int i = 0; i < 64; i++) {
                W2[i] = W[i] ^ W[i + 4];
            }

            uint32_t a = ctx->H[0], b = ctx->H[1], c = ctx->H[2], d = ctx->H[3];
            uint32_t e = ctx->H[4], f = ctx->H[5], g = ctx->H[6], h = ctx->H[7];

            // Rounds 0-15
            for (int t = 0; t <= 15; t++) {
                uint32_t ss1 = rotate_left(rotate_left(a, 12) + e + rotate_left(0x79cc4519U, t), 7);
                uint32_t ss2 = ss1 ^ rotate_left(a, 12);
                uint32_t tt1 = ff0(a, b, c) + d + ss2 + W2[t];
                uint32_t tt2 = gg0(e, f, g) + h + ss1 + W[t];
                d = c;
                c = rotate_left(b, 9);
                b = a;
                a = tt1;
                h = g;
                g = rotate_left(f, 19);
                f = e;
                e = p0(tt2);
            }

            // Rounds 16-63
            for (int t = 16; t <= 63; t++) {
                uint32_t ss1 = rotate_left(rotate_left(a, 12) + e + rotate_left(0x7a879d8aU, t), 7);
                uint32_t ss2 = ss1 ^ rotate_left(a, 12);
                uint32_t tt1 = ff1(a, b, c) + d + ss2 + W2[t];
                uint32_t tt2 = gg1(e, f, g) + h + ss1 + W[t];
                d = c;
                c = rotate_left(b, 9);
                b = a;
                a = tt1;
                h = g;
                g = rotate_left(f, 19);
                f = e;
                e = p0(tt2);
            }

            ctx->H[0] ^= a;
            ctx->H[1] ^= b;
            ctx->H[2] ^= c;
            ctx->H[3] ^= d;
            ctx->H[4] ^= e;
            ctx->H[5] ^= f;
            ctx->H[6] ^= g;
            ctx->H[7] ^= h;
        }

    } // namespace detail

    inline void init(Context *ctx) {
        ctx->H[0] = 0x7380166f;
        ctx->H[1] = 0x4914b2b9;
        ctx->H[2] = 0x172442d7;
        ctx->H[3] = 0xda8a0600;
        ctx->H[4] = 0xa96f30bc;
        ctx->H[5] = 0x163138aa;
        ctx->H[6] = 0xe38dee4d;
        ctx->H[7] = 0xb0fb0e4e;
        ctx->buffer_len = 0;
        ctx->total_bits = 0;
    }

    inline void update(Context *ctx, const uint8_t *message, size_t message_size) {
        ctx->total_bits += message_size * 8;

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

            if (ctx->buffer_len == 64) {
                detail::transform(ctx, ctx->buffer);
                ctx->buffer_len = 0;
            }
        }

        // Process full blocks
        while (message_size >= 64) {
            detail::transform(ctx, message);
            message += 64;
            message_size -= 64;
        }

        // Buffer remaining bytes
        if (message_size > 0) {
            std::memcpy(ctx->buffer, message, message_size);
            ctx->buffer_len = message_size;
        }
    }

    inline void final(Context *ctx, uint8_t hash[32]) {
        // Padding
        ctx->buffer[ctx->buffer_len++] = 0x80;

        if (ctx->buffer_len > 56) {
            std::memset(ctx->buffer + ctx->buffer_len, 0, 64 - ctx->buffer_len);
            detail::transform(ctx, ctx->buffer);
            ctx->buffer_len = 0;
        }

        std::memset(ctx->buffer + ctx->buffer_len, 0, 56 - ctx->buffer_len);
        detail::store64_be(ctx->buffer + 56, ctx->total_bits);
        detail::transform(ctx, ctx->buffer);

        // Output
        for (int i = 0; i < 8; i++) {
            detail::store32_be(hash + i * 4, ctx->H[i]);
        }

        crypto::constant_time::wipe(ctx, sizeof(*ctx));
    }

    // One-shot hash
    inline void hash(uint8_t hash[32], const uint8_t *message, size_t message_size) {
        Context ctx;
        init(&ctx);
        update(&ctx, message, message_size);
        final(&ctx, hash);
    }

} // namespace keylock::hash::sm3
