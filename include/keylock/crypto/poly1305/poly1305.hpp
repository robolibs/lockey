#pragma once

// Poly1305 one-time authenticator
// Adapted from Monocypher (public domain)

#include <cstddef>
#include <cstdint>
#include <cstring>

#include "keylock/crypto/constant_time/wipe.hpp"

namespace keylock::crypto::poly1305 {

    namespace detail {

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

        inline void load32_le_buf(uint32_t *dst, const uint8_t *src, size_t size) {
            for (size_t i = 0; i < size; ++i) {
                dst[i] = load32_le(src + i * 4);
            }
        }

        inline size_t gap(size_t x, size_t pow_2) { return (~x + 1) & (pow_2 - 1); }

        inline size_t min(size_t a, size_t b) { return a <= b ? a : b; }

    } // namespace detail

    struct Context {
        uint8_t c[16];
        size_t c_idx;
        uint32_t r[4];
        uint32_t pad[4];
        uint32_t h[5];
    };

    namespace detail {

        inline void poly_blocks(Context *ctx, const uint8_t *in, size_t nb_blocks, unsigned end) {
            const uint32_t r0 = ctx->r[0];
            const uint32_t r1 = ctx->r[1];
            const uint32_t r2 = ctx->r[2];
            const uint32_t r3 = ctx->r[3];
            const uint32_t rr0 = (r0 >> 2) * 5;
            const uint32_t rr1 = (r1 >> 2) + r1;
            const uint32_t rr2 = (r2 >> 2) + r2;
            const uint32_t rr3 = (r3 >> 2) + r3;
            const uint32_t rr4 = r0 & 3;

            uint32_t h0 = ctx->h[0];
            uint32_t h1 = ctx->h[1];
            uint32_t h2 = ctx->h[2];
            uint32_t h3 = ctx->h[3];
            uint32_t h4 = ctx->h[4];

            for (size_t i = 0; i < nb_blocks; ++i) {
                const uint64_t s0 = static_cast<uint64_t>(h0) + load32_le(in);
                in += 4;
                const uint64_t s1 = static_cast<uint64_t>(h1) + load32_le(in);
                in += 4;
                const uint64_t s2 = static_cast<uint64_t>(h2) + load32_le(in);
                in += 4;
                const uint64_t s3 = static_cast<uint64_t>(h3) + load32_le(in);
                in += 4;
                const uint32_t s4 = h4 + end;

                const uint64_t x0 = s0 * r0 + s1 * rr3 + s2 * rr2 + s3 * rr1 + s4 * rr0;
                const uint64_t x1 = s0 * r1 + s1 * r0 + s2 * rr3 + s3 * rr2 + s4 * rr1;
                const uint64_t x2 = s0 * r2 + s1 * r1 + s2 * r0 + s3 * rr3 + s4 * rr2;
                const uint64_t x3 = s0 * r3 + s1 * r2 + s2 * r1 + s3 * r0 + s4 * rr3;
                const uint32_t x4 = s4 * rr4;

                const uint32_t u5 = x4 + static_cast<uint32_t>(x3 >> 32);
                const uint64_t u0 = (u5 >> 2) * 5 + (x0 & 0xffffffff);
                const uint64_t u1 = (u0 >> 32) + (x1 & 0xffffffff) + (x0 >> 32);
                const uint64_t u2 = (u1 >> 32) + (x2 & 0xffffffff) + (x1 >> 32);
                const uint64_t u3 = (u2 >> 32) + (x3 & 0xffffffff) + (x2 >> 32);
                const uint32_t u4 = static_cast<uint32_t>(u3 >> 32) + (u5 & 3);

                h0 = static_cast<uint32_t>(u0 & 0xffffffff);
                h1 = static_cast<uint32_t>(u1 & 0xffffffff);
                h2 = static_cast<uint32_t>(u2 & 0xffffffff);
                h3 = static_cast<uint32_t>(u3 & 0xffffffff);
                h4 = u4;
            }

            ctx->h[0] = h0;
            ctx->h[1] = h1;
            ctx->h[2] = h2;
            ctx->h[3] = h3;
            ctx->h[4] = h4;
        }

    } // namespace detail

    inline void init(Context *ctx, const uint8_t key[32]) {
        std::memset(ctx->h, 0, sizeof(ctx->h));
        ctx->c_idx = 0;
        detail::load32_le_buf(ctx->r, key, 4);
        detail::load32_le_buf(ctx->pad, key + 16, 4);
        ctx->r[0] &= 0x0fffffff;
        ctx->r[1] &= 0x0ffffffc;
        ctx->r[2] &= 0x0ffffffc;
        ctx->r[3] &= 0x0ffffffc;
    }

    inline void update(Context *ctx, const uint8_t *message, size_t message_size) {
        if (message_size == 0) {
            return;
        }

        size_t aligned = detail::min(detail::gap(ctx->c_idx, 16), message_size);
        for (size_t i = 0; i < aligned; ++i) {
            ctx->c[ctx->c_idx] = *message;
            ctx->c_idx++;
            message++;
            message_size--;
        }

        if (ctx->c_idx == 16) {
            detail::poly_blocks(ctx, ctx->c, 1, 1);
            ctx->c_idx = 0;
        }

        size_t nb_blocks = message_size >> 4;
        detail::poly_blocks(ctx, message, nb_blocks, 1);
        message += nb_blocks << 4;
        message_size &= 15;

        for (size_t i = 0; i < message_size; ++i) {
            ctx->c[ctx->c_idx] = message[i];
            ctx->c_idx++;
        }
    }

    inline void final(Context *ctx, uint8_t mac[16]) {
        if (ctx->c_idx != 0) {
            std::memset(ctx->c + ctx->c_idx, 0, 16 - ctx->c_idx);
            ctx->c[ctx->c_idx] = 1;
            detail::poly_blocks(ctx, ctx->c, 1, 0);
        }

        uint64_t c = 5;
        for (int i = 0; i < 4; ++i) {
            c += ctx->h[i];
            c >>= 32;
        }
        c += ctx->h[4];
        c = (c >> 2) * 5;

        for (int i = 0; i < 4; ++i) {
            c += static_cast<uint64_t>(ctx->h[i]) + ctx->pad[i];
            detail::store32_le(mac + i * 4, static_cast<uint32_t>(c));
            c = c >> 32;
        }

        constant_time::wipe(ctx, sizeof(*ctx));
    }

    // One-shot Poly1305
    inline void poly1305(uint8_t mac[16], const uint8_t *message, size_t message_size, const uint8_t key[32]) {
        Context ctx;
        init(&ctx, key);
        update(&ctx, message, message_size);
        final(&ctx, mac);
    }

} // namespace keylock::crypto::poly1305
