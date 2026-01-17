#pragma once

// SHA-256 hash function

#include <cstddef>
#include <cstdint>
#include <cstring>

#include "keylock/crypto/constant_time/wipe.hpp"

namespace keylock::hash::sha256 {

    inline constexpr size_t BYTES = 32;

    namespace detail {

        inline constexpr uint32_t K[64] = {
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

        inline uint32_t rot(uint32_t x, int c) { return (x >> c) | (x << (32 - c)); }
        inline uint32_t ch(uint32_t x, uint32_t y, uint32_t z) { return (x & y) ^ (~x & z); }
        inline uint32_t maj(uint32_t x, uint32_t y, uint32_t z) { return (x & y) ^ (x & z) ^ (y & z); }
        inline uint32_t big_sigma0(uint32_t x) { return rot(x, 2) ^ rot(x, 13) ^ rot(x, 22); }
        inline uint32_t big_sigma1(uint32_t x) { return rot(x, 6) ^ rot(x, 11) ^ rot(x, 25); }
        inline uint32_t lit_sigma0(uint32_t x) { return rot(x, 7) ^ rot(x, 18) ^ (x >> 3); }
        inline uint32_t lit_sigma1(uint32_t x) { return rot(x, 17) ^ rot(x, 19) ^ (x >> 10); }

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

    } // namespace detail

    struct Context {
        uint32_t hash[8];
        uint8_t buffer[64];
        uint64_t total_len;
        size_t buffer_len;
    };

    namespace detail {

        inline void compress(Context *ctx, const uint8_t block[64]) {
            uint32_t w[64];
            for (int i = 0; i < 16; ++i) {
                w[i] = load32_be(block + i * 4);
            }
            for (int i = 16; i < 64; ++i) {
                w[i] = lit_sigma1(w[i - 2]) + w[i - 7] + lit_sigma0(w[i - 15]) + w[i - 16];
            }

            uint32_t a = ctx->hash[0], b = ctx->hash[1];
            uint32_t c = ctx->hash[2], d = ctx->hash[3];
            uint32_t e = ctx->hash[4], f = ctx->hash[5];
            uint32_t g = ctx->hash[6], h = ctx->hash[7];

            for (int i = 0; i < 64; ++i) {
                uint32_t t1 = h + big_sigma1(e) + ch(e, f, g) + K[i] + w[i];
                uint32_t t2 = big_sigma0(a) + maj(a, b, c);
                h = g;
                g = f;
                f = e;
                e = d + t1;
                d = c;
                c = b;
                b = a;
                a = t1 + t2;
            }

            ctx->hash[0] += a;
            ctx->hash[1] += b;
            ctx->hash[2] += c;
            ctx->hash[3] += d;
            ctx->hash[4] += e;
            ctx->hash[5] += f;
            ctx->hash[6] += g;
            ctx->hash[7] += h;
        }

    } // namespace detail

    inline void init(Context *ctx) {
        ctx->hash[0] = 0x6a09e667;
        ctx->hash[1] = 0xbb67ae85;
        ctx->hash[2] = 0x3c6ef372;
        ctx->hash[3] = 0xa54ff53a;
        ctx->hash[4] = 0x510e527f;
        ctx->hash[5] = 0x9b05688c;
        ctx->hash[6] = 0x1f83d9ab;
        ctx->hash[7] = 0x5be0cd19;
        ctx->total_len = 0;
        ctx->buffer_len = 0;
    }

    inline void update(Context *ctx, const uint8_t *message, size_t message_size) {
        ctx->total_len += message_size;

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
                detail::compress(ctx, ctx->buffer);
                ctx->buffer_len = 0;
            }
        }

        // Process full blocks
        while (message_size >= 64) {
            detail::compress(ctx, message);
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
        // Pad message
        ctx->buffer[ctx->buffer_len++] = 0x80;

        if (ctx->buffer_len > 56) {
            std::memset(ctx->buffer + ctx->buffer_len, 0, 64 - ctx->buffer_len);
            detail::compress(ctx, ctx->buffer);
            ctx->buffer_len = 0;
        }

        std::memset(ctx->buffer + ctx->buffer_len, 0, 56 - ctx->buffer_len);
        detail::store64_be(ctx->buffer + 56, ctx->total_len * 8);
        detail::compress(ctx, ctx->buffer);

        for (int i = 0; i < 8; ++i) {
            detail::store32_be(hash + i * 4, ctx->hash[i]);
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

} // namespace keylock::hash::sha256
