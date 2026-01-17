#pragma once

// SHA-512 hash function
// Adapted from Monocypher (public domain)

#include <cstddef>
#include <cstdint>
#include <cstring>

#include "keylock/crypto/constant_time/wipe.hpp"

namespace keylock::hash::sha512 {

    inline constexpr size_t BYTES = 64;

    namespace detail {

        inline constexpr uint64_t K[80] = {
            0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
            0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL, 0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
            0xd807aa98a3030242ULL, 0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
            0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
            0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL, 0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
            0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
            0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
            0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL, 0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
            0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
            0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
            0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL, 0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
            0xd192e819d6ef5218ULL, 0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
            0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
            0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL, 0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
            0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
            0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
            0xca273eceea26619cULL, 0xd186b8c721c0c207ULL, 0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
            0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
            0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
            0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL, 0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL};

        inline uint64_t rot(uint64_t x, int c) { return (x >> c) | (x << (64 - c)); }
        inline uint64_t ch(uint64_t x, uint64_t y, uint64_t z) { return (x & y) ^ (~x & z); }
        inline uint64_t maj(uint64_t x, uint64_t y, uint64_t z) { return (x & y) ^ (x & z) ^ (y & z); }
        inline uint64_t big_sigma0(uint64_t x) { return rot(x, 28) ^ rot(x, 34) ^ rot(x, 39); }
        inline uint64_t big_sigma1(uint64_t x) { return rot(x, 14) ^ rot(x, 18) ^ rot(x, 41); }
        inline uint64_t lit_sigma0(uint64_t x) { return rot(x, 1) ^ rot(x, 8) ^ (x >> 7); }
        inline uint64_t lit_sigma1(uint64_t x) { return rot(x, 19) ^ rot(x, 61) ^ (x >> 6); }

        inline uint64_t load64_be(const uint8_t s[8]) {
            return (static_cast<uint64_t>(s[0]) << 56) | (static_cast<uint64_t>(s[1]) << 48) |
                   (static_cast<uint64_t>(s[2]) << 40) | (static_cast<uint64_t>(s[3]) << 32) |
                   (static_cast<uint64_t>(s[4]) << 24) | (static_cast<uint64_t>(s[5]) << 16) |
                   (static_cast<uint64_t>(s[6]) << 8) | static_cast<uint64_t>(s[7]);
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

        inline void load64_be_buf(uint64_t *dst, const uint8_t *src, size_t size) {
            for (size_t i = 0; i < size; ++i) {
                dst[i] = load64_be(src + i * 8);
            }
        }

        inline size_t align(size_t x, size_t pow_2) { return (~x + 1) & (pow_2 - 1); }

        inline size_t min_val(size_t a, size_t b) { return a <= b ? a : b; }

    } // namespace detail

    struct Context {
        uint64_t hash[8];
        uint64_t input[16];
        uint64_t input_size[2];
        size_t input_idx;
    };

    namespace detail {

        inline void compress(Context *ctx) {
            uint64_t a = ctx->hash[0], b = ctx->hash[1];
            uint64_t c = ctx->hash[2], d = ctx->hash[3];
            uint64_t e = ctx->hash[4], f = ctx->hash[5];
            uint64_t g = ctx->hash[6], h = ctx->hash[7];

            for (size_t j = 0; j < 16; ++j) {
                uint64_t in = K[j] + ctx->input[j];
                uint64_t t1 = big_sigma1(e) + ch(e, f, g) + h + in;
                uint64_t t2 = big_sigma0(a) + maj(a, b, c);
                h = g;
                g = f;
                f = e;
                e = d + t1;
                d = c;
                c = b;
                b = a;
                a = t1 + t2;
            }

            size_t i16 = 0;
            for (size_t i = 1; i < 5; ++i) {
                i16 += 16;
                for (size_t j = 0; j < 16; ++j) {
                    ctx->input[j] += lit_sigma1(ctx->input[(j - 2) & 15]);
                    ctx->input[j] += lit_sigma0(ctx->input[(j - 15) & 15]);
                    ctx->input[j] += ctx->input[(j - 7) & 15];
                    uint64_t in = K[i16 + j] + ctx->input[j];
                    uint64_t t1 = big_sigma1(e) + ch(e, f, g) + h + in;
                    uint64_t t2 = big_sigma0(a) + maj(a, b, c);
                    h = g;
                    g = f;
                    f = e;
                    e = d + t1;
                    d = c;
                    c = b;
                    b = a;
                    a = t1 + t2;
                }
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

        inline void set_input(Context *ctx, uint8_t input) {
            size_t word = ctx->input_idx >> 3;
            size_t byte = ctx->input_idx & 7;
            ctx->input[word] |= static_cast<uint64_t>(input) << (8 * (7 - byte));
        }

        inline void incr(uint64_t x[2], uint64_t y) {
            x[1] += y;
            if (x[1] < y) {
                x[0]++;
            }
        }

    } // namespace detail

    inline void init(Context *ctx) {
        ctx->hash[0] = 0x6a09e667f3bcc908ULL;
        ctx->hash[1] = 0xbb67ae8584caa73bULL;
        ctx->hash[2] = 0x3c6ef372fe94f82bULL;
        ctx->hash[3] = 0xa54ff53a5f1d36f1ULL;
        ctx->hash[4] = 0x510e527fade682d1ULL;
        ctx->hash[5] = 0x9b05688c2b3e6c1fULL;
        ctx->hash[6] = 0x1f83d9abfb41bd6bULL;
        ctx->hash[7] = 0x5be0cd19137e2179ULL;
        ctx->input_size[0] = 0;
        ctx->input_size[1] = 0;
        ctx->input_idx = 0;
        std::memset(ctx->input, 0, sizeof(ctx->input));
    }

    inline void update(Context *ctx, const uint8_t *message, size_t message_size) {
        if (message_size == 0) {
            return;
        }

        // Align with word boundaries
        if ((ctx->input_idx & 7) != 0) {
            size_t nb_bytes = detail::min_val(detail::align(ctx->input_idx, 8), message_size);
            for (size_t i = 0; i < nb_bytes; ++i) {
                detail::set_input(ctx, message[i]);
                ctx->input_idx++;
            }
            message += nb_bytes;
            message_size -= nb_bytes;
        }

        // Align with block boundaries
        if ((ctx->input_idx & 127) != 0) {
            size_t nb_words = detail::min_val(detail::align(ctx->input_idx, 128), message_size) >> 3;
            detail::load64_be_buf(ctx->input + (ctx->input_idx >> 3), message, nb_words);
            ctx->input_idx += nb_words << 3;
            message += nb_words << 3;
            message_size -= nb_words << 3;
        }

        // Compress block if needed
        if (ctx->input_idx == 128) {
            detail::incr(ctx->input_size, 1024);
            detail::compress(ctx);
            ctx->input_idx = 0;
            std::memset(ctx->input, 0, sizeof(ctx->input));
        }

        // Process message block by block
        for (size_t i = 0; i < (message_size >> 7); ++i) {
            detail::load64_be_buf(ctx->input, message, 16);
            detail::incr(ctx->input_size, 1024);
            detail::compress(ctx);
            ctx->input_idx = 0;
            std::memset(ctx->input, 0, sizeof(ctx->input));
            message += 128;
        }
        message_size &= 127;

        if (message_size != 0) {
            size_t nb_words = message_size >> 3;
            detail::load64_be_buf(ctx->input, message, nb_words);
            ctx->input_idx += nb_words << 3;
            message += nb_words << 3;
            message_size -= nb_words << 3;

            for (size_t i = 0; i < message_size; ++i) {
                detail::set_input(ctx, message[i]);
                ctx->input_idx++;
            }
        }
    }

    inline void final(Context *ctx, uint8_t hash[64]) {
        if (ctx->input_idx == 0) {
            std::memset(ctx->input, 0, sizeof(ctx->input));
        }
        detail::set_input(ctx, 128); // padding bit

        detail::incr(ctx->input_size, ctx->input_idx * 8);

        if (ctx->input_idx > 111) {
            detail::compress(ctx);
            std::memset(ctx->input, 0, 14 * sizeof(uint64_t));
        }

        ctx->input[14] = ctx->input_size[0];
        ctx->input[15] = ctx->input_size[1];
        detail::compress(ctx);

        for (int i = 0; i < 8; ++i) {
            detail::store64_be(hash + i * 8, ctx->hash[i]);
        }

        crypto::constant_time::wipe(ctx, sizeof(*ctx));
    }

    // One-shot hash
    inline void hash(uint8_t hash[64], const uint8_t *message, size_t message_size) {
        Context ctx;
        init(&ctx);
        update(&ctx, message, message_size);
        final(&ctx, hash);
    }

} // namespace keylock::hash::sha512
