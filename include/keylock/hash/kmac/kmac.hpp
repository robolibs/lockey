#pragma once

// KMAC128/256 (KECCAK Message Authentication Code)
// Based on NIST SP 800-185
// Original digestpp implementation by kerukuro (public domain)

#include <cstddef>
#include <cstdint>
#include <cstring>

#include "keylock/crypto/constant_time/wipe.hpp"

namespace keylock::hash::kmac {

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

        // Left encode for bytepad
        inline size_t left_encode(size_t num, uint8_t *buf) {
            uint8_t n = 1;
            size_t tmp = num;
            while (tmp >>= 8)
                ++n;
            buf[0] = n;
            for (size_t i = 0; i < n; ++i) {
                buf[n - i] = static_cast<uint8_t>(num >> (8 * i));
            }
            return n + 1;
        }

        // Right encode for output length
        inline size_t right_encode(size_t num, uint8_t *buf) {
            uint8_t n = 1;
            size_t tmp = num;
            while (tmp >>= 8)
                ++n;
            for (size_t i = 0; i < n; ++i) {
                buf[n - 1 - i] = static_cast<uint8_t>(num >> (8 * i));
            }
            buf[n] = n;
            return n + 1;
        }

    } // namespace detail

    struct Context {
        uint64_t A[25];
        uint8_t buffer[168]; // Max rate is 1344 bits = 168 bytes for KMAC128
        size_t buffer_len;
        size_t rate;        // Rate in bytes (168 for 128, 136 for 256)
        size_t squeeze_pos; // Position in squeeze phase
        size_t output_size; // Expected output size (0 for XOF mode)
        bool squeezing;     // Whether in squeeze phase
        bool is_xof;        // Whether in XOF mode
    };

    namespace detail {

        // Internal update for context
        inline void ctx_update(Context *ctx, const uint8_t *message, size_t message_size) {
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
                    absorb(ctx->A, ctx->buffer, rate);
                    ctx->buffer_len = 0;
                }
            }

            // Process full blocks
            while (message_size >= rate) {
                absorb(ctx->A, message, rate);
                message += rate;
                message_size -= rate;
            }

            // Buffer remaining bytes
            if (message_size > 0) {
                std::memcpy(ctx->buffer, message, message_size);
                ctx->buffer_len = message_size;
            }
        }

    } // namespace detail

    // Initialize KMAC128
    inline void init_128(Context *ctx, const uint8_t *key, size_t key_size, const uint8_t *S, size_t S_len,
                         size_t output_size) {
        std::memset(ctx->A, 0, sizeof(ctx->A));
        ctx->buffer_len = 0;
        ctx->rate = 168; // 1344 bits
        ctx->squeeze_pos = 0;
        ctx->output_size = output_size;
        ctx->squeezing = false;
        ctx->is_xof = (output_size == 0);

        uint8_t buf[32];
        size_t rate = ctx->rate;

        // cSHAKE domain separation: bytepad(encode_string("KMAC") || encode_string(S), rate)
        // First, absorb left_encode(rate)
        size_t len = detail::left_encode(rate, buf);
        detail::ctx_update(ctx, buf, len);
        size_t total = len;

        // Absorb encode_string("KMAC") = left_encode(4*8) || "KMAC"
        const uint8_t kmac_name[] = "KMAC";
        len = detail::left_encode(4 * 8, buf);
        detail::ctx_update(ctx, buf, len);
        detail::ctx_update(ctx, kmac_name, 4);
        total += len + 4;

        // Absorb encode_string(S)
        len = detail::left_encode(S_len * 8, buf);
        detail::ctx_update(ctx, buf, len);
        if (S_len > 0) {
            detail::ctx_update(ctx, S, S_len);
        }
        total += len + S_len;

        // Pad to rate boundary
        size_t pad_len = rate - (total % rate);
        if (pad_len != rate) {
            std::memset(buf, 0, sizeof(buf));
            while (pad_len > 0) {
                size_t chunk = pad_len > sizeof(buf) ? sizeof(buf) : pad_len;
                detail::ctx_update(ctx, buf, chunk);
                pad_len -= chunk;
            }
        }

        // bytepad(encode_string(K), rate)
        len = detail::left_encode(rate, buf);
        detail::ctx_update(ctx, buf, len);
        total = len;

        len = detail::left_encode(key_size * 8, buf);
        detail::ctx_update(ctx, buf, len);
        if (key_size > 0) {
            detail::ctx_update(ctx, key, key_size);
        }
        total += len + key_size;

        // Pad to rate boundary
        pad_len = rate - (total % rate);
        if (pad_len != rate) {
            std::memset(buf, 0, sizeof(buf));
            while (pad_len > 0) {
                size_t chunk = pad_len > sizeof(buf) ? sizeof(buf) : pad_len;
                detail::ctx_update(ctx, buf, chunk);
                pad_len -= chunk;
            }
        }
    }

    // Initialize KMAC256
    inline void init_256(Context *ctx, const uint8_t *key, size_t key_size, const uint8_t *S, size_t S_len,
                         size_t output_size) {
        std::memset(ctx->A, 0, sizeof(ctx->A));
        ctx->buffer_len = 0;
        ctx->rate = 136; // 1088 bits
        ctx->squeeze_pos = 0;
        ctx->output_size = output_size;
        ctx->squeezing = false;
        ctx->is_xof = (output_size == 0);

        uint8_t buf[32];
        size_t rate = ctx->rate;

        // cSHAKE domain separation: bytepad(encode_string("KMAC") || encode_string(S), rate)
        // First, absorb left_encode(rate)
        size_t len = detail::left_encode(rate, buf);
        detail::ctx_update(ctx, buf, len);
        size_t total = len;

        // Absorb encode_string("KMAC") = left_encode(4*8) || "KMAC"
        const uint8_t kmac_name[] = "KMAC";
        len = detail::left_encode(4 * 8, buf);
        detail::ctx_update(ctx, buf, len);
        detail::ctx_update(ctx, kmac_name, 4);
        total += len + 4;

        // Absorb encode_string(S)
        len = detail::left_encode(S_len * 8, buf);
        detail::ctx_update(ctx, buf, len);
        if (S_len > 0) {
            detail::ctx_update(ctx, S, S_len);
        }
        total += len + S_len;

        // Pad to rate boundary
        size_t pad_len = rate - (total % rate);
        if (pad_len != rate) {
            std::memset(buf, 0, sizeof(buf));
            while (pad_len > 0) {
                size_t chunk = pad_len > sizeof(buf) ? sizeof(buf) : pad_len;
                detail::ctx_update(ctx, buf, chunk);
                pad_len -= chunk;
            }
        }

        // bytepad(encode_string(K), rate)
        len = detail::left_encode(rate, buf);
        detail::ctx_update(ctx, buf, len);
        total = len;

        len = detail::left_encode(key_size * 8, buf);
        detail::ctx_update(ctx, buf, len);
        if (key_size > 0) {
            detail::ctx_update(ctx, key, key_size);
        }
        total += len + key_size;

        // Pad to rate boundary
        pad_len = rate - (total % rate);
        if (pad_len != rate) {
            std::memset(buf, 0, sizeof(buf));
            while (pad_len > 0) {
                size_t chunk = pad_len > sizeof(buf) ? sizeof(buf) : pad_len;
                detail::ctx_update(ctx, buf, chunk);
                pad_len -= chunk;
            }
        }
    }

    inline void update(Context *ctx, const uint8_t *message, size_t message_size) {
        detail::ctx_update(ctx, message, message_size);
    }

    // Squeeze output bytes
    inline void squeeze(Context *ctx, uint8_t *output, size_t output_size) {
        size_t rate = ctx->rate;

        if (!ctx->squeezing) {
            // Append right_encode(L) where L is output length in bits
            // For KMAC XOF, L=0; for KMAC, L=output_size*8
            uint8_t buf[16];
            size_t len = detail::right_encode(ctx->is_xof ? 0 : ctx->output_size * 8, buf);
            detail::ctx_update(ctx, buf, len);

            // Finalize absorb phase with cSHAKE suffix (0x04)
            ctx->buffer[ctx->buffer_len++] = 0x04;
            std::memset(ctx->buffer + ctx->buffer_len, 0, rate - ctx->buffer_len);
            ctx->buffer[rate - 1] |= 0x80;
            detail::absorb(ctx->A, ctx->buffer, rate);
            ctx->squeezing = true;
            ctx->squeeze_pos = 0;
        }

        // Extract output bytes
        size_t produced = 0;
        while (produced < output_size) {
            if (ctx->squeeze_pos == rate) {
                detail::keccak_f(ctx->A);
                ctx->squeeze_pos = 0;
            }

            size_t available = rate - ctx->squeeze_pos;
            size_t to_copy = output_size - produced;
            if (to_copy > available) {
                to_copy = available;
            }

            // Copy from state
            uint8_t *state_bytes = reinterpret_cast<uint8_t *>(ctx->A);
            std::memcpy(output + produced, state_bytes + ctx->squeeze_pos, to_copy);
            ctx->squeeze_pos += to_copy;
            produced += to_copy;
        }
    }

    // Finalize and produce MAC
    inline void final(Context *ctx, uint8_t *mac) {
        squeeze(ctx, mac, ctx->output_size);
        crypto::constant_time::wipe(ctx, sizeof(*ctx));
    }

    // Finalize XOF mode - call after done squeezing
    inline void final_xof(Context *ctx) { crypto::constant_time::wipe(ctx, sizeof(*ctx)); }

    // One-shot KMAC128
    inline void kmac128(uint8_t *mac, size_t mac_size, const uint8_t *key, size_t key_size, const uint8_t *S,
                        size_t S_len, const uint8_t *message, size_t message_size) {
        Context ctx;
        init_128(&ctx, key, key_size, S, S_len, mac_size);
        update(&ctx, message, message_size);
        squeeze(&ctx, mac, mac_size);
        crypto::constant_time::wipe(&ctx, sizeof(ctx));
    }

    // One-shot KMAC256
    inline void kmac256(uint8_t *mac, size_t mac_size, const uint8_t *key, size_t key_size, const uint8_t *S,
                        size_t S_len, const uint8_t *message, size_t message_size) {
        Context ctx;
        init_256(&ctx, key, key_size, S, S_len, mac_size);
        update(&ctx, message, message_size);
        squeeze(&ctx, mac, mac_size);
        crypto::constant_time::wipe(&ctx, sizeof(ctx));
    }

    // Convenience: KMAC128 with no customization string
    inline void kmac128(uint8_t *mac, size_t mac_size, const uint8_t *key, size_t key_size, const uint8_t *message,
                        size_t message_size) {
        kmac128(mac, mac_size, key, key_size, nullptr, 0, message, message_size);
    }

    // Convenience: KMAC256 with no customization string
    inline void kmac256(uint8_t *mac, size_t mac_size, const uint8_t *key, size_t key_size, const uint8_t *message,
                        size_t message_size) {
        kmac256(mac, mac_size, key, key_size, nullptr, 0, message, message_size);
    }

} // namespace keylock::hash::kmac
