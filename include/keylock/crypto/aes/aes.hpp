#pragma once

// AES block cipher with CTR and CBC modes
// Adapted from plusaes by kkAyataka (Boost Software License)
// Supports AES-128, AES-192, AES-256

#include <cstddef>
#include <cstdint>
#include <cstring>

#include "keylock/crypto/constant_time/wipe.hpp"

namespace keylock::crypto::aes {

    inline constexpr size_t BLOCK_SIZE = 16;
    inline constexpr size_t KEY_SIZE_128 = 16;
    inline constexpr size_t KEY_SIZE_192 = 24;
    inline constexpr size_t KEY_SIZE_256 = 32;

    namespace detail {

        inline constexpr uint8_t sbox[256] = {
            0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82,
            0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26,
            0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15, 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96,
            0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
            0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb,
            0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, 0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f,
            0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff,
            0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
            0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32,
            0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d,
            0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, 0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6,
            0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
            0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e,
            0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, 0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f,
            0xb0, 0x54, 0xbb, 0x16};

        inline constexpr uint8_t inv_sbox[256] = {
            0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb, 0x7c, 0xe3,
            0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb, 0x54, 0x7b, 0x94, 0x32,
            0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e, 0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9,
            0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25, 0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16,
            0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92, 0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15,
            0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84, 0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05,
            0xb8, 0xb3, 0x45, 0x06, 0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13,
            0x8a, 0x6b, 0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
            0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e, 0x47, 0xf1,
            0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b, 0xfc, 0x56, 0x3e, 0x4b,
            0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4, 0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07,
            0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f, 0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d,
            0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef, 0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb,
            0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61, 0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63,
            0x55, 0x21, 0x0c, 0x7d};

        inline constexpr uint8_t rcon[11] = {0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36};

        inline uint32_t sub_word(uint32_t w) {
            return (static_cast<uint32_t>(sbox[(w >> 0) & 0xFF]) << 0) |
                   (static_cast<uint32_t>(sbox[(w >> 8) & 0xFF]) << 8) |
                   (static_cast<uint32_t>(sbox[(w >> 16) & 0xFF]) << 16) |
                   (static_cast<uint32_t>(sbox[(w >> 24) & 0xFF]) << 24);
        }

        inline uint32_t rot_word(uint32_t v) { return ((v >> 8) & 0x00FFFFFF) | ((v & 0xFF) << 24); }

        inline int get_rounds(size_t key_size) {
            if (key_size == 16)
                return 10;
            if (key_size == 24)
                return 12;
            if (key_size == 32)
                return 14;
            return 0;
        }

        inline uint8_t mul2(uint8_t b) {
            uint8_t m2 = b << 1;
            if (b & 0x80)
                m2 ^= 0x1B;
            return m2;
        }

        inline uint8_t mul(uint8_t b, uint8_t m) {
            uint8_t r = 0;
            uint8_t t = b;
            for (int i = 0; i < 8; ++i) {
                if (m & (1 << i))
                    r ^= t;
                t = mul2(t);
            }
            return r;
        }

    } // namespace detail

    struct Context {
        uint32_t round_keys[60]; // Max for AES-256: 15 * 4 = 60
        int rounds;
    };

    inline bool init(Context *ctx, const uint8_t *key, size_t key_size) {
        if (key_size != 16 && key_size != 24 && key_size != 32) {
            return false;
        }

        ctx->rounds = detail::get_rounds(key_size);
        int nk = key_size / 4;
        int nb = 4;

        for (int i = 0; i < nk; ++i) {
            std::memcpy(&ctx->round_keys[i], key + i * 4, 4);
        }

        for (int i = nk; i < nb * (ctx->rounds + 1); ++i) {
            uint32_t t = ctx->round_keys[i - 1];
            if (i % nk == 0) {
                t = detail::sub_word(detail::rot_word(t)) ^ detail::rcon[i / nk];
            } else if (nk > 6 && i % nk == 4) {
                t = detail::sub_word(t);
            }
            ctx->round_keys[i] = t ^ ctx->round_keys[i - nk];
        }

        return true;
    }

    namespace detail {

        inline void add_round_key(uint8_t state[16], const uint32_t *rk) {
            for (int i = 0; i < 4; ++i) {
                state[i * 4 + 0] ^= (rk[i] >> 0) & 0xFF;
                state[i * 4 + 1] ^= (rk[i] >> 8) & 0xFF;
                state[i * 4 + 2] ^= (rk[i] >> 16) & 0xFF;
                state[i * 4 + 3] ^= (rk[i] >> 24) & 0xFF;
            }
        }

        inline void sub_bytes(uint8_t state[16]) {
            for (int i = 0; i < 16; ++i) {
                state[i] = sbox[state[i]];
            }
        }

        inline void inv_sub_bytes(uint8_t state[16]) {
            for (int i = 0; i < 16; ++i) {
                state[i] = inv_sbox[state[i]];
            }
        }

        inline void shift_rows(uint8_t state[16]) {
            uint8_t t;
            // Row 1: shift left by 1
            t = state[1];
            state[1] = state[5];
            state[5] = state[9];
            state[9] = state[13];
            state[13] = t;
            // Row 2: shift left by 2
            t = state[2];
            state[2] = state[10];
            state[10] = t;
            t = state[6];
            state[6] = state[14];
            state[14] = t;
            // Row 3: shift left by 3 (= right by 1)
            t = state[15];
            state[15] = state[11];
            state[11] = state[7];
            state[7] = state[3];
            state[3] = t;
        }

        inline void inv_shift_rows(uint8_t state[16]) {
            uint8_t t;
            // Row 1: shift right by 1
            t = state[13];
            state[13] = state[9];
            state[9] = state[5];
            state[5] = state[1];
            state[1] = t;
            // Row 2: shift right by 2
            t = state[2];
            state[2] = state[10];
            state[10] = t;
            t = state[6];
            state[6] = state[14];
            state[14] = t;
            // Row 3: shift right by 3 (= left by 1)
            t = state[3];
            state[3] = state[7];
            state[7] = state[11];
            state[11] = state[15];
            state[15] = t;
        }

        inline void mix_columns(uint8_t state[16]) {
            for (int c = 0; c < 4; ++c) {
                uint8_t *col = state + c * 4;
                uint8_t a0 = col[0], a1 = col[1], a2 = col[2], a3 = col[3];
                col[0] = mul(a0, 2) ^ mul(a1, 3) ^ a2 ^ a3;
                col[1] = a0 ^ mul(a1, 2) ^ mul(a2, 3) ^ a3;
                col[2] = a0 ^ a1 ^ mul(a2, 2) ^ mul(a3, 3);
                col[3] = mul(a0, 3) ^ a1 ^ a2 ^ mul(a3, 2);
            }
        }

        inline void inv_mix_columns(uint8_t state[16]) {
            for (int c = 0; c < 4; ++c) {
                uint8_t *col = state + c * 4;
                uint8_t a0 = col[0], a1 = col[1], a2 = col[2], a3 = col[3];
                col[0] = mul(a0, 0x0E) ^ mul(a1, 0x0B) ^ mul(a2, 0x0D) ^ mul(a3, 0x09);
                col[1] = mul(a0, 0x09) ^ mul(a1, 0x0E) ^ mul(a2, 0x0B) ^ mul(a3, 0x0D);
                col[2] = mul(a0, 0x0D) ^ mul(a1, 0x09) ^ mul(a2, 0x0E) ^ mul(a3, 0x0B);
                col[3] = mul(a0, 0x0B) ^ mul(a1, 0x0D) ^ mul(a2, 0x09) ^ mul(a3, 0x0E);
            }
        }

        inline void incr_counter(uint8_t counter[16]) {
            for (int i = 15; i >= 0; --i) {
                if (++counter[i] != 0)
                    break;
            }
        }

    } // namespace detail

    // Encrypt a single 16-byte block
    inline void encrypt_block(const Context *ctx, const uint8_t in[16], uint8_t out[16]) {
        uint8_t state[16];
        std::memcpy(state, in, 16);

        detail::add_round_key(state, ctx->round_keys);

        for (int r = 1; r < ctx->rounds; ++r) {
            detail::sub_bytes(state);
            detail::shift_rows(state);
            detail::mix_columns(state);
            detail::add_round_key(state, ctx->round_keys + r * 4);
        }

        detail::sub_bytes(state);
        detail::shift_rows(state);
        detail::add_round_key(state, ctx->round_keys + ctx->rounds * 4);

        std::memcpy(out, state, 16);
    }

    // Decrypt a single 16-byte block
    inline void decrypt_block(const Context *ctx, const uint8_t in[16], uint8_t out[16]) {
        uint8_t state[16];
        std::memcpy(state, in, 16);

        detail::add_round_key(state, ctx->round_keys + ctx->rounds * 4);
        detail::inv_shift_rows(state);
        detail::inv_sub_bytes(state);

        for (int r = ctx->rounds - 1; r > 0; --r) {
            detail::add_round_key(state, ctx->round_keys + r * 4);
            detail::inv_mix_columns(state);
            detail::inv_shift_rows(state);
            detail::inv_sub_bytes(state);
        }

        detail::add_round_key(state, ctx->round_keys);

        std::memcpy(out, state, 16);
    }

    // CTR mode encryption/decryption (same operation)
    inline void ctr_crypt(const Context *ctx, const uint8_t nonce[16], const uint8_t *in, uint8_t *out, size_t len) {
        uint8_t counter[16];
        uint8_t keystream[16];
        std::memcpy(counter, nonce, 16);

        size_t pos = 0;
        while (pos < len) {
            encrypt_block(ctx, counter, keystream);
            detail::incr_counter(counter);

            size_t block_len = len - pos;
            if (block_len > 16)
                block_len = 16;

            for (size_t i = 0; i < block_len; ++i) {
                out[pos + i] = in[pos + i] ^ keystream[i];
            }
            pos += block_len;
        }

        constant_time::wipe(keystream, sizeof(keystream));
        constant_time::wipe(counter, sizeof(counter));
    }

    // CBC mode encryption (requires PKCS7 padding to be applied by caller)
    inline void cbc_encrypt(const Context *ctx, const uint8_t iv[16], const uint8_t *in, uint8_t *out, size_t len) {
        uint8_t prev[16];
        std::memcpy(prev, iv, 16);

        size_t blocks = len / 16;
        for (size_t b = 0; b < blocks; ++b) {
            uint8_t block[16];
            for (int i = 0; i < 16; ++i) {
                block[i] = in[b * 16 + i] ^ prev[i];
            }
            encrypt_block(ctx, block, out + b * 16);
            std::memcpy(prev, out + b * 16, 16);
        }

        constant_time::wipe(prev, sizeof(prev));
    }

    // CBC mode decryption (caller must handle PKCS7 padding removal)
    inline void cbc_decrypt(const Context *ctx, const uint8_t iv[16], const uint8_t *in, uint8_t *out, size_t len) {
        uint8_t prev[16];
        std::memcpy(prev, iv, 16);

        size_t blocks = len / 16;
        for (size_t b = 0; b < blocks; ++b) {
            uint8_t block[16];
            decrypt_block(ctx, in + b * 16, block);
            for (int i = 0; i < 16; ++i) {
                out[b * 16 + i] = block[i] ^ prev[i];
            }
            std::memcpy(prev, in + b * 16, 16);
        }

        constant_time::wipe(prev, sizeof(prev));
    }

    inline void wipe(Context *ctx) { constant_time::wipe(ctx, sizeof(*ctx)); }

} // namespace keylock::crypto::aes
