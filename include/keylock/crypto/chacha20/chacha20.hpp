#pragma once

// ChaCha20 stream cipher implementation
// Adapted from Monocypher (public domain)

#include <cstddef>
#include <cstdint>
#include <cstring>

#include "keylock/crypto/constant_time/wipe.hpp"

namespace keylock::crypto::chacha20 {

    namespace detail {

        inline constexpr uint32_t rotl32(uint32_t x, uint32_t n) { return (x << n) | (x >> (32 - n)); }

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

        inline void store32_le_buf(uint8_t *dst, const uint32_t *src, size_t size) {
            for (size_t i = 0; i < size; ++i) {
                store32_le(dst + i * 4, src[i]);
            }
        }

#define QUARTERROUND(a, b, c, d)                                                                                       \
    a += b;                                                                                                            \
    d = rotl32(d ^ a, 16);                                                                                             \
    c += d;                                                                                                            \
    b = rotl32(b ^ c, 12);                                                                                             \
    a += b;                                                                                                            \
    d = rotl32(d ^ a, 8);                                                                                              \
    c += d;                                                                                                            \
    b = rotl32(b ^ c, 7)

        inline void chacha20_rounds(uint32_t out[16], const uint32_t in[16]) {
            uint32_t t0 = in[0], t1 = in[1], t2 = in[2], t3 = in[3];
            uint32_t t4 = in[4], t5 = in[5], t6 = in[6], t7 = in[7];
            uint32_t t8 = in[8], t9 = in[9], t10 = in[10], t11 = in[11];
            uint32_t t12 = in[12], t13 = in[13], t14 = in[14], t15 = in[15];

            for (int i = 0; i < 10; ++i) {
                QUARTERROUND(t0, t4, t8, t12);
                QUARTERROUND(t1, t5, t9, t13);
                QUARTERROUND(t2, t6, t10, t14);
                QUARTERROUND(t3, t7, t11, t15);
                QUARTERROUND(t0, t5, t10, t15);
                QUARTERROUND(t1, t6, t11, t12);
                QUARTERROUND(t2, t7, t8, t13);
                QUARTERROUND(t3, t4, t9, t14);
            }

            out[0] = t0;
            out[1] = t1;
            out[2] = t2;
            out[3] = t3;
            out[4] = t4;
            out[5] = t5;
            out[6] = t6;
            out[7] = t7;
            out[8] = t8;
            out[9] = t9;
            out[10] = t10;
            out[11] = t11;
            out[12] = t12;
            out[13] = t13;
            out[14] = t14;
            out[15] = t15;
        }

#undef QUARTERROUND

        inline constexpr uint8_t chacha20_constant[16] = {'e', 'x', 'p', 'a', 'n', 'd', ' ', '3',
                                                          '2', '-', 'b', 'y', 't', 'e', ' ', 'k'};

    } // namespace detail

    // HChaCha20: derive subkey from key and 16-byte input
    // Used for XChaCha20 key derivation
    inline void hchacha20(uint8_t out[32], const uint8_t key[32], const uint8_t in[16]) {
        uint32_t block[16];
        detail::load32_le_buf(block, detail::chacha20_constant, 4);
        detail::load32_le_buf(block + 4, key, 8);
        detail::load32_le_buf(block + 12, in, 4);

        detail::chacha20_rounds(block, block);

        detail::store32_le_buf(out, block, 4);
        detail::store32_le_buf(out + 16, block + 12, 4);
        constant_time::wipe(block, sizeof(block));
    }

    // ChaCha20 with 8-byte nonce (DJB original)
    inline uint64_t chacha20_djb(uint8_t *cipher_text, const uint8_t *plain_text, size_t text_size,
                                 const uint8_t key[32], const uint8_t nonce[8], uint64_t ctr) {
        uint32_t input[16];
        detail::load32_le_buf(input, detail::chacha20_constant, 4);
        detail::load32_le_buf(input + 4, key, 8);
        detail::load32_le_buf(input + 14, nonce, 2);
        input[12] = static_cast<uint32_t>(ctr);
        input[13] = static_cast<uint32_t>(ctr >> 32);

        uint32_t pool[16];
        size_t nb_blocks = text_size >> 6;

        for (size_t i = 0; i < nb_blocks; ++i) {
            detail::chacha20_rounds(pool, input);
            if (plain_text != nullptr) {
                for (int j = 0; j < 16; ++j) {
                    uint32_t p = pool[j] + input[j];
                    detail::store32_le(cipher_text, p ^ detail::load32_le(plain_text));
                    cipher_text += 4;
                    plain_text += 4;
                }
            } else {
                for (int j = 0; j < 16; ++j) {
                    uint32_t p = pool[j] + input[j];
                    detail::store32_le(cipher_text, p);
                    cipher_text += 4;
                }
            }
            input[12]++;
            if (input[12] == 0) {
                input[13]++;
            }
        }
        text_size &= 63;

        if (text_size > 0) {
            static const uint8_t zero[64] = {0};
            if (plain_text == nullptr) {
                plain_text = zero;
            }
            detail::chacha20_rounds(pool, input);
            uint8_t tmp[64];
            for (int i = 0; i < 16; ++i) {
                detail::store32_le(tmp + i * 4, pool[i] + input[i]);
            }
            for (size_t i = 0; i < text_size; ++i) {
                cipher_text[i] = tmp[i] ^ plain_text[i];
            }
            constant_time::wipe(tmp, sizeof(tmp));
        }
        ctr = input[12] + (static_cast<uint64_t>(input[13]) << 32) + (text_size > 0 ? 1 : 0);

        constant_time::wipe(pool, sizeof(pool));
        constant_time::wipe(input, sizeof(input));
        return ctr;
    }

    // ChaCha20 with 12-byte nonce (IETF RFC 8439)
    inline uint32_t chacha20_ietf(uint8_t *cipher_text, const uint8_t *plain_text, size_t text_size,
                                  const uint8_t key[32], const uint8_t nonce[12], uint32_t ctr) {
        uint64_t big_ctr = ctr + (static_cast<uint64_t>(detail::load32_le(nonce)) << 32);
        return static_cast<uint32_t>(chacha20_djb(cipher_text, plain_text, text_size, key, nonce + 4, big_ctr));
    }

    // XChaCha20 with 24-byte nonce
    inline uint64_t xchacha20(uint8_t *cipher_text, const uint8_t *plain_text, size_t text_size, const uint8_t key[32],
                              const uint8_t nonce[24], uint64_t ctr) {
        uint8_t sub_key[32];
        hchacha20(sub_key, key, nonce);
        ctr = chacha20_djb(cipher_text, plain_text, text_size, sub_key, nonce + 16, ctr);
        constant_time::wipe(sub_key, sizeof(sub_key));
        return ctr;
    }

} // namespace keylock::crypto::chacha20
