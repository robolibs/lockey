#pragma once

// GCM (Galois/Counter Mode) for AES
// Adapted from plusaes (Boost Software License 1.0)

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>

#include "keylock/crypto/aead_aes256gcm/aes.hpp"

namespace keylock::crypto::gcm {

    namespace detail {

        // 128-bit block operations
        struct Block {
            uint8_t data[16];

            Block() { std::memset(data, 0, 16); }

            Block(const uint8_t *bytes, size_t len) {
                std::memset(data, 0, 16);
                if (bytes && len > 0) {
                    std::memcpy(data, bytes, std::min(len, size_t(16)));
                }
            }

            Block operator^(const Block &other) const {
                Block result;
                for (int i = 0; i < 16; ++i) {
                    result.data[i] = data[i] ^ other.data[i];
                }
                return result;
            }
        };

        // GF(2^128) multiplication
        inline Block gf_mul(const Block &X, const Block &Y) {
            // R = 0xe1 || 0^120 in polynomial representation
            uint8_t Z[16] = {0};
            uint8_t V[16];
            std::memcpy(V, Y.data, 16);

            for (int i = 0; i < 128; ++i) {
                // Check bit i of X (MSB first)
                int byte_idx = i / 8;
                int bit_idx = 7 - (i % 8);
                if (X.data[byte_idx] & (1 << bit_idx)) {
                    for (int j = 0; j < 16; ++j) {
                        Z[j] ^= V[j];
                    }
                }

                // Multiply V by x (shift right in GF(2^128))
                int lsb = V[15] & 1;
                for (int j = 15; j > 0; --j) {
                    V[j] = (V[j] >> 1) | (V[j - 1] << 7);
                }
                V[0] >>= 1;

                if (lsb) {
                    V[0] ^= 0xe1; // R polynomial
                }
            }

            Block result;
            std::memcpy(result.data, Z, 16);
            return result;
        }

        // GHASH function
        inline Block ghash(const Block &H, const uint8_t *data, size_t data_size) {
            Block Y;
            size_t blocks = data_size / 16;

            for (size_t i = 0; i < blocks; ++i) {
                Block Xi(data + i * 16, 16);
                Y = gf_mul(Y ^ Xi, H);
            }

            // Handle partial last block
            size_t remainder = data_size % 16;
            if (remainder > 0) {
                Block Xi(data + blocks * 16, remainder);
                Y = gf_mul(Y ^ Xi, H);
            }

            return Y;
        }

        // Increment counter (big-endian 32-bit increment of last 4 bytes)
        inline void inc32(uint8_t counter[16]) {
            for (int i = 15; i >= 12; --i) {
                if (++counter[i] != 0) {
                    break;
                }
            }
        }

        // GCTR function
        inline void gctr(const aes256::Context *aes_ctx, const uint8_t icb[16], const uint8_t *input, size_t input_size,
                         uint8_t *output) {
            if (input_size == 0) {
                return;
            }

            uint8_t counter[16];
            std::memcpy(counter, icb, 16);

            size_t blocks = input_size / 16;
            for (size_t i = 0; i < blocks; ++i) {
                uint8_t encrypted_counter[16];
                aes256::encrypt_block(aes_ctx, counter, encrypted_counter);

                for (int j = 0; j < 16; ++j) {
                    output[i * 16 + j] = input[i * 16 + j] ^ encrypted_counter[j];
                }

                inc32(counter);
            }

            // Handle partial last block
            size_t remainder = input_size % 16;
            if (remainder > 0) {
                uint8_t encrypted_counter[16];
                aes256::encrypt_block(aes_ctx, counter, encrypted_counter);

                for (size_t j = 0; j < remainder; ++j) {
                    output[blocks * 16 + j] = input[blocks * 16 + j] ^ encrypted_counter[j];
                }
            }
        }

        // Compute J0 from IV
        inline void compute_j0(const Block &H, const aes256::Context *aes_ctx, const uint8_t *iv, size_t iv_size,
                               uint8_t j0[16]) {
            if (iv_size == 12) {
                // Standard case: IV || 0^31 || 1
                std::memcpy(j0, iv, 12);
                j0[12] = 0;
                j0[13] = 0;
                j0[14] = 0;
                j0[15] = 1;
            } else {
                // General case: GHASH(H, IV || 0^s || [len(IV)]_64)
                size_t s = (16 - (iv_size % 16)) % 16;
                size_t ghash_len = iv_size + s + 8 + 8;
                std::vector<uint8_t> ghash_input(ghash_len, 0);

                std::memcpy(ghash_input.data(), iv, iv_size);
                // s zero bytes already filled
                // 64-bit length of IV in bits (big-endian)
                uint64_t iv_bits = iv_size * 8;
                for (int i = 0; i < 8; ++i) {
                    ghash_input[ghash_len - 8 + i] = static_cast<uint8_t>((iv_bits >> (56 - i * 8)) & 0xFF);
                }

                Block result = ghash(H, ghash_input.data(), ghash_len);
                std::memcpy(j0, result.data, 16);
            }
        }

    } // namespace detail

} // namespace keylock::crypto::gcm
