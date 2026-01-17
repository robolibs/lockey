#pragma once

// AES-256-GCM AEAD
// Compatible with libsodium crypto_aead_aes256gcm_*

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <vector>

#include "keylock/crypto/aead_aes256gcm/aes.hpp"
#include "keylock/crypto/aead_aes256gcm/gcm.hpp"
#include "keylock/crypto/constant_time/verify.hpp"
#include "keylock/crypto/constant_time/wipe.hpp"

namespace keylock::crypto::aead_aes256gcm {

    // Constants matching libsodium
    inline constexpr size_t KEYBYTES = 32;
    inline constexpr size_t NPUBBYTES = 12; // nonce size
    inline constexpr size_t ABYTES = 16;    // tag size

    // Always available (software implementation)
    inline int is_available() { return 1; }

    namespace detail {

        inline void compute_tag(uint8_t tag[16], const aes256::Context *aes_ctx, const gcm::detail::Block &H,
                                const uint8_t *ad, size_t ad_size, const uint8_t *cipher, size_t cipher_size,
                                const uint8_t j0[16]) {
            // Compute GHASH input: A || 0^v || C || 0^u || [len(A)]_64 || [len(C)]_64
            size_t u = (16 - (cipher_size % 16)) % 16;
            size_t v = (16 - (ad_size % 16)) % 16;
            size_t ghash_len = ad_size + v + cipher_size + u + 16;

            std::vector<uint8_t> ghash_input(ghash_len, 0);
            size_t offset = 0;

            if (ad_size > 0) {
                std::memcpy(ghash_input.data(), ad, ad_size);
            }
            offset = ad_size + v;

            if (cipher_size > 0) {
                std::memcpy(ghash_input.data() + offset, cipher, cipher_size);
            }
            offset += cipher_size + u;

            // 64-bit lengths in bits (big-endian)
            uint64_t ad_bits = ad_size * 8;
            uint64_t cipher_bits = cipher_size * 8;
            for (int i = 0; i < 8; ++i) {
                ghash_input[offset + i] = static_cast<uint8_t>((ad_bits >> (56 - i * 8)) & 0xFF);
                ghash_input[offset + 8 + i] = static_cast<uint8_t>((cipher_bits >> (56 - i * 8)) & 0xFF);
            }

            // S = GHASH(H, ghash_input)
            gcm::detail::Block S = gcm::detail::ghash(H, ghash_input.data(), ghash_len);

            // T = GCTR(K, J0, S)
            gcm::detail::gctr(aes_ctx, j0, S.data, 16, tag);
        }

    } // namespace detail

    // Encrypt with AES-256-GCM
    // Output format: ciphertext || 16-byte tag
    inline int encrypt(uint8_t *c, unsigned long long *clen_p, const uint8_t *m, unsigned long long mlen,
                       const uint8_t *ad, unsigned long long adlen,
                       const uint8_t *nsec, // unused
                       const uint8_t nonce[NPUBBYTES], const uint8_t key[KEYBYTES]) {
        (void)nsec;

        // Setup AES context
        aes256::Context aes_ctx;
        aes256::key_setup(&aes_ctx, key);

        // Compute H = AES_K(0^128)
        uint8_t zero_block[16] = {0};
        gcm::detail::Block H;
        aes256::encrypt_block(&aes_ctx, zero_block, H.data);

        // Compute J0
        uint8_t j0[16];
        gcm::detail::compute_j0(H, &aes_ctx, nonce, NPUBBYTES, j0);

        // Increment J0 for encryption
        uint8_t icb[16];
        std::memcpy(icb, j0, 16);
        gcm::detail::inc32(icb);

        // Encrypt
        gcm::detail::gctr(&aes_ctx, icb, m, mlen, c);

        // Compute authentication tag
        detail::compute_tag(c + mlen, &aes_ctx, H, ad, adlen, c, mlen, j0);

        constant_time::wipe(&aes_ctx, sizeof(aes_ctx));

        if (clen_p != nullptr) {
            *clen_p = mlen + ABYTES;
        }

        return 0;
    }

    // Decrypt with AES-256-GCM
    // Input format: ciphertext || 16-byte tag
    inline int decrypt(uint8_t *m, unsigned long long *mlen_p,
                       uint8_t *nsec, // unused
                       const uint8_t *c, unsigned long long clen, const uint8_t *ad, unsigned long long adlen,
                       const uint8_t nonce[NPUBBYTES], const uint8_t key[KEYBYTES]) {
        (void)nsec;

        if (clen < ABYTES) {
            return -1;
        }

        unsigned long long mlen = clen - ABYTES;

        // Setup AES context
        aes256::Context aes_ctx;
        aes256::key_setup(&aes_ctx, key);

        // Compute H
        uint8_t zero_block[16] = {0};
        gcm::detail::Block H;
        aes256::encrypt_block(&aes_ctx, zero_block, H.data);

        // Compute J0
        uint8_t j0[16];
        gcm::detail::compute_j0(H, &aes_ctx, nonce, NPUBBYTES, j0);

        // Compute expected tag
        uint8_t expected_tag[16];
        detail::compute_tag(expected_tag, &aes_ctx, H, ad, adlen, c, mlen, j0);

        // Verify tag
        if (constant_time::verify16(expected_tag, c + mlen) != 0) {
            constant_time::wipe(&aes_ctx, sizeof(aes_ctx));
            constant_time::wipe(expected_tag, sizeof(expected_tag));
            return -1;
        }

        // Decrypt
        uint8_t icb[16];
        std::memcpy(icb, j0, 16);
        gcm::detail::inc32(icb);
        gcm::detail::gctr(&aes_ctx, icb, c, mlen, m);

        constant_time::wipe(&aes_ctx, sizeof(aes_ctx));
        constant_time::wipe(expected_tag, sizeof(expected_tag));

        if (mlen_p != nullptr) {
            *mlen_p = mlen;
        }

        return 0;
    }

    // Detached encryption
    inline int encrypt_detached(uint8_t *c, uint8_t mac[ABYTES], unsigned long long *maclen_p, const uint8_t *m,
                                unsigned long long mlen, const uint8_t *ad, unsigned long long adlen,
                                const uint8_t *nsec, const uint8_t nonce[NPUBBYTES], const uint8_t key[KEYBYTES]) {
        (void)nsec;

        aes256::Context aes_ctx;
        aes256::key_setup(&aes_ctx, key);

        uint8_t zero_block[16] = {0};
        gcm::detail::Block H;
        aes256::encrypt_block(&aes_ctx, zero_block, H.data);

        uint8_t j0[16];
        gcm::detail::compute_j0(H, &aes_ctx, nonce, NPUBBYTES, j0);

        uint8_t icb[16];
        std::memcpy(icb, j0, 16);
        gcm::detail::inc32(icb);

        gcm::detail::gctr(&aes_ctx, icb, m, mlen, c);
        detail::compute_tag(mac, &aes_ctx, H, ad, adlen, c, mlen, j0);

        constant_time::wipe(&aes_ctx, sizeof(aes_ctx));

        if (maclen_p != nullptr) {
            *maclen_p = ABYTES;
        }

        return 0;
    }

    // Detached decryption
    inline int decrypt_detached(uint8_t *m, uint8_t *nsec, const uint8_t *c, unsigned long long clen,
                                const uint8_t mac[ABYTES], const uint8_t *ad, unsigned long long adlen,
                                const uint8_t nonce[NPUBBYTES], const uint8_t key[KEYBYTES]) {
        (void)nsec;

        aes256::Context aes_ctx;
        aes256::key_setup(&aes_ctx, key);

        uint8_t zero_block[16] = {0};
        gcm::detail::Block H;
        aes256::encrypt_block(&aes_ctx, zero_block, H.data);

        uint8_t j0[16];
        gcm::detail::compute_j0(H, &aes_ctx, nonce, NPUBBYTES, j0);

        uint8_t expected_tag[16];
        detail::compute_tag(expected_tag, &aes_ctx, H, ad, adlen, c, clen, j0);

        if (constant_time::verify16(expected_tag, mac) != 0) {
            constant_time::wipe(&aes_ctx, sizeof(aes_ctx));
            constant_time::wipe(expected_tag, sizeof(expected_tag));
            return -1;
        }

        uint8_t icb[16];
        std::memcpy(icb, j0, 16);
        gcm::detail::inc32(icb);
        gcm::detail::gctr(&aes_ctx, icb, c, clen, m);

        constant_time::wipe(&aes_ctx, sizeof(aes_ctx));
        constant_time::wipe(expected_tag, sizeof(expected_tag));

        return 0;
    }

} // namespace keylock::crypto::aead_aes256gcm
