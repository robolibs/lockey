#pragma once

// ChaCha20-Poly1305 IETF AEAD (RFC 8439)
// Compatible with libsodium crypto_aead_chacha20poly1305_ietf_*

#include <cstddef>
#include <cstdint>
#include <cstring>

#include "keylock/crypto/chacha20/chacha20.hpp"
#include "keylock/crypto/constant_time/verify.hpp"
#include "keylock/crypto/constant_time/wipe.hpp"
#include "keylock/crypto/poly1305/poly1305.hpp"

namespace keylock::crypto::aead_chacha20poly1305_ietf {

    // Constants matching libsodium
    inline constexpr size_t KEYBYTES = 32;
    inline constexpr size_t NPUBBYTES = 12; // nonce size (IETF)
    inline constexpr size_t ABYTES = 16;    // tag size

    namespace detail {

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

        inline size_t pad16(size_t size) { return (16 - (size & 15)) & 15; }

        // Compute Poly1305 key from ChaCha20 IETF
        inline void derive_poly_key(uint8_t poly_key[32], const uint8_t key[32], const uint8_t nonce[12]) {
            std::memset(poly_key, 0, 32);
            chacha20::chacha20_ietf(poly_key, poly_key, 32, key, nonce, 0);
        }

        inline void compute_mac(uint8_t mac[16], const uint8_t *ad, size_t ad_size, const uint8_t *cipher,
                                size_t cipher_size, const uint8_t poly_key[32]) {
            poly1305::Context ctx;
            poly1305::init(&ctx, poly_key);

            if (ad_size > 0) {
                poly1305::update(&ctx, ad, ad_size);
                uint8_t pad[16] = {0};
                size_t pad_size = pad16(ad_size);
                if (pad_size > 0) {
                    poly1305::update(&ctx, pad, pad_size);
                }
            }

            if (cipher_size > 0) {
                poly1305::update(&ctx, cipher, cipher_size);
                uint8_t pad[16] = {0};
                size_t pad_size = pad16(cipher_size);
                if (pad_size > 0) {
                    poly1305::update(&ctx, pad, pad_size);
                }
            }

            uint8_t lengths[16];
            store64_le(lengths, ad_size);
            store64_le(lengths + 8, cipher_size);
            poly1305::update(&ctx, lengths, 16);

            poly1305::final(&ctx, mac);
        }

    } // namespace detail

    inline int encrypt(uint8_t *c, unsigned long long *clen_p, const uint8_t *m, unsigned long long mlen,
                       const uint8_t *ad, unsigned long long adlen, const uint8_t *nsec, const uint8_t nonce[NPUBBYTES],
                       const uint8_t key[KEYBYTES]) {
        (void)nsec;

        uint8_t poly_key[32];
        detail::derive_poly_key(poly_key, key, nonce);

        chacha20::chacha20_ietf(c, m, mlen, key, nonce, 1);
        detail::compute_mac(c + mlen, ad, adlen, c, mlen, poly_key);

        constant_time::wipe(poly_key, sizeof(poly_key));

        if (clen_p != nullptr) {
            *clen_p = mlen + ABYTES;
        }

        return 0;
    }

    inline int decrypt(uint8_t *m, unsigned long long *mlen_p, uint8_t *nsec, const uint8_t *c, unsigned long long clen,
                       const uint8_t *ad, unsigned long long adlen, const uint8_t nonce[NPUBBYTES],
                       const uint8_t key[KEYBYTES]) {
        (void)nsec;

        if (clen < ABYTES) {
            return -1;
        }

        unsigned long long mlen = clen - ABYTES;

        uint8_t poly_key[32];
        detail::derive_poly_key(poly_key, key, nonce);

        uint8_t expected_mac[16];
        detail::compute_mac(expected_mac, ad, adlen, c, mlen, poly_key);

        if (constant_time::verify16(expected_mac, c + mlen) != 0) {
            constant_time::wipe(poly_key, sizeof(poly_key));
            constant_time::wipe(expected_mac, sizeof(expected_mac));
            return -1;
        }

        chacha20::chacha20_ietf(m, c, mlen, key, nonce, 1);

        constant_time::wipe(poly_key, sizeof(poly_key));
        constant_time::wipe(expected_mac, sizeof(expected_mac));

        if (mlen_p != nullptr) {
            *mlen_p = mlen;
        }

        return 0;
    }

    inline int encrypt_detached(uint8_t *c, uint8_t mac[ABYTES], unsigned long long *maclen_p, const uint8_t *m,
                                unsigned long long mlen, const uint8_t *ad, unsigned long long adlen,
                                const uint8_t *nsec, const uint8_t nonce[NPUBBYTES], const uint8_t key[KEYBYTES]) {
        (void)nsec;

        uint8_t poly_key[32];
        detail::derive_poly_key(poly_key, key, nonce);

        chacha20::chacha20_ietf(c, m, mlen, key, nonce, 1);
        detail::compute_mac(mac, ad, adlen, c, mlen, poly_key);

        constant_time::wipe(poly_key, sizeof(poly_key));

        if (maclen_p != nullptr) {
            *maclen_p = ABYTES;
        }

        return 0;
    }

    inline int decrypt_detached(uint8_t *m, uint8_t *nsec, const uint8_t *c, unsigned long long clen,
                                const uint8_t mac[ABYTES], const uint8_t *ad, unsigned long long adlen,
                                const uint8_t nonce[NPUBBYTES], const uint8_t key[KEYBYTES]) {
        (void)nsec;

        uint8_t poly_key[32];
        detail::derive_poly_key(poly_key, key, nonce);

        uint8_t expected_mac[16];
        detail::compute_mac(expected_mac, ad, adlen, c, clen, poly_key);

        if (constant_time::verify16(expected_mac, mac) != 0) {
            constant_time::wipe(poly_key, sizeof(poly_key));
            constant_time::wipe(expected_mac, sizeof(expected_mac));
            return -1;
        }

        chacha20::chacha20_ietf(m, c, clen, key, nonce, 1);

        constant_time::wipe(poly_key, sizeof(poly_key));
        constant_time::wipe(expected_mac, sizeof(expected_mac));

        return 0;
    }

} // namespace keylock::crypto::aead_chacha20poly1305_ietf
