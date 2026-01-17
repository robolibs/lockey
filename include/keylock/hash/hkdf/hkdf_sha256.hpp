#pragma once

// HKDF with SHA-256

#include <cstddef>
#include <cstdint>
#include <cstring>

#include "keylock/crypto/constant_time/wipe.hpp"
#include "keylock/hash/hmac/hmac_sha256.hpp"

namespace keylock::hash::hkdf_sha256 {

    namespace detail {

        inline size_t min_val(size_t a, size_t b) { return a <= b ? a : b; }

    } // namespace detail

    // HKDF-Expand
    inline void expand(uint8_t *okm, size_t okm_size, const uint8_t *prk, size_t prk_size, const uint8_t *info,
                       size_t info_size) {
        int not_first = 0;
        uint8_t ctr = 1;
        uint8_t blk[32];

        while (okm_size > 0) {
            size_t out_size = detail::min_val(okm_size, sizeof(blk));

            hmac_sha256::Context ctx;
            hmac_sha256::init(&ctx, prk, prk_size);
            if (not_first) {
                hmac_sha256::update(&ctx, blk, sizeof(blk));
            }
            hmac_sha256::update(&ctx, info, info_size);
            hmac_sha256::update(&ctx, &ctr, 1);
            hmac_sha256::final(&ctx, blk);

            std::memcpy(okm, blk, out_size);

            not_first = 1;
            okm += out_size;
            okm_size -= out_size;
            ctr++;
        }

        crypto::constant_time::wipe(blk, sizeof(blk));
    }

    // HKDF-Extract
    inline void extract(uint8_t prk[32], const uint8_t *salt, size_t salt_size, const uint8_t *ikm, size_t ikm_size) {
        if (salt == nullptr || salt_size == 0) {
            uint8_t zero_salt[32] = {0};
            hmac_sha256::hmac(prk, zero_salt, sizeof(zero_salt), ikm, ikm_size);
        } else {
            hmac_sha256::hmac(prk, salt, salt_size, ikm, ikm_size);
        }
    }

    // Full HKDF (Extract + Expand)
    inline void hkdf(uint8_t *okm, size_t okm_size, const uint8_t *ikm, size_t ikm_size, const uint8_t *salt,
                     size_t salt_size, const uint8_t *info, size_t info_size) {
        uint8_t prk[32];
        extract(prk, salt, salt_size, ikm, ikm_size);
        expand(okm, okm_size, prk, sizeof(prk), info, info_size);
        crypto::constant_time::wipe(prk, sizeof(prk));
    }

} // namespace keylock::hash::hkdf_sha256
