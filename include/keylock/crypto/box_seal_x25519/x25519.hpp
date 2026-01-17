#pragma once

// X25519 key exchange (RFC 7748)
// Adapted from Monocypher (BSD-2-Clause OR CC0-1.0)
// Original: Copyright (c) 2017-2020, Loup Vaillant

#include <cstddef>
#include <cstdint>

#include "keylock/crypto/constant_time/wipe.hpp"
#include "keylock/crypto/curve25519/common.hpp"
#include "keylock/crypto/curve25519/field.hpp"

namespace keylock::crypto::x25519 {

    // Constants matching libsodium
    inline constexpr size_t PUBLICKEYBYTES = 32;
    inline constexpr size_t SECRETKEYBYTES = 32;
    inline constexpr size_t SCALARBYTES = 32;

    namespace detail {
        using namespace curve25519;

        // Montgomery ladder for X25519
        inline void scalarmult_impl(u8 q[32], const u8 scalar[32], const u8 p[32], int nb_bits) {
            fe x1;
            fe_frombytes(x1, p);

            fe x2, z2, x3, z3, t0, t1;
            fe_1(x2);
            fe_0(z2);
            fe_copy(x3, x1);
            fe_1(z3);
            int swap = 0;
            for (int pos = nb_bits - 1; pos >= 0; --pos) {
                int b = scalar_bit(scalar, pos);
                swap ^= b;
                fe_cswap(x2, x3, swap);
                fe_cswap(z2, z3, swap);
                swap = b;

                fe_sub(t0, x3, z3);
                fe_sub(t1, x2, z2);
                fe_add(x2, x2, z2);
                fe_add(z2, x3, z3);
                fe_mul(z3, t0, x2);
                fe_mul(z2, z2, t1);
                fe_sq(t0, t1);
                fe_sq(t1, x2);
                fe_add(x3, z3, z2);
                fe_sub(z2, z3, z2);
                fe_mul(x2, t1, t0);
                fe_sub(t1, t1, t0);
                fe_sq(z2, z2);
                fe_mul_small(z3, t1, 121666);
                fe_sq(x3, x3);
                fe_add(t0, t0, z3);
                fe_mul(z3, x1, z2);
                fe_mul(z2, t1, t0);
            }
            fe_cswap(x2, x3, swap);
            fe_cswap(z2, z3, swap);

            fe_invert(z2, z2);
            fe_mul(x2, x2, z2);
            fe_tobytes(q, x2);

            CURVE25519_WIPE_BUFFER(x1);
            CURVE25519_WIPE_BUFFER(x2);
            CURVE25519_WIPE_BUFFER(z2);
            CURVE25519_WIPE_BUFFER(t0);
            CURVE25519_WIPE_BUFFER(x3);
            CURVE25519_WIPE_BUFFER(z3);
            CURVE25519_WIPE_BUFFER(t1);
        }
    } // namespace detail

    // Generate public key from secret key
    inline void public_key(uint8_t pk[32], const uint8_t sk[32]) {
        static const uint8_t base_point[32] = {9};
        uint8_t e[32];
        curve25519::trim_scalar(e, sk);
        detail::scalarmult_impl(pk, e, base_point, 255);
        curve25519::CURVE25519_WIPE_BUFFER(e);
    }

    // Scalar multiplication (Diffie-Hellman)
    inline void scalarmult(uint8_t shared[32], const uint8_t sk[32], const uint8_t pk[32]) {
        uint8_t e[32];
        curve25519::trim_scalar(e, sk);
        detail::scalarmult_impl(shared, e, pk, 255);
        curve25519::CURVE25519_WIPE_BUFFER(e);
    }

    // Generate keypair
    inline void keypair(uint8_t pk[32], uint8_t sk[32]) {
        // Caller must fill sk with random bytes first
        public_key(pk, sk);
    }

} // namespace keylock::crypto::x25519
