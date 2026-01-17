#pragma once

// Elligator 2 for Curve25519
// Adapted from Monocypher (BSD-2-Clause OR CC0-1.0)
// Original: Copyright (c) 2017-2020, Loup Vaillant
//
// Allows encoding X25519 public keys as random-looking byte strings
// and decoding them back, enabling censorship-resistant protocols.

#include <cstddef>
#include <cstdint>

#include "keylock/crypto/constant_time/wipe.hpp"
#include "keylock/crypto/curve25519/common.hpp"
#include "keylock/crypto/curve25519/field.hpp"

namespace keylock::crypto::elligator {

    using namespace curve25519;

    namespace detail {

        // A = 486662 (Montgomery curve constant for Curve25519)
        inline constexpr i32 A_data[10] = {486662, 0, 0, 0, 0, 0, 0, 0, 0, 0};

        // A^2 = 486662^2 = 236839902006
        inline constexpr i32 A2_data[10] = {12721188, 3529, 0, 0, 0, 0, 0, 0, 0, 0};

        // ufactor = -sqrt(-1) * 2 (for non_square = 2)
        // This is -sqrtm1 * 2 in radix 2^25.5
        inline constexpr i32 ufactor_data[10] = {-12222970, -8312128, 11511410, -9067497,  -15300785,
                                                 -241793,   25456130, 14121551, -12187136, 3972024};

        // fe_one
        inline constexpr i32 fe_one_arr[10] = {1, 0, 0, 0, 0, 0, 0, 0, 0, 0};

    } // namespace detail

    // Map a 32-byte representative (hidden) to a curve point (u-coordinate)
    // This is the forward Elligator 2 map
    inline void map(uint8_t curve[32], const uint8_t hidden[32]) {
        fe A, A2, ufactor;
        CURVE25519_COPY(A, detail::A_data, 10);
        CURVE25519_COPY(A2, detail::A2_data, 10);
        CURVE25519_COPY(ufactor, detail::ufactor_data, 10);

        fe r, u, t1, t2, t3;
        fe_frombytes_mask(r, hidden, 2); // r is encoded in 254 bits
        fe_sq(r, r);
        fe_add(t1, r, r);

        fe one;
        CURVE25519_COPY(one, detail::fe_one_arr, 10);
        fe_add(u, t1, one);
        fe_sq(t2, u);
        fe_mul(t3, A2, t1);
        fe_sub(t3, t3, t2);
        fe_mul(t3, t3, A);
        fe_mul(t1, t2, u);
        fe_mul(t1, t3, t1);
        int is_square = invsqrt(t1, t1);
        fe_mul(u, r, ufactor);
        fe_ccopy(u, one, is_square);
        fe_sq(t1, t1);
        fe_mul(u, u, A);
        fe_mul(u, u, t3);
        fe_mul(u, u, t2);
        fe_mul(u, u, t1);
        fe_neg(u, u);
        fe_tobytes(curve, u);

        CURVE25519_WIPE_BUFFER(t1);
        CURVE25519_WIPE_BUFFER(r);
        CURVE25519_WIPE_BUFFER(t2);
        CURVE25519_WIPE_BUFFER(u);
        CURVE25519_WIPE_BUFFER(t3);
    }

    // Compute the representative of a public key, if possible
    // Returns 0 on success, -1 if the point has no representative
    // The tweak parameter should be a random byte for padding
    inline int reverse(uint8_t hidden[32], const uint8_t public_key[32], uint8_t tweak) {
        fe A;
        CURVE25519_COPY(A, detail::A_data, 10);

        fe t1, t2, t3;
        fe_frombytes(t1, public_key); // t1 = u

        fe_add(t2, t1, A); // t2 = u + A
        fe_mul(t3, t1, t2);
        fe_mul_small(t3, t3, -2);
        int is_square = invsqrt(t3, t3); // t3 = sqrt(-1 / (non_square * u * (u+A)))

        if (is_square) {
            fe_ccopy(t1, t2, tweak & 1); // multiply by u if v is positive
            fe_mul(t3, t1, t3);          // multiply by u+A otherwise
            fe_mul_small(t1, t3, 2);
            fe_neg(t2, t3);
            fe_ccopy(t3, t2, fe_isodd(t1));
            fe_tobytes(hidden, t3);

            // Pad with two random bits
            hidden[31] |= tweak & 0xc0;
        }

        CURVE25519_WIPE_BUFFER(t1);
        CURVE25519_WIPE_BUFFER(t2);
        CURVE25519_WIPE_BUFFER(t3);
        return is_square - 1;
    }

} // namespace keylock::crypto::elligator
