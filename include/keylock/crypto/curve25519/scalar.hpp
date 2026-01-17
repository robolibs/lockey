#pragma once

// Scalar arithmetic modulo L (Ed25519 group order)
// Adapted from Monocypher (BSD-2-Clause OR CC0-1.0)
// Original: Copyright (c) 2017-2020, Loup Vaillant

#include "keylock/crypto/curve25519/common.hpp"

namespace keylock::crypto::curve25519 {

    // L = 2^252 + 27742317777372353535851937790883648493
    inline constexpr u32 L[8] = {
        0x5cf5d3ed, 0x5812631a, 0xa2f79cd6, 0x14def9de, 0x00000000, 0x00000000, 0x00000000, 0x10000000,
    };

    inline void multiply(u32 p[16], const u32 a[8], const u32 b[8]) {
        CURVE25519_FOR(i, 0, 8) {
            u64 carry = 0;
            CURVE25519_FOR(j, 0, 8) {
                carry += p[i + j] + (u64)a[i] * b[j];
                p[i + j] = (u32)carry;
                carry >>= 32;
            }
            p[i + 8] = (u32)carry;
        }
    }

    inline int is_above_l(const u32 x[8]) {
        u64 carry = 1;
        CURVE25519_FOR(i, 0, 8) {
            carry += (u64)x[i] + (~L[i] & 0xffffffff);
            carry >>= 32;
        }
        return (int)carry;
    }

    inline void remove_l(u32 r[8], const u32 x[8]) {
        u64 carry = (u64)is_above_l(x);
        u32 mask = ~(u32)carry + 1;
        CURVE25519_FOR(i, 0, 8) {
            carry += (u64)x[i] + (~L[i] & mask);
            r[i] = (u32)carry;
            carry >>= 32;
        }
    }

    inline void mod_l(u8 reduced[32], const u32 x[16]) {
        static constexpr u32 r[9] = {
            0x0a2c131b, 0xed9ce5a3, 0x086329a7, 0x2106215d, 0xffffffeb, 0xffffffff, 0xffffffff, 0xffffffff, 0xf,
        };
        u32 xr[25] = {0};
        CURVE25519_FOR(i, 0, 9) {
            u64 carry = 0;
            CURVE25519_FOR(j, 0, 16) {
                carry += xr[i + j] + (u64)r[i] * x[j];
                xr[i + j] = (u32)carry;
                carry >>= 32;
            }
            xr[i + 16] = (u32)carry;
        }
        CURVE25519_ZERO(xr, 8);
        CURVE25519_FOR(i, 0, 8) {
            u64 carry = 0;
            for (size_t j = 0; j < 8 - i; j++) {
                carry += xr[i + j] + (u64)xr[i + 16] * L[j];
                xr[i + j] = (u32)carry;
                carry >>= 32;
            }
        }
        u64 carry = 1;
        CURVE25519_FOR(i, 0, 8) {
            carry += (u64)x[i] + (~xr[i] & 0xffffffff);
            xr[i] = (u32)carry;
            carry >>= 32;
        }
        remove_l(xr, xr);
        store32_le_buf(reduced, xr, 8);
        CURVE25519_WIPE_BUFFER(xr);
    }

    inline void reduce(u8 reduced[32], const u8 expanded[64]) {
        u32 x[16];
        load32_le_buf(x, expanded, 16);
        mod_l(reduced, x);
        CURVE25519_WIPE_BUFFER(x);
    }

    inline void mul_add(u8 r[32], const u8 a[32], const u8 b[32], const u8 c[32]) {
        u32 A[8];
        load32_le_buf(A, a, 8);
        u32 B[8];
        load32_le_buf(B, b, 8);
        u32 p[16];
        load32_le_buf(p, c, 8);
        CURVE25519_ZERO(p + 8, 8);
        multiply(p, A, B);
        mod_l(r, p);
        CURVE25519_WIPE_BUFFER(p);
        CURVE25519_WIPE_BUFFER(A);
        CURVE25519_WIPE_BUFFER(B);
    }

} // namespace keylock::crypto::curve25519
