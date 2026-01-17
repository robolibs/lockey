#pragma once

// Curve25519 common utilities
// Adapted from Monocypher (BSD-2-Clause OR CC0-1.0)
// Original: Copyright (c) 2017-2020, Loup Vaillant

#include <cstddef>
#include <cstdint>
#include <cstring>

namespace keylock::crypto::curve25519 {

    /////////////////
    /// Utilities ///
    /////////////////
    using u8 = uint8_t;
    using u32 = uint32_t;
    using u64 = uint64_t;
    using i8 = int8_t;
    using i16 = int16_t;
    using i32 = int32_t;
    using i64 = int64_t;

#define CURVE25519_FOR(i, start, end) for (size_t i = (start); i < (end); i++)
#define CURVE25519_COPY(dst, src, size) CURVE25519_FOR(_i_, 0, size)(dst)[_i_] = (src)[_i_]
#define CURVE25519_ZERO(buf, size) CURVE25519_FOR(_i_, 0, size)(buf)[_i_] = 0
#define CURVE25519_WIPE_CTX(ctx) crypto_wipe(ctx, sizeof(*(ctx)))
#define CURVE25519_WIPE_BUFFER(buffer) crypto_wipe(buffer, sizeof(buffer))
#define CURVE25519_MIN(a, b) ((a) <= (b) ? (a) : (b))
#define CURVE25519_MAX(a, b) ((a) >= (b) ? (a) : (b))

    inline void crypto_wipe(void *secret, size_t size) {
        volatile u8 *v_secret = (u8 *)secret;
        CURVE25519_ZERO(v_secret, size);
    }

    inline u32 load24_le(const u8 s[3]) { return ((u32)s[0] << 0) | ((u32)s[1] << 8) | ((u32)s[2] << 16); }

    inline u32 load32_le(const u8 s[4]) {
        return ((u32)s[0] << 0) | ((u32)s[1] << 8) | ((u32)s[2] << 16) | ((u32)s[3] << 24);
    }

    inline u64 load64_le(const u8 s[8]) { return load32_le(s) | ((u64)load32_le(s + 4) << 32); }

    inline void store32_le(u8 out[4], u32 in) {
        out[0] = in & 0xff;
        out[1] = (in >> 8) & 0xff;
        out[2] = (in >> 16) & 0xff;
        out[3] = (in >> 24) & 0xff;
    }

    inline void store64_le(u8 out[8], u64 in) {
        store32_le(out, (u32)in);
        store32_le(out + 4, in >> 32);
    }

    inline void load32_le_buf(u32 *dst, const u8 *src, size_t size) {
        CURVE25519_FOR(i, 0, size) { dst[i] = load32_le(src + i * 4); }
    }

    inline void load64_le_buf(u64 *dst, const u8 *src, size_t size) {
        CURVE25519_FOR(i, 0, size) { dst[i] = load64_le(src + i * 8); }
    }

    inline void store32_le_buf(u8 *dst, const u32 *src, size_t size) {
        CURVE25519_FOR(i, 0, size) { store32_le(dst + i * 4, src[i]); }
    }

    inline void store64_le_buf(u8 *dst, const u64 *src, size_t size) {
        CURVE25519_FOR(i, 0, size) { store64_le(dst + i * 8, src[i]); }
    }

    inline u64 rotr64(u64 x, u64 n) { return (x >> n) ^ (x << (64 - n)); }
    inline u32 rotl32(u32 x, u32 n) { return (x << n) ^ (x >> (32 - n)); }

    inline int neq0(u64 diff) {
        u64 half = (diff >> 32) | ((u32)diff);
        return (1 & ((half - 1) >> 32)) - 1;
    }

    inline u64 x16(const u8 a[16], const u8 b[16]) {
        return (load64_le(a + 0) ^ load64_le(b + 0)) | (load64_le(a + 8) ^ load64_le(b + 8));
    }

    inline u64 x32(const u8 a[32], const u8 b[32]) { return x16(a, b) | x16(a + 16, b + 16); }

    inline u64 x64(const u8 a[64], const u8 b[64]) { return x32(a, b) | x32(a + 32, b + 32); }

    inline int crypto_verify16(const u8 a[16], const u8 b[16]) { return neq0(x16(a, b)); }
    inline int crypto_verify32(const u8 a[32], const u8 b[32]) { return neq0(x32(a, b)); }
    inline int crypto_verify64(const u8 a[64], const u8 b[64]) { return neq0(x64(a, b)); }

    // Trim scalar for Ed25519/X25519 (clamp)
    inline void trim_scalar(u8 out[32], const u8 in[32]) {
        CURVE25519_COPY(out, in, 32);
        out[0] &= 248;
        out[31] &= 127;
        out[31] |= 64;
    }

    // Get bit i of scalar
    inline int scalar_bit(const u8 s[32], int i) {
        if (i < 0) {
            return 0;
        }
        return (s[i >> 3] >> (i & 7)) & 1;
    }

} // namespace keylock::crypto::curve25519
