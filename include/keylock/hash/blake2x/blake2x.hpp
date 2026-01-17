#pragma once

// BLAKE2xb and BLAKE2xs - Extensible Output Functions (XOFs)
// Based on BLAKE2b and BLAKE2s respectively
// Provides variable-length output up to 2^32-1 bytes

#include <cstddef>
#include <cstdint>
#include <cstring>

#include "keylock/crypto/constant_time/wipe.hpp"
#include "keylock/hash/blake2b/blake2b.hpp"
#include "keylock/hash/blake2s/blake2s.hpp"

namespace keylock::hash::blake2xb {

    inline constexpr size_t BYTES_MAX = 0xFFFFFFFFULL; // 2^32 - 1

    namespace detail {

        inline constexpr uint64_t iv[8] = {
            0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL, 0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
            0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL, 0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL,
        };

        inline uint64_t load64_le(const uint8_t s[8]) {
            return static_cast<uint64_t>(s[0]) | (static_cast<uint64_t>(s[1]) << 8) |
                   (static_cast<uint64_t>(s[2]) << 16) | (static_cast<uint64_t>(s[3]) << 24) |
                   (static_cast<uint64_t>(s[4]) << 32) | (static_cast<uint64_t>(s[5]) << 40) |
                   (static_cast<uint64_t>(s[6]) << 48) | (static_cast<uint64_t>(s[7]) << 56);
        }

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

        inline void store32_le(uint8_t out[4], uint32_t in) {
            out[0] = static_cast<uint8_t>(in & 0xff);
            out[1] = static_cast<uint8_t>((in >> 8) & 0xff);
            out[2] = static_cast<uint8_t>((in >> 16) & 0xff);
            out[3] = static_cast<uint8_t>((in >> 24) & 0xff);
        }

    } // namespace detail

    struct Context {
        blake2b::Context inner;
        uint8_t root_hash[64];
        uint32_t xof_length;  // Desired output length (0xFFFFFFFF for unlimited)
        uint32_t node_offset; // Current output block
        size_t produced;      // Bytes produced so far
        bool finalized;       // Whether inner hash is finalized
    };

    inline void init(Context *ctx, uint32_t xof_length = 0xFFFFFFFF) {
        // Initialize inner BLAKE2b with XOF parameters
        std::memset(&ctx->inner, 0, sizeof(ctx->inner));
        for (int i = 0; i < 8; ++i) {
            ctx->inner.hash[i] = detail::iv[i];
        }
        // Parameter block modification for BLAKE2X:
        // P[0] = 0x40 (64 byte inner hash) | key_len << 8 | 0x01 << 16 (fanout) | 0x01 << 24 (depth)
        // P[1] = leaf_length (0) | xof_length in bytes 4-7
        ctx->inner.hash[0] ^= 0x01010040;                                // 64 byte digest, no key, fanout=1, depth=1
        ctx->inner.hash[1] ^= (static_cast<uint64_t>(xof_length) << 32); // xof_length in upper 32 bits

        ctx->inner.input_offset[0] = 0;
        ctx->inner.input_offset[1] = 0;
        ctx->inner.hash_size = 64;
        ctx->inner.input_idx = 0;
        std::memset(ctx->inner.input, 0, sizeof(ctx->inner.input));

        ctx->xof_length = xof_length;
        ctx->node_offset = 0;
        ctx->produced = 0;
        ctx->finalized = false;
    }

    inline void update(Context *ctx, const uint8_t *message, size_t message_size) {
        blake2b::update(&ctx->inner, message, message_size);
    }

    // Squeeze output bytes
    inline void squeeze(Context *ctx, uint8_t *output, size_t output_size) {
        if (!ctx->finalized) {
            // Finalize inner hash to get root hash
            blake2b::final(&ctx->inner, ctx->root_hash);
            ctx->finalized = true;
            ctx->node_offset = 0;
        }

        size_t produced = 0;
        while (produced < output_size) {
            // How many bytes from current block
            size_t block_pos = ctx->produced % 64;
            size_t available = 64 - block_pos;
            size_t to_produce = output_size - produced;
            if (to_produce > available) {
                to_produce = available;
            }

            if (block_pos == 0) {
                // Need to generate new output block
                // Use BLAKE2b to hash the root hash with node_offset
                uint8_t block[64];

                // Set up parameters for output block
                // digest_length = min(64, remaining)
                size_t remaining = (ctx->xof_length == 0xFFFFFFFF)
                                       ? 64
                                       : ((ctx->xof_length > ctx->produced) ? (ctx->xof_length - ctx->produced) : 0);
                if (remaining > 64)
                    remaining = 64;

                // Initialize a new BLAKE2b context for this output block
                blake2b::Context out_ctx;
                for (int i = 0; i < 8; ++i) {
                    out_ctx.hash[i] = detail::iv[i];
                }
                // P[0] = digest_length | 0x00 << 8 (key_len) | 0x00 << 16 (fanout) | 0x00 << 24 (depth)
                out_ctx.hash[0] ^= remaining;
                out_ctx.hash[0] ^= 0x00004000ULL; // inner_length = 64
                // P[1] = node_offset
                out_ctx.hash[1] ^= ctx->node_offset;
                out_ctx.hash[1] ^= (static_cast<uint64_t>(ctx->xof_length) << 32);
                // P[2] = node_depth (1) | inner_length (64)
                out_ctx.hash[2] ^= 0x00000040ULL;

                out_ctx.input_offset[0] = 0;
                out_ctx.input_offset[1] = 0;
                out_ctx.hash_size = remaining;
                out_ctx.input_idx = 0;
                std::memset(out_ctx.input, 0, sizeof(out_ctx.input));

                blake2b::update(&out_ctx, ctx->root_hash, 64);
                blake2b::final(&out_ctx, block);

                // Copy to output
                std::memcpy(output + produced, block, to_produce);
                ctx->node_offset++;
            } else {
                // Continue from partially used block - regenerate
                uint8_t block[64];
                size_t remaining = (ctx->xof_length == 0xFFFFFFFF)
                                       ? 64
                                       : ((ctx->xof_length > (ctx->produced - block_pos))
                                              ? (ctx->xof_length - (ctx->produced - block_pos))
                                              : 0);
                if (remaining > 64)
                    remaining = 64;

                blake2b::Context out_ctx;
                for (int i = 0; i < 8; ++i) {
                    out_ctx.hash[i] = detail::iv[i];
                }
                out_ctx.hash[0] ^= remaining;
                out_ctx.hash[0] ^= 0x00004000ULL;
                out_ctx.hash[1] ^= (ctx->node_offset - 1);
                out_ctx.hash[1] ^= (static_cast<uint64_t>(ctx->xof_length) << 32);
                out_ctx.hash[2] ^= 0x00000040ULL;

                out_ctx.input_offset[0] = 0;
                out_ctx.input_offset[1] = 0;
                out_ctx.hash_size = remaining;
                out_ctx.input_idx = 0;
                std::memset(out_ctx.input, 0, sizeof(out_ctx.input));

                blake2b::update(&out_ctx, ctx->root_hash, 64);
                blake2b::final(&out_ctx, block);

                std::memcpy(output + produced, block + block_pos, to_produce);
            }

            ctx->produced += to_produce;
            produced += to_produce;
        }
    }

    inline void final(Context *ctx) { crypto::constant_time::wipe(ctx, sizeof(*ctx)); }

    // One-shot XOF
    inline void xof(uint8_t *output, size_t output_size, const uint8_t *message, size_t message_size) {
        Context ctx;
        init(&ctx, static_cast<uint32_t>(output_size > 0xFFFFFFFF ? 0xFFFFFFFF : output_size));
        update(&ctx, message, message_size);
        squeeze(&ctx, output, output_size);
        final(&ctx);
    }

} // namespace keylock::hash::blake2xb

namespace keylock::hash::blake2xs {

    inline constexpr size_t BYTES_MAX = 0xFFFFULL; // 2^16 - 1 (limited by parameter block)

    namespace detail {

        inline constexpr uint32_t iv[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                                           0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};

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

    } // namespace detail

    struct Context {
        blake2s::Context inner;
        uint8_t root_hash[32];
        uint16_t xof_length;  // Desired output length (0xFFFF for unlimited)
        uint32_t node_offset; // Current output block
        size_t produced;      // Bytes produced so far
        bool finalized;       // Whether inner hash is finalized
    };

    inline void init(Context *ctx, uint16_t xof_length = 0xFFFF) {
        // Initialize inner BLAKE2s with XOF parameters
        std::memset(&ctx->inner, 0, sizeof(ctx->inner));
        for (int i = 0; i < 8; ++i) {
            ctx->inner.hash[i] = detail::iv[i];
        }
        // Parameter block modification for BLAKE2X:
        // P[0] = 0x20 (32 byte inner hash) | key_len << 8 | fanout << 16 | depth << 24
        ctx->inner.hash[0] ^= 0x01010020; // 32 byte digest, no key, fanout=1, depth=1
        // P[3] contains xof_length in upper 16 bits for BLAKE2xs
        ctx->inner.hash[3] ^= (static_cast<uint32_t>(xof_length) << 16);

        ctx->inner.t = 0;
        ctx->inner.buffer_len = 0;
        ctx->inner.hash_size = 32;

        ctx->xof_length = xof_length;
        ctx->node_offset = 0;
        ctx->produced = 0;
        ctx->finalized = false;
    }

    inline void update(Context *ctx, const uint8_t *message, size_t message_size) {
        blake2s::update(&ctx->inner, message, message_size);
    }

    // Squeeze output bytes
    inline void squeeze(Context *ctx, uint8_t *output, size_t output_size) {
        if (!ctx->finalized) {
            // Finalize inner hash to get root hash
            blake2s::final(&ctx->inner, ctx->root_hash);
            ctx->finalized = true;
            ctx->node_offset = 0;
        }

        size_t produced = 0;
        while (produced < output_size) {
            // How many bytes from current block
            size_t block_pos = ctx->produced % 32;
            size_t available = 32 - block_pos;
            size_t to_produce = output_size - produced;
            if (to_produce > available) {
                to_produce = available;
            }

            if (block_pos == 0) {
                // Need to generate new output block
                uint8_t block[32];

                size_t remaining = (ctx->xof_length == 0xFFFF)
                                       ? 32
                                       : ((ctx->xof_length > ctx->produced) ? (ctx->xof_length - ctx->produced) : 0);
                if (remaining > 32)
                    remaining = 32;

                // Initialize a new BLAKE2s context for this output block
                blake2s::Context out_ctx;
                for (int i = 0; i < 8; ++i) {
                    out_ctx.hash[i] = detail::iv[i];
                }
                out_ctx.hash[0] ^= remaining;
                out_ctx.hash[1] ^= 0x00000020; // inner_length = 32
                out_ctx.hash[2] ^= ctx->node_offset;
                out_ctx.hash[3] ^= 0x20000000; // depth = 1, inner = 32
                out_ctx.hash[3] ^= static_cast<uint16_t>(ctx->xof_length);

                out_ctx.t = 0;
                out_ctx.buffer_len = 0;
                out_ctx.hash_size = remaining;

                blake2s::update(&out_ctx, ctx->root_hash, 32);
                blake2s::final(&out_ctx, block);

                std::memcpy(output + produced, block, to_produce);
                ctx->node_offset++;
            } else {
                // Continue from partially used block - regenerate
                uint8_t block[32];
                size_t remaining = (ctx->xof_length == 0xFFFF) ? 32
                                                               : ((ctx->xof_length > (ctx->produced - block_pos))
                                                                      ? (ctx->xof_length - (ctx->produced - block_pos))
                                                                      : 0);
                if (remaining > 32)
                    remaining = 32;

                blake2s::Context out_ctx;
                for (int i = 0; i < 8; ++i) {
                    out_ctx.hash[i] = detail::iv[i];
                }
                out_ctx.hash[0] ^= remaining;
                out_ctx.hash[1] ^= 0x00000020;
                out_ctx.hash[2] ^= (ctx->node_offset - 1);
                out_ctx.hash[3] ^= 0x20000000;
                out_ctx.hash[3] ^= static_cast<uint16_t>(ctx->xof_length);

                out_ctx.t = 0;
                out_ctx.buffer_len = 0;
                out_ctx.hash_size = remaining;

                blake2s::update(&out_ctx, ctx->root_hash, 32);
                blake2s::final(&out_ctx, block);

                std::memcpy(output + produced, block + block_pos, to_produce);
            }

            ctx->produced += to_produce;
            produced += to_produce;
        }
    }

    inline void final(Context *ctx) { crypto::constant_time::wipe(ctx, sizeof(*ctx)); }

    // One-shot XOF
    inline void xof(uint8_t *output, size_t output_size, const uint8_t *message, size_t message_size) {
        Context ctx;
        init(&ctx, static_cast<uint16_t>(output_size > 0xFFFF ? 0xFFFF : output_size));
        update(&ctx, message, message_size);
        squeeze(&ctx, output, output_size);
        final(&ctx);
    }

} // namespace keylock::hash::blake2xs
