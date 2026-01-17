#pragma once

// Argon2 key derivation function
// Adapted from Monocypher (public domain)
// Supports Argon2i, Argon2d, and Argon2id variants

#include <cstddef>
#include <cstdint>
#include <cstring>

#include "keylock/crypto/constant_time/wipe.hpp"
#include "keylock/hash/blake2b/blake2b.hpp"

namespace keylock::kdf::argon2 {

    enum class Algorithm : uint32_t { ARGON2D = 0, ARGON2I = 1, ARGON2ID = 2 };

    struct Config {
        Algorithm algorithm;
        uint32_t nb_blocks; // Memory usage: nb_blocks * 1024 bytes
        uint32_t nb_passes; // Time cost (iterations)
        uint32_t nb_lanes;  // Parallelism (usually 1 for single-threaded)
    };

    struct Inputs {
        const uint8_t *pass;
        uint32_t pass_size;
        const uint8_t *salt;
        uint32_t salt_size;
    };

    struct Extras {
        const uint8_t *key;
        uint32_t key_size;
        const uint8_t *ad;
        uint32_t ad_size;
    };

    inline constexpr Extras no_extras = {nullptr, 0, nullptr, 0};

    namespace detail {

        // Argon2 operates on 1024 byte blocks
        struct Block {
            uint64_t a[128];
        };

        inline uint64_t rotr64(uint64_t x, int n) { return (x >> n) | (x << (64 - n)); }

        inline void store32_le(uint8_t out[4], uint32_t in) {
            out[0] = static_cast<uint8_t>(in & 0xff);
            out[1] = static_cast<uint8_t>((in >> 8) & 0xff);
            out[2] = static_cast<uint8_t>((in >> 16) & 0xff);
            out[3] = static_cast<uint8_t>((in >> 24) & 0xff);
        }

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

        inline void load64_le_buf(uint64_t *dst, const uint8_t *src, size_t size) {
            for (size_t i = 0; i < size; ++i) {
                dst[i] = load64_le(src + i * 8);
            }
        }

        inline void store64_le_buf(uint8_t *dst, const uint64_t *src, size_t size) {
            for (size_t i = 0; i < size; ++i) {
                store64_le(dst + i * 8, src[i]);
            }
        }

        inline void blake_update_32(hash::blake2b::Context *ctx, uint32_t input) {
            uint8_t buf[4];
            store32_le(buf, input);
            hash::blake2b::update(ctx, buf, 4);
        }

        inline void blake_update_32_buf(hash::blake2b::Context *ctx, const uint8_t *buf, uint32_t size) {
            blake_update_32(ctx, size);
            if (buf && size > 0) {
                hash::blake2b::update(ctx, buf, size);
            }
        }

        inline void copy_block(Block *o, const Block *in) {
            for (int i = 0; i < 128; ++i)
                o->a[i] = in->a[i];
        }

        inline void xor_block(Block *o, const Block *in) {
            for (int i = 0; i < 128; ++i)
                o->a[i] ^= in->a[i];
        }

        // Extended hash for variable output size
        inline void extended_hash(uint8_t *digest, uint32_t digest_size, const uint8_t *input, uint32_t input_size) {
            hash::blake2b::Context ctx;
            size_t out_size = digest_size < 64 ? digest_size : 64;
            hash::blake2b::init(&ctx, out_size);
            blake_update_32(&ctx, digest_size);
            hash::blake2b::update(&ctx, input, input_size);
            hash::blake2b::final(&ctx, digest);

            if (digest_size > 64) {
                uint32_t r = ((digest_size + 31) >> 5) - 2;
                uint32_t i = 1;
                uint32_t in_pos = 0;
                uint32_t out_pos = 32;
                while (i < r) {
                    hash::blake2b::hash(digest + out_pos, 64, digest + in_pos, 64);
                    i++;
                    in_pos += 32;
                    out_pos += 32;
                }
                hash::blake2b::hash(digest + out_pos, digest_size - (32 * r), digest + in_pos, 64);
            }
        }

#define LSB(x) ((uint64_t)(uint32_t)(x))
#define G_ARGON(a, b, c, d)                                                                                            \
    a += b + ((LSB(a) * LSB(b)) << 1);                                                                                 \
    d ^= a;                                                                                                            \
    d = rotr64(d, 32);                                                                                                 \
    c += d + ((LSB(c) * LSB(d)) << 1);                                                                                 \
    b ^= c;                                                                                                            \
    b = rotr64(b, 24);                                                                                                 \
    a += b + ((LSB(a) * LSB(b)) << 1);                                                                                 \
    d ^= a;                                                                                                            \
    d = rotr64(d, 16);                                                                                                 \
    c += d + ((LSB(c) * LSB(d)) << 1);                                                                                 \
    b ^= c;                                                                                                            \
    b = rotr64(b, 63)

#define ROUND_ARGON(v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15)                              \
    G_ARGON(v0, v4, v8, v12);                                                                                          \
    G_ARGON(v1, v5, v9, v13);                                                                                          \
    G_ARGON(v2, v6, v10, v14);                                                                                         \
    G_ARGON(v3, v7, v11, v15);                                                                                         \
    G_ARGON(v0, v5, v10, v15);                                                                                         \
    G_ARGON(v1, v6, v11, v12);                                                                                         \
    G_ARGON(v2, v7, v8, v13);                                                                                          \
    G_ARGON(v3, v4, v9, v14)

        inline void g_rounds(Block *b) {
            // column rounds
            for (int i = 0; i < 128; i += 16) {
                ROUND_ARGON(b->a[i], b->a[i + 1], b->a[i + 2], b->a[i + 3], b->a[i + 4], b->a[i + 5], b->a[i + 6],
                            b->a[i + 7], b->a[i + 8], b->a[i + 9], b->a[i + 10], b->a[i + 11], b->a[i + 12],
                            b->a[i + 13], b->a[i + 14], b->a[i + 15]);
            }
            // row rounds
            for (int i = 0; i < 16; i += 2) {
                ROUND_ARGON(b->a[i], b->a[i + 1], b->a[i + 16], b->a[i + 17], b->a[i + 32], b->a[i + 33], b->a[i + 48],
                            b->a[i + 49], b->a[i + 64], b->a[i + 65], b->a[i + 80], b->a[i + 81], b->a[i + 96],
                            b->a[i + 97], b->a[i + 112], b->a[i + 113]);
            }
        }

#undef LSB
#undef G_ARGON
#undef ROUND_ARGON

    } // namespace detail

    inline void derive(uint8_t *hash, uint32_t hash_size, void *work_area, Config config, Inputs inputs,
                       Extras extras) {
        using namespace detail;

        const uint32_t segment_size = config.nb_blocks / config.nb_lanes / 4;
        const uint32_t lane_size = segment_size * 4;
        const uint32_t nb_blocks = lane_size * config.nb_lanes;

        Block *blocks = reinterpret_cast<Block *>(work_area);

        // Initial hash
        {
            uint8_t initial_hash[72];
            hash::blake2b::Context ctx;
            hash::blake2b::init(&ctx, 64);
            blake_update_32(&ctx, config.nb_lanes);
            blake_update_32(&ctx, hash_size);
            blake_update_32(&ctx, config.nb_blocks);
            blake_update_32(&ctx, config.nb_passes);
            blake_update_32(&ctx, 0x13); // version
            blake_update_32(&ctx, static_cast<uint32_t>(config.algorithm));
            blake_update_32_buf(&ctx, inputs.pass, inputs.pass_size);
            blake_update_32_buf(&ctx, inputs.salt, inputs.salt_size);
            blake_update_32_buf(&ctx, extras.key, extras.key_size);
            blake_update_32_buf(&ctx, extras.ad, extras.ad_size);
            hash::blake2b::final(&ctx, initial_hash);

            // Fill first 2 blocks of each lane
            uint8_t hash_area[1024];
            for (uint32_t l = 0; l < config.nb_lanes; ++l) {
                for (uint32_t i = 0; i < 2; ++i) {
                    store32_le(initial_hash + 64, i);
                    store32_le(initial_hash + 68, l);
                    extended_hash(hash_area, 1024, initial_hash, 72);
                    load64_le_buf(blocks[l * lane_size + i].a, hash_area, 128);
                }
            }

            crypto::constant_time::wipe(initial_hash, sizeof(initial_hash));
            crypto::constant_time::wipe(hash_area, sizeof(hash_area));
        }

        bool constant_time = config.algorithm != Algorithm::ARGON2D;

        Block tmp;
        for (uint32_t pass = 0; pass < config.nb_passes; ++pass) {
            for (uint32_t slice = 0; slice < 4; ++slice) {
                uint32_t pass_offset = (pass == 0 && slice == 0) ? 2 : 0;
                uint32_t slice_offset = slice * segment_size;

                if (slice == 2 && config.algorithm == Algorithm::ARGON2ID) {
                    constant_time = false;
                }

                for (uint32_t segment = 0; segment < config.nb_lanes; ++segment) {
                    Block index_block;
                    uint32_t index_ctr = 1;

                    for (uint32_t block = pass_offset; block < segment_size; ++block) {
                        uint32_t lane_offset = segment * lane_size;
                        Block *segment_start = blocks + lane_offset + slice_offset;
                        Block *current = segment_start + block;
                        Block *previous = (block == 0 && slice_offset == 0) ? segment_start + lane_size - 1
                                                                            : segment_start + block - 1;

                        uint64_t index_seed;
                        if (constant_time) {
                            if (block == pass_offset || (block % 128) == 0) {
                                std::memset(index_block.a, 0, sizeof(index_block.a));
                                index_block.a[0] = pass;
                                index_block.a[1] = segment;
                                index_block.a[2] = slice;
                                index_block.a[3] = nb_blocks;
                                index_block.a[4] = config.nb_passes;
                                index_block.a[5] = static_cast<uint64_t>(config.algorithm);
                                index_block.a[6] = index_ctr;
                                index_ctr++;

                                copy_block(&tmp, &index_block);
                                g_rounds(&index_block);
                                xor_block(&index_block, &tmp);
                                copy_block(&tmp, &index_block);
                                g_rounds(&index_block);
                                xor_block(&index_block, &tmp);
                            }
                            index_seed = index_block.a[block % 128];
                        } else {
                            index_seed = previous->a[0];
                        }

                        uint32_t next_slice = ((slice + 1) % 4) * segment_size;
                        uint32_t window_start = (pass == 0) ? 0 : next_slice;
                        uint32_t nb_segments = (pass == 0) ? slice : 3;
                        uint32_t lane = (pass == 0 && slice == 0) ? segment : (index_seed >> 32) % config.nb_lanes;
                        uint32_t window_size = nb_segments * segment_size + (lane == segment ? block - 1
                                                                             : block == 0    ? static_cast<uint32_t>(-1)
                                                                                             : 0);

                        uint64_t j1 = index_seed & 0xffffffff;
                        uint64_t x = (j1 * j1) >> 32;
                        uint64_t y = (window_size * x) >> 32;
                        uint64_t z = (window_size - 1) - y;
                        uint32_t ref = (window_start + z) % lane_size;
                        uint32_t index = lane * lane_size + ref;
                        Block *reference = blocks + index;

                        copy_block(&tmp, previous);
                        xor_block(&tmp, reference);
                        if (pass == 0) {
                            copy_block(current, &tmp);
                        } else {
                            xor_block(current, &tmp);
                        }
                        g_rounds(&tmp);
                        xor_block(current, &tmp);
                    }
                }
            }
        }

        // Wipe temporary block
        crypto::constant_time::wipe(&tmp, sizeof(tmp));

        // XOR last blocks of each lane
        Block *last_block = blocks + lane_size - 1;
        for (uint32_t lane = 1; lane < config.nb_lanes; ++lane) {
            Block *next_block = last_block + lane_size;
            xor_block(next_block, last_block);
            last_block = next_block;
        }

        // Serialize last block
        uint8_t final_block[1024];
        store64_le_buf(final_block, last_block->a, 128);

        // Wipe work area
        crypto::constant_time::wipe(work_area, sizeof(Block) * nb_blocks);

        // Hash into output
        extended_hash(hash, hash_size, final_block, 1024);
        crypto::constant_time::wipe(final_block, sizeof(final_block));
    }

    // Helper to calculate required work area size in bytes
    inline size_t work_area_size(uint32_t nb_blocks) { return nb_blocks * 1024; }

} // namespace keylock::kdf::argon2
