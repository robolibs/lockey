#include "keylock/hash/legacy/whirlpool.hpp"
#include <doctest/doctest.h>

#include <cstring>
#include <string>
#include <vector>

static std::string bytes_to_hex(const uint8_t *data, size_t len) {
    static const char hex_chars[] = "0123456789abcdef";
    std::string result;
    result.reserve(len * 2);
    for (size_t i = 0; i < len; ++i) {
        result += hex_chars[(data[i] >> 4) & 0xf];
        result += hex_chars[data[i] & 0xf];
    }
    return result;
}

TEST_SUITE("Whirlpool Hash Function") {
    // Test vectors from ISO/IEC 10118-3:2004

    TEST_CASE("Whirlpool empty string") {
        uint8_t hash[64];
        keylock::hash::whirlpool::hash(hash, nullptr, 0);
        std::string result = bytes_to_hex(hash, 64);
        // ISO test vector for Whirlpool("")
        CHECK(result == "19fa61d75522a4669b44e39c1d2e1726c530232130d407f89afee0964997f7a73e83be698b288febcf88e3e03c4f0757ea8964e59b63d93708b138cc42a66eb3");
    }

    TEST_CASE("Whirlpool 'a'") {
        const uint8_t msg[] = {'a'};
        uint8_t hash[64];
        keylock::hash::whirlpool::hash(hash, msg, 1);
        std::string result = bytes_to_hex(hash, 64);
        // ISO test vector for Whirlpool("a")
        CHECK(result == "8aca2602792aec6f11a67206531fb7d7f0dff59413145e6973c45001d0087b42d11bc645413aeff63a42391a39145a591a92200d560195e53b478584fdae231a");
    }

    TEST_CASE("Whirlpool 'abc'") {
        const uint8_t msg[] = {'a', 'b', 'c'};
        uint8_t hash[64];
        keylock::hash::whirlpool::hash(hash, msg, 3);
        std::string result = bytes_to_hex(hash, 64);
        // ISO test vector for Whirlpool("abc")
        CHECK(result == "4e2448a4c6f486bb16b6562c73b4020bf3043e3a731bce721ae1b303d97e6d4c7181eebdb6c57e277d0e34957114cbd6c797fc9d95d8b582d225292076d4eef5");
    }

    TEST_CASE("Whirlpool 'message digest'") {
        const uint8_t msg[] = "message digest";
        uint8_t hash[64];
        keylock::hash::whirlpool::hash(hash, msg, 14);
        std::string result = bytes_to_hex(hash, 64);
        // ISO test vector
        CHECK(result == "378c84a4126e2dc6e56dcc7458377aac838d00032230f53ce1f5700c0ffb4d3b8421557659ef55c106b4b52ac5a4aaa692ed920052838f3362e86dbd37a8903e");
    }

    TEST_CASE("Whirlpool 'abcdefghijklmnopqrstuvwxyz'") {
        const uint8_t msg[] = "abcdefghijklmnopqrstuvwxyz";
        uint8_t hash[64];
        keylock::hash::whirlpool::hash(hash, msg, 26);
        std::string result = bytes_to_hex(hash, 64);
        // ISO test vector
        CHECK(result == "f1d754662636ffe92c82ebb9212a484a8d38631ead4238f5442ee13b8054e41b08bf2a9251c30b6a0b8aae86177ab4a6f68f673e7207865d5d9819a3dba4eb3b");
    }

    TEST_CASE("Whirlpool incremental update") {
        keylock::hash::whirlpool::Context ctx;
        keylock::hash::whirlpool::init(&ctx);

        const uint8_t part1[] = {'a', 'b'};
        const uint8_t part2[] = {'c'};
        keylock::hash::whirlpool::update(&ctx, part1, 2);
        keylock::hash::whirlpool::update(&ctx, part2, 1);

        uint8_t hash[64];
        keylock::hash::whirlpool::final(&ctx, hash);

        // Compare with one-shot
        const uint8_t full_msg[] = {'a', 'b', 'c'};
        uint8_t expected[64];
        keylock::hash::whirlpool::hash(expected, full_msg, 3);

        CHECK(std::memcmp(hash, expected, 64) == 0);
    }

    TEST_CASE("Whirlpool consistency") {
        const uint8_t msg[] = "The quick brown fox jumps over the lazy dog";

        uint8_t hash1[64], hash2[64];
        keylock::hash::whirlpool::hash(hash1, msg, sizeof(msg) - 1);
        keylock::hash::whirlpool::hash(hash2, msg, sizeof(msg) - 1);

        CHECK(std::memcmp(hash1, hash2, 64) == 0);
    }

    TEST_CASE("Whirlpool longer message") {
        // Test with a message that spans multiple blocks
        std::vector<uint8_t> long_msg(1000, 0x41); // 1000 bytes of 'A'

        uint8_t hash[64];
        keylock::hash::whirlpool::hash(hash, long_msg.data(), long_msg.size());

        // Should produce valid non-zero output
        bool non_zero = false;
        for (int i = 0; i < 64; ++i) {
            if (hash[i] != 0) {
                non_zero = true;
                break;
            }
        }
        CHECK(non_zero);
    }

    TEST_CASE("Whirlpool different messages produce different hashes") {
        const uint8_t msg1[] = "message1";
        const uint8_t msg2[] = "message2";

        uint8_t hash1[64], hash2[64];
        keylock::hash::whirlpool::hash(hash1, msg1, 8);
        keylock::hash::whirlpool::hash(hash2, msg2, 8);

        CHECK(std::memcmp(hash1, hash2, 64) != 0);
    }
}
