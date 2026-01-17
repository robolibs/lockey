#include "keylock/hash/sha3/sha3.hpp"
#include <doctest/doctest.h>

#include <cstring>
#include <vector>

// Helper to convert hex string to bytes
static std::vector<uint8_t> hex_to_bytes(const char *hex) {
    std::vector<uint8_t> bytes;
    while (*hex) {
        if (hex[1] == '\0')
            break;
        uint8_t byte = 0;
        for (int i = 0; i < 2; ++i) {
            byte <<= 4;
            char c = hex[i];
            if (c >= '0' && c <= '9')
                byte |= c - '0';
            else if (c >= 'a' && c <= 'f')
                byte |= c - 'a' + 10;
            else if (c >= 'A' && c <= 'F')
                byte |= c - 'A' + 10;
        }
        bytes.push_back(byte);
        hex += 2;
    }
    return bytes;
}

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

TEST_SUITE("SHA3 Hash Functions") {
    // Test vectors from NIST CAVP

    TEST_CASE("SHA3-224 empty string") {
        uint8_t hash[28];
        keylock::hash::sha3::hash_224(hash, nullptr, 0);
        std::string result = bytes_to_hex(hash, 28);
        // NIST test vector for SHA3-224("")
        CHECK(result == "6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7");
    }

    TEST_CASE("SHA3-256 empty string") {
        uint8_t hash[32];
        keylock::hash::sha3::hash_256(hash, nullptr, 0);
        std::string result = bytes_to_hex(hash, 32);
        // NIST test vector for SHA3-256("")
        CHECK(result == "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a");
    }

    TEST_CASE("SHA3-384 empty string") {
        uint8_t hash[48];
        keylock::hash::sha3::hash_384(hash, nullptr, 0);
        std::string result = bytes_to_hex(hash, 48);
        // NIST test vector for SHA3-384("")
        CHECK(result == "0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004");
    }

    TEST_CASE("SHA3-512 empty string") {
        uint8_t hash[64];
        keylock::hash::sha3::hash_512(hash, nullptr, 0);
        std::string result = bytes_to_hex(hash, 64);
        // NIST test vector for SHA3-512("")
        CHECK(result == "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26");
    }

    TEST_CASE("SHA3-256 'abc'") {
        const uint8_t msg[] = {'a', 'b', 'c'};
        uint8_t hash[32];
        keylock::hash::sha3::hash_256(hash, msg, 3);
        std::string result = bytes_to_hex(hash, 32);
        // NIST test vector for SHA3-256("abc")
        CHECK(result == "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532");
    }

    TEST_CASE("SHA3-512 'abc'") {
        const uint8_t msg[] = {'a', 'b', 'c'};
        uint8_t hash[64];
        keylock::hash::sha3::hash_512(hash, msg, 3);
        std::string result = bytes_to_hex(hash, 64);
        // NIST test vector for SHA3-512("abc")
        CHECK(result == "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0");
    }

    TEST_CASE("SHA3-256 incremental update") {
        keylock::hash::sha3::Context ctx;
        keylock::hash::sha3::init_256(&ctx);

        const uint8_t part1[] = {'a', 'b'};
        const uint8_t part2[] = {'c'};
        keylock::hash::sha3::update(&ctx, part1, 2);
        keylock::hash::sha3::update(&ctx, part2, 1);

        uint8_t hash[32];
        keylock::hash::sha3::final(&ctx, hash);
        std::string result = bytes_to_hex(hash, 32);
        // Should match SHA3-256("abc")
        CHECK(result == "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532");
    }

    TEST_CASE("SHA3-256 longer message") {
        // "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
        const uint8_t msg[] = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
        uint8_t hash[32];
        keylock::hash::sha3::hash_256(hash, msg, 56);
        std::string result = bytes_to_hex(hash, 32);
        CHECK(result == "41c0dba2a9d6240849100376a8235e2c82e1b9998a999e21db32dd97496d3376");
    }

    TEST_CASE("SHA3-224 longer message") {
        const uint8_t msg[] = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
        uint8_t hash[28];
        keylock::hash::sha3::hash_224(hash, msg, 56);
        std::string result = bytes_to_hex(hash, 28);
        CHECK(result == "8a24108b154ada21c9fd5574494479ba5c7e7ab76ef264ead0fcce33");
    }

    TEST_CASE("SHA3 consistency check") {
        const uint8_t data[] = "The quick brown fox jumps over the lazy dog";

        uint8_t hash1[32], hash2[32];
        keylock::hash::sha3::hash_256(hash1, data, sizeof(data) - 1);
        keylock::hash::sha3::hash_256(hash2, data, sizeof(data) - 1);

        CHECK(std::memcmp(hash1, hash2, 32) == 0);
    }

    TEST_CASE("SHA3 different outputs for different sizes") {
        const uint8_t data[] = "test";

        uint8_t hash224[28], hash256[32], hash384[48], hash512[64];
        keylock::hash::sha3::hash_224(hash224, data, 4);
        keylock::hash::sha3::hash_256(hash256, data, 4);
        keylock::hash::sha3::hash_384(hash384, data, 4);
        keylock::hash::sha3::hash_512(hash512, data, 4);

        // First bytes should differ
        CHECK(hash224[0] != hash256[0]);
        CHECK(hash256[0] != hash384[0]);
        CHECK(hash384[0] != hash512[0]);
    }
}
