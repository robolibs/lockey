#include "keylock/crypto/constant_time/verify.hpp"
#include "keylock/crypto/constant_time/wipe.hpp"
#include <doctest/doctest.h>

#include <cstring>
#include <vector>

TEST_SUITE("Constant-Time Operations") {

    TEST_CASE("verify16 equal values") {
        uint8_t a[16] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
        uint8_t b[16] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};

        int result = keylock::crypto::constant_time::verify16(a, b);
        CHECK(result == 0);
    }

    TEST_CASE("verify16 different values") {
        uint8_t a[16] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
        uint8_t b[16] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 16};

        int result = keylock::crypto::constant_time::verify16(a, b);
        CHECK(result == -1);
    }

    TEST_CASE("verify32 equal values") {
        uint8_t a[32], b[32];
        for (int i = 0; i < 32; ++i) {
            a[i] = static_cast<uint8_t>(i);
            b[i] = static_cast<uint8_t>(i);
        }

        int result = keylock::crypto::constant_time::verify32(a, b);
        CHECK(result == 0);
    }

    TEST_CASE("verify32 different values") {
        uint8_t a[32], b[32];
        for (int i = 0; i < 32; ++i) {
            a[i] = static_cast<uint8_t>(i);
            b[i] = static_cast<uint8_t>(i);
        }
        b[0] ^= 0x01;

        int result = keylock::crypto::constant_time::verify32(a, b);
        CHECK(result == -1);
    }

    TEST_CASE("verify64 equal values") {
        uint8_t a[64], b[64];
        for (int i = 0; i < 64; ++i) {
            a[i] = static_cast<uint8_t>(i);
            b[i] = static_cast<uint8_t>(i);
        }

        int result = keylock::crypto::constant_time::verify64(a, b);
        CHECK(result == 0);
    }

    TEST_CASE("verify64 different values") {
        uint8_t a[64], b[64];
        for (int i = 0; i < 64; ++i) {
            a[i] = static_cast<uint8_t>(i);
            b[i] = static_cast<uint8_t>(i);
        }
        b[63] ^= 0x01;

        int result = keylock::crypto::constant_time::verify64(a, b);
        CHECK(result == -1);
    }

    TEST_CASE("verify generic equal values") {
        std::vector<uint8_t> a = {1, 2, 3, 4, 5, 6, 7, 8};
        std::vector<uint8_t> b = {1, 2, 3, 4, 5, 6, 7, 8};

        int result = keylock::crypto::constant_time::verify(a.data(), b.data(), a.size());
        CHECK(result == 0);
    }

    TEST_CASE("verify generic different values") {
        std::vector<uint8_t> a = {1, 2, 3, 4, 5, 6, 7, 8};
        std::vector<uint8_t> b = {1, 2, 3, 4, 5, 6, 7, 9};

        int result = keylock::crypto::constant_time::verify(a.data(), b.data(), a.size());
        CHECK(result == -1);
    }

    TEST_CASE("secure_compare equal") {
        std::vector<uint8_t> a = {0xde, 0xad, 0xbe, 0xef};
        std::vector<uint8_t> b = {0xde, 0xad, 0xbe, 0xef};

        bool result = keylock::crypto::constant_time::secure_compare(a.data(), b.data(), a.size());
        CHECK(result == true);
    }

    TEST_CASE("secure_compare different") {
        std::vector<uint8_t> a = {0xde, 0xad, 0xbe, 0xef};
        std::vector<uint8_t> b = {0xde, 0xad, 0xbe, 0xee};

        bool result = keylock::crypto::constant_time::secure_compare(a.data(), b.data(), a.size());
        CHECK(result == false);
    }

    TEST_CASE("wipe zeros memory") {
        uint8_t buf[32];
        std::memset(buf, 0x42, sizeof(buf));

        keylock::crypto::constant_time::wipe(buf, sizeof(buf));

        // All bytes should be zero
        for (size_t i = 0; i < sizeof(buf); ++i) {
            CHECK(buf[i] == 0);
        }
    }

    TEST_CASE("wipe template function") {
        uint8_t buf[16];
        std::memset(buf, 0xff, sizeof(buf));

        keylock::crypto::constant_time::wipe(buf);

        for (size_t i = 0; i < sizeof(buf); ++i) {
            CHECK(buf[i] == 0);
        }
    }

    TEST_CASE("wipe_container") {
        std::vector<uint8_t> vec(100, 0xaa);

        keylock::crypto::constant_time::wipe_container(vec);

        for (size_t i = 0; i < vec.size(); ++i) {
            CHECK(vec[i] == 0);
        }
    }

    TEST_CASE("verify all zeros") {
        uint8_t a[32] = {0};
        uint8_t b[32] = {0};

        int result = keylock::crypto::constant_time::verify32(a, b);
        CHECK(result == 0);
    }

    TEST_CASE("verify difference in first byte") {
        uint8_t a[32] = {0};
        uint8_t b[32] = {0};
        a[0] = 1;

        int result = keylock::crypto::constant_time::verify32(a, b);
        CHECK(result == -1);
    }

    TEST_CASE("verify difference in last byte") {
        uint8_t a[32] = {0};
        uint8_t b[32] = {0};
        b[31] = 1;

        int result = keylock::crypto::constant_time::verify32(a, b);
        CHECK(result == -1);
    }
}
