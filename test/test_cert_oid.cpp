#include <doctest/doctest.h>

#include <keylock/cert/asn1_common.hpp>
#include <keylock/cert/oid_registry.hpp>

using namespace keylock::cert;

TEST_SUITE("cert/oid") {
    TEST_CASE("signature oid lookup") {
        Oid oid{{1, 3, 101, 112}};
        auto sig = find_sig_alg_by_oid(oid);
        CHECK(sig == SignatureAlgorithmId::Ed25519);
    }

    TEST_CASE("hash oid lookup") {
        Oid oid{{2, 16, 840, 1, 101, 3, 4, 2, 1}};
        auto hash = find_hash_by_oid(oid);
        CHECK(hash.has_value());
        CHECK(*hash == ::keylock::hash::Algorithm::SHA256);
    }
}
