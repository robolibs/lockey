#include <doctest/doctest.h>

#include "cert_test_helpers.hpp"

#include <lockey/cert/trust_store.hpp>

TEST_SUITE("cert/trust_store") {
    TEST_CASE("add and remove anchors") {
        using namespace lockey::cert;
        lockey::crypto::Lockey::KeyPair key;
        auto cert = cert_test::make_self_signed_certificate("Anchor", key);

        TrustStore store;
        CHECK(store.add(cert));
        CHECK(store.anchors().size() == 1);
        CHECK(store.remove_by_subject(cert.tbs().subject));
        CHECK(store.anchors().empty());
    }
}
