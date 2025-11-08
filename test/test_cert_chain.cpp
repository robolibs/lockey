#include <doctest/doctest.h>

#include "cert_test_helpers.hpp"

#include <lockey/cert/trust_store.hpp>

TEST_SUITE("cert/chain") {
    TEST_CASE("chain validation with trust store") {
        using namespace lockey::cert;
        lockey::crypto::Lockey root_ctx(lockey::crypto::Lockey::Algorithm::Ed25519);
        auto root_key = root_ctx.generate_keypair();
        auto root_dn = cert_test::dn_from_string("CN=Root");
        auto root_cert = cert_test::make_certificate(root_dn, root_dn, root_key, root_key, true,
                                                     KeyUsageExtension::KeyCertSign);

        lockey::crypto::Lockey intermediate_ctx(lockey::crypto::Lockey::Algorithm::Ed25519);
        auto intermediate_key = intermediate_ctx.generate_keypair();
        auto intermediate_dn = cert_test::dn_from_string("CN=Intermediate");
        auto intermediate_cert =
            cert_test::make_certificate(root_dn, intermediate_dn, root_key, intermediate_key, true,
                                        KeyUsageExtension::KeyCertSign);

        lockey::crypto::Lockey leaf_ctx(lockey::crypto::Lockey::Algorithm::Ed25519);
        auto leaf_key = leaf_ctx.generate_keypair();
        auto leaf_dn = cert_test::dn_from_string("CN=leaf.example");
        auto leaf_cert = cert_test::make_certificate(intermediate_dn, leaf_dn, intermediate_key, leaf_key, false,
                                                     KeyUsageExtension::DigitalSignature);

        TrustStore store;
        store.add(root_cert);

        auto result = leaf_cert.validate_chain({intermediate_cert}, store);
        CHECK(result.success);
        CHECK(result.value);
        CHECK(leaf_cert.match_subject(leaf_dn));
    }
}
