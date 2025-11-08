#include <doctest/doctest.h>

#include "cert_test_helpers.hpp"

#include <lockey/cert/key_utils.hpp>

TEST_SUITE("cert/keys") {
    TEST_CASE("public key DER and fingerprint") {
        using namespace lockey::cert;
        lockey::crypto::Lockey::KeyPair key;
        auto cert = cert_test::make_self_signed_certificate("Key Test", key);
        auto spki = cert.public_key_der();
        CHECK(!spki.empty());
        auto fingerprint = cert.fingerprint(lockey::hash::Algorithm::SHA256);
        CHECK(!fingerprint.empty());
    }
}
