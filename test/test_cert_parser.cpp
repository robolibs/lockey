#include <doctest/doctest.h>

#include "cert_test_helpers.hpp"

#include <lockey/cert/parser.hpp>
#include <lockey/cert/pem.hpp>

using namespace lockey::cert;

TEST_SUITE("cert/parser") {
    TEST_CASE("parse self-signed certificate") {
        lockey::crypto::Lockey::KeyPair root_key;
        auto cert = cert_test::make_self_signed_certificate("Root CA", root_key);
        auto der = cert.der();
        auto parse = parse_x509_cert(ByteSpan(der.data(), der.size()));
        REQUIRE(parse.success);
        CHECK(parse.certificate.subject.to_string().find("Root CA") != std::string::npos);
    }

    TEST_CASE("PEM encode/decode roundtrip") {
        lockey::crypto::Lockey::KeyPair root_key;
        auto cert = cert_test::make_self_signed_certificate("Root CA", root_key);
        auto pem = cert.to_pem();
        auto decoded = pem_decode(pem, "CERTIFICATE");
        REQUIRE(decoded.success);
        CHECK(decoded.block.data == cert.der());
    }
}
