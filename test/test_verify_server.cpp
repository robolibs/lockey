/**
 * Test: Verification Server
 * Tests the netpipe verification server implementation
 */

#include <doctest/doctest.h>

#include <chrono>
#include <keylock/cert/builder.hpp>
#include <keylock/crypto/context.hpp>
#include <keylock/verify/client.hpp>
#include <keylock/verify/server.hpp>
#include <thread>

using namespace keylock;

TEST_CASE("SimpleRevocationHandler - Basic Operations") {
    verify::SimpleRevocationHandler handler;

    SUBCASE("Initially empty") {
        std::vector<uint8_t> serial = {0x01, 0x02, 0x03};
        CHECK_FALSE(handler.is_revoked(serial));
    }

    SUBCASE("Add and check revoked certificate") {
        std::vector<uint8_t> serial = {0x01, 0x02, 0x03};
        handler.add_revoked_certificate(serial, "Key compromise");

        CHECK(handler.is_revoked(serial));

        // Different serial should not be revoked
        std::vector<uint8_t> other_serial = {0x04, 0x05, 0x06};
        CHECK_FALSE(handler.is_revoked(other_serial));
    }

    SUBCASE("Remove revoked certificate") {
        std::vector<uint8_t> serial = {0x01, 0x02, 0x03};
        handler.add_revoked_certificate(serial);
        CHECK(handler.is_revoked(serial));

        handler.remove_revoked_certificate(serial);
        CHECK_FALSE(handler.is_revoked(serial));
    }

    SUBCASE("Clear all revocations") {
        handler.add_revoked_certificate({0x01, 0x02}, "reason1");
        handler.add_revoked_certificate({0x03, 0x04}, "reason2");

        handler.clear();

        CHECK_FALSE(handler.is_revoked({0x01, 0x02}));
        CHECK_FALSE(handler.is_revoked({0x03, 0x04}));
    }
}

TEST_CASE("SimpleRevocationHandler - Verify Chain") {
    verify::SimpleRevocationHandler handler;

    // Generate a test certificate
    crypto::Context ctx(crypto::Context::Algorithm::Ed25519);
    auto ca_keys = ctx.generate_keypair();

    auto dn_result = cert::DistinguishedName::from_string("CN=Test CA,O=keylock Test");
    REQUIRE(dn_result.success);

    auto not_before = std::chrono::system_clock::now();
    auto not_after = not_before + std::chrono::hours(24 * 365);

    cert::CertificateBuilder ca_builder;
    ca_builder.set_version(3)
        .set_serial(1)
        .set_subject(dn_result.value)
        .set_issuer(dn_result.value)
        .set_validity(not_before, not_after)
        .set_subject_public_key_ed25519(ca_keys.public_key)
        .set_basic_constraints(true, std::nullopt, true);

    auto ca_cert_result = ca_builder.build_ed25519(ca_keys, true);
    REQUIRE(ca_cert_result.success);
    auto ca_cert = ca_cert_result.value;

    SUBCASE("Good certificate") {
        std::vector<cert::Certificate> chain = {ca_cert};
        auto response = handler.verify_chain(chain, std::chrono::system_clock::now());

        CHECK(response.status == verify::wire::VerifyStatus::GOOD);
        CHECK(response.reason == "Certificate is valid");
    }

    SUBCASE("Revoked certificate") {
        // Add certificate to revocation list
        handler.add_revoked_certificate(ca_cert.tbs().serial_number, "Test revocation");

        std::vector<cert::Certificate> chain = {ca_cert};
        auto response = handler.verify_chain(chain, std::chrono::system_clock::now());

        CHECK(response.status == verify::wire::VerifyStatus::REVOKED);
        CHECK(response.reason == "Test revocation");
    }

    SUBCASE("Empty chain") {
        std::vector<cert::Certificate> empty_chain;
        auto response = handler.verify_chain(empty_chain, std::chrono::system_clock::now());

        CHECK(response.status == verify::wire::VerifyStatus::UNKNOWN);
        CHECK(response.reason == "Empty certificate chain");
    }
}

TEST_CASE("Server - Construction and Configuration") {
    auto handler = std::make_shared<verify::SimpleRevocationHandler>();

    SUBCASE("Default configuration") {
        verify::ServerConfig config;
        config.host = "127.0.0.1";
        config.port = 50052; // Use different port for testing

        verify::Server server(handler, config);
        CHECK(server.address() == "127.0.0.1:50052");
        CHECK_FALSE(server.is_running());
    }

    SUBCASE("Set signing key") {
        verify::ServerConfig config;
        config.host = "127.0.0.1";
        config.port = 50053;

        verify::Server server(handler, config);

        // Generate Ed25519 key
        std::vector<uint8_t> pk(crypto_sign_PUBLICKEYBYTES);
        std::vector<uint8_t> sk(crypto_sign_SECRETKEYBYTES);
        crypto_sign_keypair(pk.data(), sk.data());

        CHECK_NOTHROW(server.set_signing_key(sk));

        // Invalid key size should throw
        std::vector<uint8_t> bad_key(32);
        CHECK_THROWS(server.set_signing_key(bad_key));
    }

    SUBCASE("Set responder certificate") {
        verify::ServerConfig config;
        config.host = "127.0.0.1";
        config.port = 50054;

        verify::Server server(handler, config);

        // Generate a test certificate
        crypto::Context ctx(crypto::Context::Algorithm::Ed25519);
        auto keys = ctx.generate_keypair();

        auto dn_result = cert::DistinguishedName::from_string("CN=Responder");
        REQUIRE(dn_result.success);

        auto not_before = std::chrono::system_clock::now();
        auto not_after = not_before + std::chrono::hours(24 * 365);

        cert::CertificateBuilder builder;
        builder.set_version(3)
            .set_serial(1)
            .set_subject(dn_result.value)
            .set_issuer(dn_result.value)
            .set_validity(not_before, not_after)
            .set_subject_public_key_ed25519(keys.public_key)
            .set_basic_constraints(true, std::nullopt, true);

        auto cert_result = builder.build_ed25519(keys, true);
        REQUIRE(cert_result.success);

        CHECK_NOTHROW(server.set_responder_certificate(cert_result.value));
    }
}

TEST_CASE("Server - Statistics") {
    auto handler = std::make_shared<verify::SimpleRevocationHandler>();
    verify::ServerConfig config;
    config.host = "127.0.0.1";
    config.port = 50055;

    verify::Server server(handler, config);

    auto stats = server.get_stats();
    CHECK(stats.total_requests == 0);
    CHECK(stats.total_batch_requests == 0);
    CHECK(stats.total_health_checks == 0);
    CHECK(stats.good_responses == 0);
    CHECK(stats.revoked_responses == 0);
    CHECK(stats.unknown_responses == 0);
}

// Integration test - Start server, connect client, verify certificate
TEST_CASE("Server-Client Integration") {
    // NOTE: This test actually starts a server, which may fail in CI/CD environments
    // without proper network setup. Consider marking as integration test.

    auto handler = std::make_shared<verify::SimpleRevocationHandler>();
    verify::ServerConfig server_config;
    server_config.host = "127.0.0.1";
    server_config.port = 50056;

    verify::Server server(handler, server_config);

    // Generate a test certificate
    crypto::Context ctx(crypto::Context::Algorithm::Ed25519);
    auto keys = ctx.generate_keypair();

    auto dn_result = cert::DistinguishedName::from_string("CN=Test Cert");
    REQUIRE(dn_result.success);

    auto not_before = std::chrono::system_clock::now();
    auto not_after = not_before + std::chrono::hours(24 * 365);

    cert::CertificateBuilder builder;
    builder.set_version(3)
        .set_serial(1)
        .set_subject(dn_result.value)
        .set_issuer(dn_result.value)
        .set_validity(not_before, not_after)
        .set_subject_public_key_ed25519(keys.public_key)
        .set_basic_constraints(true, std::nullopt, true);

    auto cert_result = builder.build_ed25519(keys, true);
    REQUIRE(cert_result.success);
    auto test_cert = cert_result.value;

    // Start server in background
    server.start_async();

    // Give server time to start
    std::this_thread::sleep_for(std::chrono::milliseconds(500));

    CHECK(server.is_running());

    // TODO: Create client and test verification
    // This requires proper async server implementation with request handling

    // Cleanup
    server.stop();
    CHECK_FALSE(server.is_running());
}
