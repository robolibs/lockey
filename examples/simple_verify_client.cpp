/**
 * Simple Verification Client Example
 *
 * This example demonstrates how to use the lockey::verify::Client to check
 * certificate revocation status against a verification server.
 *
 * Build with: cmake -DLOCKEY_HAS_VERIFY=ON -DLOCKEY_BUILD_EXAMPLES=ON
 * Run: ./simple_verify_client [server:port]
 */

#include <iostream>
#include <lockey/lockey.hpp>

#ifdef LOCKEY_HAS_VERIFY
#include <lockey/cert/builder.hpp>
#include <lockey/verify/client.hpp>

int main(int argc, char *argv[]) {
    std::cout << "Lockey Simple Verification Client\n";
    std::cout << "==================================\n\n";

    // Parse command line arguments
    std::string server_addr = (argc >= 2) ? argv[1] : "localhost:50051";

    std::cout << "Server address: " << server_addr << "\n\n";

    // Create a test certificate to verify
    std::cout << "Creating test certificate...\n";
    lockey::crypto::Lockey lockey(lockey::crypto::Lockey::Algorithm::Ed25519);
    auto keys = lockey.generate_keypair();

    auto dn_result = lockey::cert::DistinguishedName::from_string("CN=Test User,O=Example Organization,C=US");
    if (!dn_result.success) {
        std::cerr << "Failed to create DN: " << dn_result.error << "\n";
        return 1;
    }

    auto not_before = std::chrono::system_clock::now();
    auto not_after = not_before + std::chrono::hours(24 * 365); // 1 year

    lockey::cert::CertificateBuilder builder;
    builder
        .set_version(3)    // v3 required for extensions
        .set_serial(12345) // Use a serial that's not in the revocation list
        .set_subject(dn_result.value)
        .set_issuer(dn_result.value)
        .set_validity(not_before, not_after)
        .set_subject_public_key_ed25519(keys.public_key)
        .set_basic_constraints(false, std::nullopt, true);

    auto cert_result = builder.build_ed25519(keys, true);
    if (!cert_result.success) {
        std::cerr << "Failed to create certificate: " << cert_result.error << "\n";
        return 1;
    }

    auto test_cert = cert_result.value;
    std::cout << "Certificate created successfully\n";
    std::cout << "Subject: " << test_cert.tbs().subject.to_string() << "\n";
    std::cout << "Serial: 12345\n\n";

    // Configure client
    std::cout << "Connecting to verification server...\n";
    lockey::verify::ClientConfig config;
    config.timeout = std::chrono::seconds(10);
    config.max_retry_attempts = 3;
    config.enable_compression = true;

    lockey::verify::Client client(server_addr, config);

    // Health check
    std::cout << "Performing health check...\n";
    auto health = client.health_check();
    if (!health.success) {
        std::cerr << "Health check failed: " << health.error << "\n";
        std::cerr << "Make sure the verification server is running at " << server_addr << "\n";
        return 1;
    }

    if (!health.value) {
        std::cerr << "Server is not healthy\n";
        return 1;
    }
    std::cout << "Server is healthy ✓\n\n";

    // Verify certificate
    std::cout << "Verifying certificate...\n";
    std::vector<lockey::cert::Certificate> chain = {test_cert};
    auto result = client.verify_chain(chain);

    if (!result.success) {
        std::cerr << "Verification request failed: " << result.error << "\n";
        return 1;
    }

    const auto &response = result.value;

    std::cout << "\n=== Verification Result ===\n";

    switch (response.status) {
    case lockey::verify::wire::VerifyStatus::GOOD:
        std::cout << "Status: GOOD ✓\n";
        std::cout << "The certificate is valid and not revoked\n";
        break;

    case lockey::verify::wire::VerifyStatus::REVOKED:
        std::cout << "Status: REVOKED ✗\n";
        std::cout << "Reason: " << response.reason << "\n";
        if (response.revocation_time != std::chrono::system_clock::time_point{}) {
            auto rev_time = std::chrono::system_clock::to_time_t(response.revocation_time);
            std::cout << "Revoked at: " << std::ctime(&rev_time);
        }
        break;

    case lockey::verify::wire::VerifyStatus::UNKNOWN:
        std::cout << "Status: UNKNOWN ?\n";
        std::cout << "The server doesn't have information about this certificate\n";
        if (!response.reason.empty()) {
            std::cout << "Reason: " << response.reason << "\n";
        }
        break;
    }

    std::cout << "\n=== Response Details ===\n";
    if (response.this_update != std::chrono::system_clock::time_point{}) {
        auto this_update = std::chrono::system_clock::to_time_t(response.this_update);
        std::cout << "This update: " << std::ctime(&this_update);
    }
    if (response.next_update != std::chrono::system_clock::time_point{}) {
        auto next_update = std::chrono::system_clock::to_time_t(response.next_update);
        std::cout << "Next update: " << std::ctime(&next_update);
    }
    std::cout << "Signature: " << (response.signature.size() == 64 ? "Present (Ed25519)" : "Not present") << "\n";
    std::cout << "Nonce: " << (response.nonce.size() == 32 ? "Valid (32 bytes)" : "Invalid") << "\n";

    // Test with a revoked certificate
    std::cout << "\n\n=== Testing with Revoked Certificate ===\n";
    std::cout << "Creating certificate with serial number in revocation list...\n";

    lockey::cert::CertificateBuilder revoked_builder;
    revoked_builder
        .set_version(3)                             // v3 required for extensions
        .set_serial({0x01, 0x02, 0x03, 0x04, 0x05}) // This serial is revoked
        .set_subject(dn_result.value)
        .set_issuer(dn_result.value)
        .set_validity(not_before, not_after)
        .set_subject_public_key_ed25519(keys.public_key)
        .set_basic_constraints(false, std::nullopt, true);

    auto revoked_cert_result = revoked_builder.build_ed25519(keys, true);
    if (!revoked_cert_result.success) {
        std::cerr << "Failed to create revoked certificate: " << revoked_cert_result.error << "\n";
        return 1;
    }

    std::cout << "Verifying revoked certificate...\n";
    std::vector<lockey::cert::Certificate> revoked_chain = {revoked_cert_result.value};
    auto revoked_result = client.verify_chain(revoked_chain);

    if (!revoked_result.success) {
        std::cerr << "Verification request failed: " << revoked_result.error << "\n";
        return 1;
    }

    const auto &revoked_response = revoked_result.value;

    std::cout << "\n=== Verification Result ===\n";

    switch (revoked_response.status) {
    case lockey::verify::wire::VerifyStatus::GOOD:
        std::cout << "Status: GOOD (unexpected!)\n";
        break;

    case lockey::verify::wire::VerifyStatus::REVOKED:
        std::cout << "Status: REVOKED ✓ (as expected)\n";
        std::cout << "Reason: " << revoked_response.reason << "\n";
        if (revoked_response.revocation_time != std::chrono::system_clock::time_point{}) {
            auto rev_time = std::chrono::system_clock::to_time_t(revoked_response.revocation_time);
            std::cout << "Revoked at: " << std::ctime(&rev_time);
        }
        break;

    case lockey::verify::wire::VerifyStatus::UNKNOWN:
        std::cout << "Status: UNKNOWN\n";
        break;
    }

    std::cout << "\n✓ Client demo completed successfully!\n";
    return 0;
}

#else

int main() {
    std::cerr << "This example requires LOCKEY_HAS_VERIFY to be enabled\n";
    std::cerr << "Please rebuild with: cmake -DLOCKEY_HAS_VERIFY=ON -DLOCKEY_BUILD_EXAMPLES=ON\n";
    return 1;
}

#endif // LOCKEY_HAS_VERIFY
