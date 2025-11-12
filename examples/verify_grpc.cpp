/**
 * Example: Certificate revocation checking using gRPC verification service
 *
 * This example demonstrates how to use the Lockey Verification Protocol (LVP)
 * to check certificate revocation status via a gRPC server.
 *
 * Build with: cmake -DLOCKEY_HAS_VERIFY=ON -DLOCKEY_BUILD_EXAMPLES=ON
 */

#include <iostream>
#include <lockey/lockey.hpp>

#ifdef LOCKEY_HAS_VERIFY
#include <lockey/verify/client.hpp>

int main(int argc, char *argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <certificate.pem> [server:port]\n";
        std::cerr << "Example: " << argv[0] << " cert.pem verify.example.com:50051\n";
        return 1;
    }

    std::string cert_path = argv[1];
    std::string server_addr = (argc >= 3) ? argv[2] : "localhost:50051";

    std::cout << "Lockey Certificate Revocation Check Example\n";
    std::cout << "===========================================\n\n";

    // Load certificate
    std::cout << "Loading certificate from: " << cert_path << "\n";
    auto cert_result = lockey::cert::Certificate::load(cert_path);
    if (!cert_result.success || cert_result.value.empty()) {
        std::cerr << "Failed to load certificate: " << cert_result.error << "\n";
        return 1;
    }

    auto cert = cert_result.value[0];
    std::cout << "Certificate loaded successfully\n";
    std::cout << "Subject: " << cert.tbs().subject.to_string() << "\n\n";

    // Configure gRPC client
    std::cout << "Connecting to verification server: " << server_addr << "\n";
    lockey::verify::ClientConfig config;
    config.timeout = std::chrono::seconds(10);
    config.max_retry_attempts = 3;
    config.enable_compression = true;

    lockey::verify::Client client(server_addr, config);

    // Optional: Set responder certificate for signature verification
    // If you have the server's public certificate, load it and set it:
    // auto responder_cert_result = lockey::cert::Certificate::load("responder.pem");
    // if (responder_cert_result.success && !responder_cert_result.value.empty()) {
    //     client.set_responder_cert(responder_cert_result.value[0]);
    //     std::cout << "Responder certificate set for signature verification\n";
    // }

    // Check health first
    std::cout << "Checking server health...\n";
    auto health = client.health_check();
    if (!health.success || !health.value) {
        std::cerr << "Server health check failed: " << health.error << "\n";
        std::cerr << "Make sure the verification server is running\n";
        return 1;
    }
    std::cout << "Server is healthy\n\n";

    // Verify certificate revocation status
    std::cout << "Checking certificate revocation status...\n";
    std::vector<lockey::cert::Certificate> chain = {cert};
    auto result = client.verify_chain(chain);

    if (!result.success) {
        std::cerr << "Verification failed: " << result.error << "\n";
        return 1;
    }

    const auto &response = result.value;

    std::cout << "\nVerification Result:\n";
    std::cout << "-------------------\n";

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

    std::cout << "\nResponse Details:\n";
    auto this_update = std::chrono::system_clock::to_time_t(response.this_update);
    auto next_update = std::chrono::system_clock::to_time_t(response.next_update);
    std::cout << "This update: " << std::ctime(&this_update);
    std::cout << "Next update: " << std::ctime(&next_update);
    std::cout << "Signature: " << (response.signature.size() == 64 ? "Present (Ed25519)" : "Invalid") << "\n";
    std::cout << "Nonce: " << (response.nonce.size() == 32 ? "Valid" : "Invalid") << "\n";

    // Example: Check using the convenience method
    std::cout << "\n\nAlternative: Using Certificate::check_revocation()\n";
    std::cout << "================================================\n";
    auto check_result = cert.check_revocation(client);
    if (check_result.success) {
        std::cout << "Certificate is valid and not revoked ✓\n";
    } else {
        std::cout << "Certificate check failed: " << check_result.error << "\n";
    }

    return 0;
}

#else

int main() {
    std::cerr << "This example requires LOCKEY_HAS_VERIFY to be enabled\n";
    std::cerr << "Please rebuild with: cmake -DLOCKEY_HAS_VERIFY=ON -DLOCKEY_BUILD_EXAMPLES=ON\n";
    return 1;
}

#endif // LOCKEY_HAS_VERIFY
