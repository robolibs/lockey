/**
 * Simple Verification Server Example
 *
 * This example demonstrates how to create a simple netpipe verification server
 * using the lockey::verify::Server API. The server maintains an in-memory
 * revocation list and responds to certificate verification requests.
 *
 * Build with: cmake -DLOCKEY_BUILD_EXAMPLES=ON
 * Run: ./simple_verify_server [port]
 */

#include <csignal>
#include <iostream>
#include <lockey/cert/builder.hpp>
#include <lockey/lockey.hpp>
#include <lockey/verify/server.hpp>
#include <thread>

// Global server instance for signal handling
lockey::verify::Server *g_server = nullptr;

void signal_handler(int signal) {
    if (signal == SIGINT || signal == SIGTERM) {
        std::cout << "\nShutting down server...\n";
        if (g_server) {
            g_server->stop();
        }
    }
}

int main(int argc, char *argv[]) {
    std::cout << "Lockey Simple Verification Server\n";
    std::cout << "==================================\n\n";

    // Parse command line arguments
    std::string port = (argc >= 2) ? argv[1] : "50051";
    std::string address = "0.0.0.0:" + port;

    // Create a simple revocation handler
    auto handler = std::make_shared<lockey::verify::SimpleRevocationHandler>();

    // Example: Add some revoked certificates for demonstration
    // In a real application, you would load these from a database or CRL
    std::cout << "Initializing revocation list...\n";

    // Example revoked certificate serial numbers
    handler->add_revoked_certificate({0x01, 0x02, 0x03, 0x04, 0x05}, "Key compromise",
                                     std::chrono::system_clock::now() - std::chrono::hours(48));

    handler->add_revoked_certificate({0xDE, 0xAD, 0xBE, 0xEF}, "Certificate hold",
                                     std::chrono::system_clock::now() - std::chrono::hours(24));

    std::cout << "Added 2 revoked certificates to the list\n\n";

    // Configure server
    lockey::verify::ServerConfig config;
    config.host = "0.0.0.0";
    config.port = static_cast<uint16_t>(std::stoi(port));
    config.max_threads = 4;

    std::cout << "Creating server...\n";
    lockey::verify::Server server(handler, config);
    g_server = &server;

    // Optional: Generate and set signing key for response signatures
    std::cout << "Generating Ed25519 signing key...\n";
    std::vector<uint8_t> pk(crypto_sign_PUBLICKEYBYTES);
    std::vector<uint8_t> sk(crypto_sign_SECRETKEYBYTES);
    crypto_sign_keypair(pk.data(), sk.data());
    server.set_signing_key(sk);

    // Optional: Create and set responder certificate
    std::cout << "Creating responder certificate...\n";
    lockey::crypto::Lockey lockey(lockey::crypto::Lockey::Algorithm::Ed25519);
    auto keys = lockey.generate_keypair();

    auto dn_result =
        lockey::cert::DistinguishedName::from_string("CN=Lockey Verification Server,O=Example Organization");
    if (dn_result.success) {
        auto not_before = std::chrono::system_clock::now();
        auto not_after = not_before + std::chrono::hours(24 * 365); // 1 year

        lockey::cert::CertificateBuilder builder;
        builder.set_version(3)  // v3 required for extensions
            .set_serial(1)
            .set_subject(dn_result.value)
            .set_issuer(dn_result.value)
            .set_validity(not_before, not_after)
            .set_subject_public_key_ed25519(keys.public_key)
            .set_basic_constraints(true, std::nullopt, true);

        auto cert_result = builder.build_ed25519(keys, true);
        if (cert_result.success) {
            server.set_responder_certificate(cert_result.value);
            std::cout << "Responder certificate created\n";
        }
    }

    // Setup signal handlers for graceful shutdown
    std::signal(SIGINT, signal_handler);
    std::signal(SIGTERM, signal_handler);

    std::cout << "\nServer Configuration:\n";
    std::cout << "  Address: " << config.host << ":" << config.port << "\n";
    std::cout << "  Threads: " << config.max_threads << "\n";
    std::cout << "  Response Signing: enabled\n";
    std::cout << "\nStarting server...\n";
    std::cout << "Press Ctrl+C to stop\n\n";

    try {
        // Start server (blocks until stopped)
        server.start_async();

        std::cout << "Server started successfully!\n";
        std::cout << "Listening for verification requests...\n\n";

        // Print stats periodically
        while (server.is_running()) {
            std::this_thread::sleep_for(std::chrono::seconds(10));

            auto stats = server.get_stats();
            std::cout << "\n=== Server Statistics ===\n";
            std::cout << "Total requests: " << stats.total_requests << "\n";
            std::cout << "Batch requests: " << stats.total_batch_requests << "\n";
            std::cout << "Health checks: " << stats.total_health_checks << "\n";
            std::cout << "GOOD responses: " << stats.good_responses << "\n";
            std::cout << "REVOKED responses: " << stats.revoked_responses << "\n";
            std::cout << "UNKNOWN responses: " << stats.unknown_responses << "\n";

            auto uptime = std::chrono::system_clock::now() - stats.start_time;
            auto uptime_seconds = std::chrono::duration_cast<std::chrono::seconds>(uptime).count();
            std::cout << "Uptime: " << uptime_seconds << " seconds\n";
            std::cout << "========================\n\n";
        }

        server.wait();
        std::cout << "Server stopped.\n";

    } catch (const std::exception &e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }

    g_server = nullptr;
    return 0;
}
