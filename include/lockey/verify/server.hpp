#pragma once

#include <chrono>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include <lockey/cert/certificate.hpp>
#include <lockey/verify/wire_format.hpp>

namespace lockey::verify {

    // Method IDs for RPC routing
    namespace methods {
        constexpr uint32_t CHECK_CERTIFICATE = 1;
        constexpr uint32_t CHECK_BATCH = 2;
        constexpr uint32_t HEALTH_CHECK = 3;
    } // namespace methods

    // Server configuration
    struct ServerConfig {
        std::string host{"0.0.0.0"};
        uint16_t port{50051};
        int max_threads{4};                       // Number of worker threads
        std::chrono::seconds shutdown_timeout{5}; // Graceful shutdown timeout
        int recv_timeout_ms{5000};                // Receive timeout in milliseconds

        ServerConfig() = default;
    };

    // Verification handler interface - implement this to provide verification logic
    class VerificationHandler {
      public:
        virtual ~VerificationHandler() = default;

        // Verify a single certificate chain
        // Returns the verification status, reason, and timestamps
        virtual wire::VerifyResponse verify_chain(const std::vector<cert::Certificate> &chain,
                                                  std::chrono::system_clock::time_point validation_time) = 0;

        // Optional: Override for batch optimization
        virtual std::vector<wire::VerifyResponse>
        verify_batch(const std::vector<std::vector<cert::Certificate>> &chains) {
            std::vector<wire::VerifyResponse> responses;
            responses.reserve(chains.size());
            for (const auto &chain : chains) {
                responses.push_back(verify_chain(chain, std::chrono::system_clock::now()));
            }
            return responses;
        }

        // Optional: Health check logic
        virtual bool is_healthy() const { return true; }
    };

    // Simple in-memory revocation list handler
    class SimpleRevocationHandler : public VerificationHandler {
      public:
        SimpleRevocationHandler() = default;

        // Add a revoked certificate by serial number
        void add_revoked_certificate(
            const std::vector<uint8_t> &serial_number, const std::string &reason = "unspecified",
            std::chrono::system_clock::time_point revocation_time = std::chrono::system_clock::now());

        // Remove a certificate from revocation list (if it was added by mistake)
        void remove_revoked_certificate(const std::vector<uint8_t> &serial_number);

        // Check if a certificate is revoked
        bool is_revoked(const std::vector<uint8_t> &serial_number) const;

        // Clear all revocations
        void clear();

        // VerificationHandler interface implementation
        wire::VerifyResponse verify_chain(const std::vector<cert::Certificate> &chain,
                                          std::chrono::system_clock::time_point validation_time) override;

      private:
        struct RevocationInfo {
            std::string reason;
            std::chrono::system_clock::time_point revocation_time;
            std::chrono::system_clock::time_point this_update;
            std::chrono::system_clock::time_point next_update;
        };

        std::map<std::vector<uint8_t>, RevocationInfo> revoked_certs_;
        mutable std::mutex mutex_;
    };

    // Netpipe-based Verification Server
    class Server {
      public:
        // Constructor with handler and config
        explicit Server(std::shared_ptr<VerificationHandler> handler, const ServerConfig &config = ServerConfig{});

        ~Server();

        // Disable copy
        Server(const Server &) = delete;
        Server &operator=(const Server &) = delete;

        // Enable move
        Server(Server &&) noexcept;
        Server &operator=(Server &&) noexcept;

        // Start the server (blocks until Stop() is called)
        void start();

        // Start the server in a background thread (non-blocking)
        void start_async();

        // Stop the server gracefully
        void stop();

        // Wait for the server to finish (if started with start_async)
        void wait();

        // Check if server is running
        bool is_running() const;

        // Get the server address
        std::string address() const;

        // Set the signing key for response signatures (Ed25519)
        // If not set, responses will not be signed
        void set_signing_key(const std::vector<uint8_t> &ed25519_private_key);

        // Set the responder certificate (included in responses if requested)
        void set_responder_certificate(const cert::Certificate &cert);

        // Server statistics
        struct Stats {
            uint64_t total_requests{0};
            uint64_t total_batch_requests{0};
            uint64_t total_health_checks{0};
            uint64_t good_responses{0};
            uint64_t revoked_responses{0};
            uint64_t unknown_responses{0};
            std::chrono::system_clock::time_point start_time;
        };

        Stats get_stats() const;

        class Impl; // Public for implementation details

      private:
        std::unique_ptr<Impl> impl_;
    };

} // namespace lockey::verify
