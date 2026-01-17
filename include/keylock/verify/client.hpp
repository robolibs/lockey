#pragma once

#include <chrono>
#include <memory>
#include <string>
#include <vector>

#include <keylock/cert/certificate.hpp>
#include <keylock/verify/transport.hpp>
#include <keylock/verify/wire_format.hpp>

namespace keylock::verify {

    // Client configuration
    struct ClientConfig {
        std::chrono::seconds timeout{5};
        int max_retry_attempts{3};

        ClientConfig() = default;
    };

    // Verification client for checking certificate revocation status
    class Client {
      public:
        // Response from verification service
        struct Response {
            bool valid{false};
            std::string reason;
            wire::VerifyStatus status{wire::VerifyStatus::UNKNOWN};
            std::chrono::system_clock::time_point revocation_time;
            std::chrono::system_clock::time_point this_update;
            std::chrono::system_clock::time_point next_update;
            std::vector<uint8_t> signature; // Ed25519 signature
            std::vector<uint8_t> nonce;

            Response() = default;
        };

        // Result type for operations
        template <typename T> struct Result {
            bool success{false};
            T value{};
            std::string error;

            static Result<T> ok(T val) { return Result<T>{true, std::move(val), ""}; }

            static Result<T> failure(std::string err) { return Result<T>{false, {}, std::move(err)}; }
        };

        // Constructor with transport
        explicit Client(std::shared_ptr<Transport> transport, const ClientConfig &config = ClientConfig{});

        ~Client();

        // Disable copy
        Client(const Client &) = delete;
        Client &operator=(const Client &) = delete;

        // Enable move
        Client(Client &&) noexcept;
        Client &operator=(Client &&) noexcept;

        // Single certificate chain verification
        Result<Response>
        verify_chain(const std::vector<cert::Certificate> &chain,
                     std::chrono::system_clock::time_point validation_time = std::chrono::system_clock::now());

        // Batch verification for efficiency
        Result<std::vector<Response>> verify_batch(const std::vector<std::vector<cert::Certificate>> &chains);

        // Set responder certificate for signature verification
        void set_responder_cert(const cert::Certificate &cert);

        // Health check
        Result<bool> health_check();

        // Check if transport is ready
        bool is_ready() const;

      private:
        class Impl;
        std::unique_ptr<Impl> impl_;

        // Verify response signature using responder certificate
        bool verify_response_signature(const Response &response);
    };

} // namespace keylock::verify
