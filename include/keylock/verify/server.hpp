#pragma once

#include <chrono>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include <keylock/cert/certificate.hpp>
#include <keylock/verify/wire_format.hpp>

namespace keylock::verify {

    // Method IDs for RPC routing
    namespace methods {
        constexpr uint32_t CHECK_CERTIFICATE = 1;
        constexpr uint32_t CHECK_BATCH = 2;
        constexpr uint32_t HEALTH_CHECK = 3;
    } // namespace methods

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

    // Request processor - handles wire format requests and dispatches to handler
    // This can be used to build custom server implementations
    class RequestProcessor {
      public:
        explicit RequestProcessor(std::shared_ptr<VerificationHandler> handler);
        ~RequestProcessor();

        // Process a raw request and return a raw response
        // method_id: The RPC method ID (CHECK_CERTIFICATE, CHECK_BATCH, HEALTH_CHECK)
        // request_data: Serialized wire format request
        // Returns: Serialized wire format response
        std::vector<uint8_t> process(uint32_t method_id, const std::vector<uint8_t> &request_data);

        // Set the signing key for response signatures (Ed25519)
        void set_signing_key(const std::vector<uint8_t> &ed25519_private_key);

        // Set the responder certificate (included in responses if requested)
        void set_responder_certificate(const cert::Certificate &cert);

        // Statistics
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

      private:
        class Impl;
        std::unique_ptr<Impl> impl_;
    };

} // namespace keylock::verify
