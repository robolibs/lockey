#pragma once

#include <keylock/verify/client.hpp>
#include <keylock/verify/server.hpp>
#include <keylock/verify/transport.hpp>

namespace keylock::verify {

    // Direct transport - connects client to request processor in-process (no networking)
    // This is useful for local verification without any network overhead
    class DirectTransport : public Transport {
      public:
        explicit DirectTransport(std::shared_ptr<RequestProcessor> processor);
        ~DirectTransport() override;

        // Transport interface
        std::vector<uint8_t> call(uint32_t method_id, const std::vector<uint8_t> &request) override;
        bool is_ready() const override;
        std::string last_error() const override;

      private:
        std::shared_ptr<RequestProcessor> processor_;
        std::string last_error_;
    };

    // Helper function to create a verification client with direct (in-process) transport
    // This is the simplest way to use the verification system without networking
    class Verifier {
      public:
        // Create a verifier with a custom handler
        explicit Verifier(std::shared_ptr<VerificationHandler> handler);

        // Create a verifier with a SimpleRevocationHandler
        Verifier();

        ~Verifier();

        // Disable copy
        Verifier(const Verifier &) = delete;
        Verifier &operator=(const Verifier &) = delete;

        // Enable move
        Verifier(Verifier &&) noexcept;
        Verifier &operator=(Verifier &&) noexcept;

        // Get the underlying handler (for adding revocations, etc.)
        VerificationHandler &handler();
        const VerificationHandler &handler() const;

        // Get as SimpleRevocationHandler (returns nullptr if not a SimpleRevocationHandler)
        SimpleRevocationHandler *as_revocation_handler();

        // Get the client for performing verifications
        Client &client();

        // Set the signing key for response signatures
        void set_signing_key(const std::vector<uint8_t> &ed25519_private_key);

        // Set the responder certificate
        void set_responder_certificate(const cert::Certificate &cert);

        // Convenience method: verify a single chain directly
        Client::Result<Client::Response>
        verify_chain(const std::vector<cert::Certificate> &chain,
                     std::chrono::system_clock::time_point validation_time = std::chrono::system_clock::now());

        // Convenience method: verify batch
        Client::Result<std::vector<Client::Response>>
        verify_batch(const std::vector<std::vector<cert::Certificate>> &chains);

        // Convenience method: health check
        Client::Result<bool> health_check();

      private:
        class Impl;
        std::unique_ptr<Impl> impl_;
    };

} // namespace keylock::verify
