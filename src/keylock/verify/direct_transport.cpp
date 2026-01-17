#include <keylock/verify/direct_transport.hpp>

namespace keylock::verify {

    // DirectTransport implementation
    DirectTransport::DirectTransport(std::shared_ptr<RequestProcessor> processor) : processor_(std::move(processor)) {}

    DirectTransport::~DirectTransport() = default;

    std::vector<uint8_t> DirectTransport::call(uint32_t method_id, const std::vector<uint8_t> &request) {
        if (!processor_) {
            last_error_ = "No processor configured";
            return {};
        }

        try {
            auto response = processor_->process(method_id, request);
            last_error_.clear();
            return response;
        } catch (const std::exception &e) {
            last_error_ = e.what();
            return {};
        }
    }

    bool DirectTransport::is_ready() const { return processor_ != nullptr; }

    std::string DirectTransport::last_error() const { return last_error_; }

    // Verifier implementation
    class Verifier::Impl {
      public:
        std::shared_ptr<VerificationHandler> handler;
        std::shared_ptr<RequestProcessor> processor;
        std::shared_ptr<DirectTransport> transport;
        std::unique_ptr<Client> client;

        explicit Impl(std::shared_ptr<VerificationHandler> h) : handler(std::move(h)) {
            processor = std::make_shared<RequestProcessor>(handler);
            transport = std::make_shared<DirectTransport>(processor);
            client = std::make_unique<Client>(transport);
        }
    };

    Verifier::Verifier(std::shared_ptr<VerificationHandler> handler)
        : impl_(std::make_unique<Impl>(std::move(handler))) {}

    Verifier::Verifier() : Verifier(std::make_shared<SimpleRevocationHandler>()) {}

    Verifier::~Verifier() = default;

    Verifier::Verifier(Verifier &&) noexcept = default;
    Verifier &Verifier::operator=(Verifier &&) noexcept = default;

    VerificationHandler &Verifier::handler() { return *impl_->handler; }

    const VerificationHandler &Verifier::handler() const { return *impl_->handler; }

    SimpleRevocationHandler *Verifier::as_revocation_handler() {
        return dynamic_cast<SimpleRevocationHandler *>(impl_->handler.get());
    }

    Client &Verifier::client() { return *impl_->client; }

    void Verifier::set_signing_key(const std::vector<uint8_t> &ed25519_private_key) {
        impl_->processor->set_signing_key(ed25519_private_key);
    }

    void Verifier::set_responder_certificate(const cert::Certificate &cert) {
        impl_->processor->set_responder_certificate(cert);
        impl_->client->set_responder_cert(cert);
    }

    Client::Result<Client::Response> Verifier::verify_chain(const std::vector<cert::Certificate> &chain,
                                                            std::chrono::system_clock::time_point validation_time) {
        return impl_->client->verify_chain(chain, validation_time);
    }

    Client::Result<std::vector<Client::Response>>
    Verifier::verify_batch(const std::vector<std::vector<cert::Certificate>> &chains) {
        return impl_->client->verify_batch(chains);
    }

    Client::Result<bool> Verifier::health_check() { return impl_->client->health_check(); }

} // namespace keylock::verify
