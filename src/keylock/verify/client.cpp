#include <keylock/verify/client.hpp>
#include <keylock/verify/server.hpp> // For method IDs

#include <sodium.h>

namespace keylock::verify {

    // PIMPL implementation
    class Client::Impl {
      public:
        std::shared_ptr<Transport> transport;
        ClientConfig config;
        std::optional<cert::Certificate> responder_cert;

        explicit Impl(std::shared_ptr<Transport> t, const ClientConfig &cfg) : transport(std::move(t)), config(cfg) {}

        ~Impl() = default;
    };

    // Constructor
    Client::Client(std::shared_ptr<Transport> transport, const ClientConfig &config)
        : impl_(std::make_unique<Impl>(std::move(transport), config)) {}

    // Destructor
    Client::~Client() = default;

    // Move constructor
    Client::Client(Client &&) noexcept = default;

    // Move assignment
    Client &Client::operator=(Client &&) noexcept = default;

    bool Client::is_ready() const { return impl_->transport && impl_->transport->is_ready(); }

    // Verify single certificate chain
    Client::Result<Client::Response> Client::verify_chain(const std::vector<cert::Certificate> &chain,
                                                          std::chrono::system_clock::time_point validation_time) {

        if (chain.empty()) {
            return Result<Response>::failure("Certificate chain is empty");
        }

        if (!is_ready()) {
            return Result<Response>::failure("Transport is not ready");
        }

        // Build wire format request
        wire::VerifyRequest wire_req;
        for (const auto &cert : chain) {
            wire::CertificateData cert_data;
            cert_data.der_bytes = cert.to_der();
            wire_req.certificate_chain.push_back(std::move(cert_data));
        }
        wire_req.validation_timestamp = validation_time;
        wire_req.flags = wire::RequestFlags::NONE;

        // Generate nonce
        wire_req.nonce.resize(32);
        randombytes_buf(wire_req.nonce.data(), wire_req.nonce.size());

        // Serialize request
        auto request_data = wire::Serializer::serialize(wire_req);

        // Call via transport
        auto response_data = impl_->transport->call(methods::CHECK_CERTIFICATE, request_data);

        if (response_data.empty()) {
            return Result<Response>::failure("Transport call failed: " + impl_->transport->last_error());
        }

        // Deserialize response
        wire::VerifyResponse wire_resp;
        if (!wire::Serializer::deserialize(response_data, wire_resp)) {
            return Result<Response>::failure("Failed to deserialize response");
        }

        // Verify nonce matches
        if (wire_resp.nonce != wire_req.nonce) {
            return Result<Response>::failure("Nonce mismatch - possible replay attack");
        }

        // Convert to client response
        Response response;
        response.status = wire_resp.status;
        response.valid = (wire_resp.status == wire::VerifyStatus::GOOD);
        response.reason = wire_resp.reason;
        response.revocation_time = wire_resp.revocation_time;
        response.this_update = wire_resp.this_update;
        response.next_update = wire_resp.next_update;
        response.signature = wire_resp.signature;
        response.nonce = wire_resp.nonce;

        // Verify signature if responder cert is set
        if (impl_->responder_cert.has_value()) {
            if (!verify_response_signature(response)) {
                return Result<Response>::failure("Response signature verification failed");
            }
        }

        return Result<Response>::ok(std::move(response));
    }

    // Batch verification
    Client::Result<std::vector<Client::Response>>
    Client::verify_batch(const std::vector<std::vector<cert::Certificate>> &chains) {

        if (chains.empty()) {
            return Result<std::vector<Response>>::failure("No chains provided");
        }

        if (!is_ready()) {
            return Result<std::vector<Response>>::failure("Transport is not ready");
        }

        // Build batch request
        wire::BatchVerifyRequest batch_req;
        for (const auto &chain : chains) {
            if (chain.empty()) {
                continue;
            }

            wire::VerifyRequest wire_req;
            for (const auto &cert : chain) {
                wire::CertificateData cert_data;
                cert_data.der_bytes = cert.to_der();
                wire_req.certificate_chain.push_back(std::move(cert_data));
            }
            wire_req.validation_timestamp = std::chrono::system_clock::now();
            wire_req.flags = wire::RequestFlags::NONE;

            // Generate unique nonce for each request
            wire_req.nonce.resize(32);
            randombytes_buf(wire_req.nonce.data(), wire_req.nonce.size());

            batch_req.requests.push_back(std::move(wire_req));
        }

        // Serialize request
        auto request_data = wire::Serializer::serialize(batch_req);

        // Call via transport
        auto response_data = impl_->transport->call(methods::CHECK_BATCH, request_data);

        if (response_data.empty()) {
            return Result<std::vector<Response>>::failure("Transport call failed: " + impl_->transport->last_error());
        }

        // Deserialize response
        wire::BatchVerifyResponse batch_resp;
        if (!wire::Serializer::deserialize(response_data, batch_resp)) {
            return Result<std::vector<Response>>::failure("Failed to deserialize batch response");
        }

        // Convert to client responses
        std::vector<Response> responses;
        responses.reserve(batch_resp.responses.size());

        for (const auto &wire_resp : batch_resp.responses) {
            Response response;
            response.status = wire_resp.status;
            response.valid = (wire_resp.status == wire::VerifyStatus::GOOD);
            response.reason = wire_resp.reason;
            response.revocation_time = wire_resp.revocation_time;
            response.this_update = wire_resp.this_update;
            response.next_update = wire_resp.next_update;
            response.signature = wire_resp.signature;
            response.nonce = wire_resp.nonce;

            responses.push_back(std::move(response));
        }

        return Result<std::vector<Response>>::ok(std::move(responses));
    }

    // Set responder certificate
    void Client::set_responder_cert(const cert::Certificate &cert) { impl_->responder_cert = cert; }

    // Health check
    Client::Result<bool> Client::health_check() {
        if (!is_ready()) {
            return Result<bool>::failure("Transport is not ready");
        }

        wire::HealthCheckRequest req;

        // Serialize request
        auto request_data = wire::Serializer::serialize(req);

        // Call via transport
        auto response_data = impl_->transport->call(methods::HEALTH_CHECK, request_data);

        if (response_data.empty()) {
            return Result<bool>::failure("Health check failed: " + impl_->transport->last_error());
        }

        // Deserialize response
        wire::HealthCheckResponse resp;
        if (!wire::Serializer::deserialize(response_data, resp)) {
            return Result<bool>::failure("Failed to deserialize health check response");
        }

        bool healthy = (resp.status == wire::HealthCheckResponse::ServingStatus::SERVING);
        return Result<bool>::ok(healthy);
    }

    // Verify response signature
    bool Client::verify_response_signature(const Response &response) {
        if (!impl_->responder_cert.has_value()) {
            return false;
        }

        if (response.signature.size() != crypto_sign_BYTES) {
            return false;
        }

        // Build message to verify (concatenate fields in order)
        std::vector<uint8_t> message;

        // Status
        message.push_back(static_cast<uint8_t>(response.status));

        // Reason
        message.insert(message.end(), response.reason.begin(), response.reason.end());

        // Timestamps (as Unix timestamps)
        auto rev_time =
            std::chrono::duration_cast<std::chrono::seconds>(response.revocation_time.time_since_epoch()).count();
        auto this_time =
            std::chrono::duration_cast<std::chrono::seconds>(response.this_update.time_since_epoch()).count();
        auto next_time =
            std::chrono::duration_cast<std::chrono::seconds>(response.next_update.time_since_epoch()).count();

        for (int i = 7; i >= 0; --i) {
            message.push_back(static_cast<uint8_t>((rev_time >> (i * 8)) & 0xFF));
        }
        for (int i = 7; i >= 0; --i) {
            message.push_back(static_cast<uint8_t>((this_time >> (i * 8)) & 0xFF));
        }
        for (int i = 7; i >= 0; --i) {
            message.push_back(static_cast<uint8_t>((next_time >> (i * 8)) & 0xFF));
        }

        // Nonce
        message.insert(message.end(), response.nonce.begin(), response.nonce.end());

        // Get public key from responder certificate
        const auto &pub_key = impl_->responder_cert->tbs().subject_public_key_info.public_key;
        if (pub_key.size() != crypto_sign_PUBLICKEYBYTES) {
            return false;
        }

        // Verify Ed25519 signature
        int verify_result =
            crypto_sign_verify_detached(response.signature.data(), message.data(), message.size(), pub_key.data());

        return (verify_result == 0);
    }

} // namespace keylock::verify
