#include <keylock/verify/server.hpp>

#include <atomic>
#include <sodium.h>

namespace keylock::verify {

    // SimpleRevocationHandler implementation
    void SimpleRevocationHandler::add_revoked_certificate(const std::vector<uint8_t> &serial_number,
                                                          const std::string &reason,
                                                          std::chrono::system_clock::time_point revocation_time) {

        std::lock_guard<std::mutex> lock(mutex_);
        RevocationInfo info;
        info.reason = reason;
        info.revocation_time = revocation_time;
        info.this_update = std::chrono::system_clock::now();
        info.next_update = info.this_update + std::chrono::hours(24);
        revoked_certs_[serial_number] = info;
    }

    void SimpleRevocationHandler::remove_revoked_certificate(const std::vector<uint8_t> &serial_number) {
        std::lock_guard<std::mutex> lock(mutex_);
        revoked_certs_.erase(serial_number);
    }

    bool SimpleRevocationHandler::is_revoked(const std::vector<uint8_t> &serial_number) const {
        std::lock_guard<std::mutex> lock(mutex_);
        return revoked_certs_.find(serial_number) != revoked_certs_.end();
    }

    void SimpleRevocationHandler::clear() {
        std::lock_guard<std::mutex> lock(mutex_);
        revoked_certs_.clear();
    }

    wire::VerifyResponse SimpleRevocationHandler::verify_chain(const std::vector<cert::Certificate> &chain,
                                                               std::chrono::system_clock::time_point validation_time) {

        wire::VerifyResponse response;
        if (chain.empty()) {
            response.status = wire::VerifyStatus::UNKNOWN;
            response.reason = "Empty certificate chain";
            return response;
        }

        const auto &cert = chain[0];
        const auto &serial = cert.tbs().serial_number;

        std::lock_guard<std::mutex> lock(mutex_);
        auto it = revoked_certs_.find(serial);

        if (it != revoked_certs_.end()) {
            response.status = wire::VerifyStatus::REVOKED;
            response.reason = it->second.reason;
            response.revocation_time = it->second.revocation_time;
            response.this_update = it->second.this_update;
            response.next_update = it->second.next_update;
        } else {
            response.status = wire::VerifyStatus::GOOD;
            response.reason = "Certificate is valid";
            response.this_update = std::chrono::system_clock::now();
            response.next_update = response.this_update + std::chrono::hours(24);
        }
        return response;
    }

    // RequestProcessor implementation
    class RequestProcessor::Impl {
      public:
        std::shared_ptr<VerificationHandler> handler;

        std::vector<uint8_t> signing_key;
        std::optional<cert::Certificate> responder_cert;

        RequestProcessor::Stats stats;
        mutable std::mutex stats_mutex;

        explicit Impl(std::shared_ptr<VerificationHandler> h) : handler(std::move(h)) {
            stats.start_time = std::chrono::system_clock::now();
        }

        void sign_response(wire::VerifyResponse &response);

        std::vector<uint8_t> handle_verify_request(const std::vector<uint8_t> &request_data);
        std::vector<uint8_t> handle_batch_request(const std::vector<uint8_t> &request_data);
        std::vector<uint8_t> handle_health_check(const std::vector<uint8_t> &request_data);
    };

    void RequestProcessor::Impl::sign_response(wire::VerifyResponse &response) {
        if (signing_key.size() != crypto_sign_SECRETKEYBYTES) {
            return;
        }

        std::vector<uint8_t> message;
        message.push_back(static_cast<uint8_t>(response.status));
        message.insert(message.end(), response.reason.begin(), response.reason.end());

        auto rev_time = std::chrono::system_clock::to_time_t(response.revocation_time);
        auto this_time = std::chrono::system_clock::to_time_t(response.this_update);
        auto next_time = std::chrono::system_clock::to_time_t(response.next_update);

        for (int i = 0; i < 8; i++) {
            message.push_back(static_cast<uint8_t>((rev_time >> (i * 8)) & 0xFF));
        }
        for (int i = 0; i < 8; i++) {
            message.push_back(static_cast<uint8_t>((this_time >> (i * 8)) & 0xFF));
        }
        for (int i = 0; i < 8; i++) {
            message.push_back(static_cast<uint8_t>((next_time >> (i * 8)) & 0xFF));
        }

        message.insert(message.end(), response.nonce.begin(), response.nonce.end());

        response.signature.resize(crypto_sign_BYTES);
        crypto_sign_detached(response.signature.data(), nullptr, message.data(), message.size(), signing_key.data());
    }

    std::vector<uint8_t> RequestProcessor::Impl::handle_verify_request(const std::vector<uint8_t> &request_data) {
        wire::VerifyRequest wire_req;

        if (!wire::Serializer::deserialize(request_data, wire_req)) {
            wire::VerifyResponse error_resp;
            error_resp.status = wire::VerifyStatus::UNKNOWN;
            error_resp.reason = "Failed to deserialize request";
            return wire::Serializer::serialize(error_resp);
        }

        std::vector<cert::Certificate> chain;
        for (const auto &cert_data : wire_req.certificate_chain) {
            auto parse_result = cert::Certificate::parse(cert_data.der_bytes);
            if (!parse_result.success) {
                wire::VerifyResponse error_resp;
                error_resp.status = wire::VerifyStatus::UNKNOWN;
                error_resp.reason = "Failed to parse certificate: " + parse_result.error;
                error_resp.nonce = wire_req.nonce;
                return wire::Serializer::serialize(error_resp);
            }
            chain.push_back(std::move(parse_result.value));
        }

        auto response = handler->verify_chain(chain, wire_req.validation_timestamp);
        response.nonce = wire_req.nonce;

        if ((wire_req.flags & wire::RequestFlags::INCLUDE_RESPONDER_CERT) != wire::RequestFlags::NONE) {
            if (responder_cert.has_value()) {
                response.responder_cert_der = responder_cert->der();
            }
        }

        sign_response(response);

        {
            std::lock_guard<std::mutex> lock(stats_mutex);
            stats.total_requests++;
            switch (response.status) {
            case wire::VerifyStatus::GOOD:
                stats.good_responses++;
                break;
            case wire::VerifyStatus::REVOKED:
                stats.revoked_responses++;
                break;
            case wire::VerifyStatus::UNKNOWN:
                stats.unknown_responses++;
                break;
            }
        }

        return wire::Serializer::serialize(response);
    }

    std::vector<uint8_t> RequestProcessor::Impl::handle_batch_request(const std::vector<uint8_t> &request_data) {
        wire::BatchVerifyRequest batch_req;

        if (!wire::Serializer::deserialize(request_data, batch_req)) {
            wire::BatchVerifyResponse error_resp;
            return wire::Serializer::serialize(error_resp);
        }

        std::vector<std::vector<cert::Certificate>> chains;
        for (const auto &req : batch_req.requests) {
            std::vector<cert::Certificate> chain;
            for (const auto &cert_data : req.certificate_chain) {
                auto parse_result = cert::Certificate::parse(cert_data.der_bytes);
                if (parse_result.success) {
                    chain.push_back(std::move(parse_result.value));
                }
            }
            chains.push_back(std::move(chain));
        }

        auto responses = handler->verify_batch(chains);

        for (size_t i = 0; i < responses.size() && i < batch_req.requests.size(); i++) {
            responses[i].nonce = batch_req.requests[i].nonce;
            sign_response(responses[i]);
        }

        {
            std::lock_guard<std::mutex> lock(stats_mutex);
            stats.total_batch_requests++;
            for (const auto &resp : responses) {
                switch (resp.status) {
                case wire::VerifyStatus::GOOD:
                    stats.good_responses++;
                    break;
                case wire::VerifyStatus::REVOKED:
                    stats.revoked_responses++;
                    break;
                case wire::VerifyStatus::UNKNOWN:
                    stats.unknown_responses++;
                    break;
                }
            }
        }

        wire::BatchVerifyResponse batch_resp;
        batch_resp.responses = std::move(responses);
        return wire::Serializer::serialize(batch_resp);
    }

    std::vector<uint8_t> RequestProcessor::Impl::handle_health_check(const std::vector<uint8_t> &request_data) {
        wire::HealthCheckResponse health_resp;
        health_resp.status = handler->is_healthy() ? wire::HealthCheckResponse::ServingStatus::SERVING
                                                   : wire::HealthCheckResponse::ServingStatus::NOT_SERVING;

        {
            std::lock_guard<std::mutex> lock(stats_mutex);
            stats.total_health_checks++;
        }

        return wire::Serializer::serialize(health_resp);
    }

    // RequestProcessor public interface
    RequestProcessor::RequestProcessor(std::shared_ptr<VerificationHandler> handler)
        : impl_(std::make_unique<Impl>(std::move(handler))) {}

    RequestProcessor::~RequestProcessor() = default;

    std::vector<uint8_t> RequestProcessor::process(uint32_t method_id, const std::vector<uint8_t> &request_data) {
        switch (method_id) {
        case methods::CHECK_CERTIFICATE:
            return impl_->handle_verify_request(request_data);
        case methods::CHECK_BATCH:
            return impl_->handle_batch_request(request_data);
        case methods::HEALTH_CHECK:
            return impl_->handle_health_check(request_data);
        default:
            // Unknown method - return empty response
            return {};
        }
    }

    void RequestProcessor::set_signing_key(const std::vector<uint8_t> &ed25519_private_key) {
        if (ed25519_private_key.size() != crypto_sign_SECRETKEYBYTES) {
            throw std::invalid_argument("Invalid Ed25519 private key size");
        }
        impl_->signing_key = ed25519_private_key;
    }

    void RequestProcessor::set_responder_certificate(const cert::Certificate &cert) { impl_->responder_cert = cert; }

    RequestProcessor::Stats RequestProcessor::get_stats() const {
        std::lock_guard<std::mutex> lock(impl_->stats_mutex);
        return impl_->stats;
    }

} // namespace keylock::verify
