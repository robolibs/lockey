#include <lockey/verify/server.hpp>

#include <netpipe/remote/remote.hpp>
#include <netpipe/stream/tcp.hpp>

#include <atomic>
#include <iostream>
#include <sodium.h>
#include <thread>

namespace lockey::verify {

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

    // Server implementation
    class Server::Impl {
      public:
        std::shared_ptr<VerificationHandler> handler;
        ServerConfig config;
        netpipe::TcpStream listener;
        std::atomic<bool> running{false};
        std::atomic<bool> should_stop{false};

        std::vector<uint8_t> signing_key;
        std::optional<cert::Certificate> responder_cert;

        Server::Stats stats;
        mutable std::mutex stats_mutex;

        std::thread server_thread;

        explicit Impl(std::shared_ptr<VerificationHandler> h, const ServerConfig &cfg)
            : handler(std::move(h)), config(cfg) {
            stats.start_time = std::chrono::system_clock::now();
        }

        void sign_response(wire::VerifyResponse &response);

        dp::Res<netpipe::Message> handle_verify_request(const netpipe::Message &request_data);
        dp::Res<netpipe::Message> handle_batch_request(const netpipe::Message &request_data);
        dp::Res<netpipe::Message> handle_health_check(const netpipe::Message &request_data);

        void serve_client(std::unique_ptr<netpipe::Stream> client_stream);
        void run_server();
    };

    void Server::Impl::sign_response(wire::VerifyResponse &response) {
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

    dp::Res<netpipe::Message> Server::Impl::handle_verify_request(const netpipe::Message &request_data) {
        wire::VerifyRequest wire_req;
        std::vector<uint8_t> data(request_data.begin(), request_data.end());

        if (!wire::Serializer::deserialize(data, wire_req)) {
            wire::VerifyResponse error_resp;
            error_resp.status = wire::VerifyStatus::UNKNOWN;
            error_resp.reason = "Failed to deserialize request";
            auto resp_data = wire::Serializer::serialize(error_resp);
            return dp::result::ok(netpipe::Message(resp_data.begin(), resp_data.end()));
        }

        std::vector<cert::Certificate> chain;
        for (const auto &cert_data : wire_req.certificate_chain) {
            auto parse_result = cert::Certificate::parse(cert_data.der_bytes);
            if (!parse_result.success) {
                wire::VerifyResponse error_resp;
                error_resp.status = wire::VerifyStatus::UNKNOWN;
                error_resp.reason = "Failed to parse certificate: " + parse_result.error;
                error_resp.nonce = wire_req.nonce;
                auto resp_data = wire::Serializer::serialize(error_resp);
                return dp::result::ok(netpipe::Message(resp_data.begin(), resp_data.end()));
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

        auto resp_data = wire::Serializer::serialize(response);
        return dp::result::ok(netpipe::Message(resp_data.begin(), resp_data.end()));
    }

    dp::Res<netpipe::Message> Server::Impl::handle_batch_request(const netpipe::Message &request_data) {
        wire::BatchVerifyRequest batch_req;
        std::vector<uint8_t> data(request_data.begin(), request_data.end());

        if (!wire::Serializer::deserialize(data, batch_req)) {
            wire::BatchVerifyResponse error_resp;
            auto resp_data = wire::Serializer::serialize(error_resp);
            return dp::result::ok(netpipe::Message(resp_data.begin(), resp_data.end()));
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
        auto resp_data = wire::Serializer::serialize(batch_resp);
        return dp::result::ok(netpipe::Message(resp_data.begin(), resp_data.end()));
    }

    dp::Res<netpipe::Message> Server::Impl::handle_health_check(const netpipe::Message &request_data) {
        wire::HealthCheckResponse health_resp;
        health_resp.status = handler->is_healthy() ? wire::HealthCheckResponse::ServingStatus::SERVING
                                                   : wire::HealthCheckResponse::ServingStatus::NOT_SERVING;

        {
            std::lock_guard<std::mutex> lock(stats_mutex);
            stats.total_health_checks++;
        }

        auto resp_data = wire::Serializer::serialize(health_resp);
        return dp::result::ok(netpipe::Message(resp_data.begin(), resp_data.end()));
    }

    void Server::Impl::serve_client(std::unique_ptr<netpipe::Stream> client_stream) {
        netpipe::remote::Remote<netpipe::remote::Unidirect> remote(*client_stream);

        remote.register_method(methods::CHECK_CERTIFICATE,
                               [this](const netpipe::Message &req) { return handle_verify_request(req); });

        remote.register_method(methods::CHECK_BATCH,
                               [this](const netpipe::Message &req) { return handle_batch_request(req); });

        remote.register_method(methods::HEALTH_CHECK,
                               [this](const netpipe::Message &req) { return handle_health_check(req); });

        // Serve requests until connection closes or server stops
        remote.serve();
    }

    void Server::Impl::run_server() {
        netpipe::TcpEndpoint endpoint{dp::String(config.host.c_str()), config.port};
        auto listen_result = listener.listen(endpoint);

        if (listen_result.is_err()) {
            std::cerr << "Failed to start server on " << config.host << ":" << config.port << std::endl;
            return;
        }

        running = true;
        std::cout << "Lockey Verification Server listening on " << config.host << ":" << config.port << std::endl;

        listener.set_recv_timeout(config.recv_timeout_ms);

        while (!should_stop) {
            auto accept_result = listener.accept();
            if (accept_result.is_err()) {
                // Timeout or error - check if we should stop
                continue;
            }

            auto client_stream = std::move(accept_result.value());

            // Handle client in a new thread
            std::thread([this, stream = std::move(client_stream)]() mutable {
                serve_client(std::move(stream));
            }).detach();
        }

        running = false;
    }

    // Server public interface
    Server::Server(std::shared_ptr<VerificationHandler> handler, const ServerConfig &config)
        : impl_(std::make_unique<Impl>(std::move(handler), config)) {}

    Server::~Server() {
        if (impl_ && impl_->running) {
            stop();
        }
    }

    Server::Server(Server &&) noexcept = default;
    Server &Server::operator=(Server &&) noexcept = default;

    void Server::start() {
        if (impl_->running) {
            return;
        }
        impl_->run_server();
    }

    void Server::start_async() {
        if (impl_->running) {
            return;
        }

        impl_->server_thread = std::thread([this]() { this->start(); });
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }

    void Server::stop() {
        if (!impl_->running) {
            return;
        }

        impl_->should_stop = true;
        impl_->listener.close();

        if (impl_->server_thread.joinable()) {
            impl_->server_thread.join();
        }
    }

    void Server::wait() {
        if (impl_->server_thread.joinable()) {
            impl_->server_thread.join();
        }
    }

    bool Server::is_running() const { return impl_->running; }

    std::string Server::address() const { return impl_->config.host + ":" + std::to_string(impl_->config.port); }

    void Server::set_signing_key(const std::vector<uint8_t> &ed25519_private_key) {
        if (ed25519_private_key.size() != crypto_sign_SECRETKEYBYTES) {
            throw std::invalid_argument("Invalid Ed25519 private key size");
        }
        impl_->signing_key = ed25519_private_key;
    }

    void Server::set_responder_certificate(const cert::Certificate &cert) { impl_->responder_cert = cert; }

    Server::Stats Server::get_stats() const {
        std::lock_guard<std::mutex> lock(impl_->stats_mutex);
        return impl_->stats;
    }

} // namespace lockey::verify
