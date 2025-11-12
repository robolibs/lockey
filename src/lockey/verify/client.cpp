#ifdef LOCKEY_HAS_VERIFY

#include <grpcpp/create_channel.h>
#include <grpcpp/generic/generic_stub_callback.h>
#include <grpcpp/security/credentials.h>
#include <grpcpp/support/channel_arguments.h>
#include <lockey/verify/client.hpp>
#include <lockey/verify/codec.hpp>
#include <sodium.h>

#include <condition_variable>
#include <mutex>

namespace lockey::verify {

    // PIMPL implementation
    class Client::Impl {
      public:
        std::shared_ptr<grpc::Channel> channel;
        std::unique_ptr<grpc::GenericStubCallback> stub;
        ClientConfig config;
        std::optional<cert::Certificate> responder_cert;

        explicit Impl(const std::string &server_address, const ClientConfig &cfg) : config(cfg) {

            // Setup channel arguments
            grpc::ChannelArguments args;
            if (config.enable_compression) {
                args.SetCompressionAlgorithm(GRPC_COMPRESS_GZIP);
            }
            args.SetMaxReceiveMessageSize(10 * 1024 * 1024); // 10MB max
            args.SetMaxSendMessageSize(10 * 1024 * 1024);    // 10MB max

            // Create credentials
            std::shared_ptr<grpc::ChannelCredentials> creds;
            if (!config.ca_cert_path.empty()) {
                // TLS with custom CA certificate
                grpc::SslCredentialsOptions ssl_opts;
                // TODO: Read CA cert from file
                // ssl_opts.pem_root_certs = read_file(config.ca_cert_path);
                creds = grpc::SslCredentials(ssl_opts);
            } else {
                // Insecure channel (for development/testing)
                creds = grpc::InsecureChannelCredentials();
            }

            // Create channel
            channel = grpc::CreateCustomChannel(server_address, creds, args);

            // Create generic stub for custom binary protocol
            stub = std::make_unique<grpc::GenericStubCallback>(channel);
        }

        ~Impl() = default;
    };

    // Constructor
    Client::Client(const std::string &server_address, const ClientConfig &config)
        : impl_(std::make_unique<Impl>(server_address, config)) {}

    // Destructor
    Client::~Client() = default;

    // Move constructor
    Client::Client(Client &&) noexcept = default;

    // Move assignment
    Client &Client::operator=(Client &&) noexcept = default;

    // Verify single certificate chain
    Client::Result<Client::Response> Client::verify_chain(const std::vector<cert::Certificate> &chain,
                                                          std::chrono::system_clock::time_point validation_time) {

        if (chain.empty()) {
            return Result<Response>::failure("Certificate chain is empty");
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
        grpc::ByteBuffer request_buffer;
        auto serialize_status = CustomCodec::serialize_request(wire_req, &request_buffer);
        if (!serialize_status.ok()) {
            return Result<Response>::failure("Failed to serialize request: " +
                                             std::string(serialize_status.error_message()));
        }

        // Setup RPC context
        grpc::ClientContext context;
        context.set_deadline(std::chrono::system_clock::now() + impl_->config.timeout);

        // Call the server (generic call with custom binary protocol)
        grpc::ByteBuffer response_buffer;

        // Use synchronous wrapper for async callback API
        std::mutex mutex;
        std::condition_variable cv;
        bool done = false;
        grpc::Status status;

        impl_->stub->UnaryCall(&context, "/lockey.verify.VerifyService/CheckCertificate", grpc::StubOptions(),
                               &request_buffer, &response_buffer, [&](grpc::Status s) {
                                   std::lock_guard<std::mutex> lock(mutex);
                                   status = std::move(s);
                                   done = true;
                                   cv.notify_one();
                               });

        // Wait for completion
        {
            std::unique_lock<std::mutex> lock(mutex);
            cv.wait(lock, [&] { return done; });
        }

        if (!status.ok()) {
            return Result<Response>::failure("RPC failed: " + std::string(status.error_message()));
        }

        // Deserialize response
        wire::VerifyResponse wire_resp;
        auto deserialize_status = CustomCodec::deserialize_response(&response_buffer, wire_resp);
        if (!deserialize_status.ok()) {
            return Result<Response>::failure("Failed to deserialize response: " +
                                             std::string(deserialize_status.error_message()));
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
        grpc::ByteBuffer request_buffer;
        auto serialize_status = CustomCodec::serialize_request(batch_req, &request_buffer);
        if (!serialize_status.ok()) {
            return Result<std::vector<Response>>::failure("Failed to serialize batch request: " +
                                                          std::string(serialize_status.error_message()));
        }

        // Setup RPC context
        grpc::ClientContext context;
        context.set_deadline(std::chrono::system_clock::now() + impl_->config.timeout);

        // Call the server
        grpc::ByteBuffer response_buffer;

        // Use synchronous wrapper for async callback API
        std::mutex mutex;
        std::condition_variable cv;
        bool done = false;
        grpc::Status status;

        impl_->stub->UnaryCall(&context, "/lockey.verify.VerifyService/CheckBatch", grpc::StubOptions(),
                               &request_buffer, &response_buffer, [&](grpc::Status s) {
                                   std::lock_guard<std::mutex> lock(mutex);
                                   status = std::move(s);
                                   done = true;
                                   cv.notify_one();
                               });

        // Wait for completion
        {
            std::unique_lock<std::mutex> lock(mutex);
            cv.wait(lock, [&] { return done; });
        }

        if (!status.ok()) {
            return Result<std::vector<Response>>::failure("RPC failed: " + std::string(status.error_message()));
        }

        // Deserialize response
        wire::BatchVerifyResponse batch_resp;
        auto deserialize_status = CustomCodec::deserialize_response(&response_buffer, batch_resp);
        if (!deserialize_status.ok()) {
            return Result<std::vector<Response>>::failure("Failed to deserialize batch response: " +
                                                          std::string(deserialize_status.error_message()));
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
        wire::HealthCheckRequest req;

        // Serialize request
        grpc::ByteBuffer request_buffer;
        auto serialize_status = CustomCodec::serialize_request(req, &request_buffer);
        if (!serialize_status.ok()) {
            return Result<bool>::failure("Failed to serialize health check: " +
                                         std::string(serialize_status.error_message()));
        }

        // Setup RPC context
        grpc::ClientContext context;
        context.set_deadline(std::chrono::system_clock::now() + std::chrono::seconds(5));

        // Call the server
        grpc::ByteBuffer response_buffer;

        // Use synchronous wrapper for async callback API
        std::mutex mutex;
        std::condition_variable cv;
        bool done = false;
        grpc::Status status;

        impl_->stub->UnaryCall(&context, "/lockey.verify.VerifyService/HealthCheck", grpc::StubOptions(),
                               &request_buffer, &response_buffer, [&](grpc::Status s) {
                                   std::lock_guard<std::mutex> lock(mutex);
                                   status = std::move(s);
                                   done = true;
                                   cv.notify_one();
                               });

        // Wait for completion
        {
            std::unique_lock<std::mutex> lock(mutex);
            cv.wait(lock, [&] { return done; });
        }

        if (!status.ok()) {
            return Result<bool>::failure("Health check failed: " + std::string(status.error_message()));
        }

        // Deserialize response
        wire::HealthCheckResponse resp;
        auto deserialize_status = CustomCodec::deserialize_response(&response_buffer, resp);
        if (!deserialize_status.ok()) {
            return Result<bool>::failure("Failed to deserialize health check response: " +
                                         std::string(deserialize_status.error_message()));
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

} // namespace lockey::verify

#endif // LOCKEY_HAS_VERIFY
