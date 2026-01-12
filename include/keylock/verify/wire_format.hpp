#pragma once

#include <chrono>
#include <cstdint>
#include <string>
#include <vector>

namespace keylock::verify::wire {

    // Protocol version
    constexpr uint8_t VERSION = 0x01;

    // Magic bytes for protocol identification
    constexpr uint8_t MAGIC[4] = {'L', 'K', 'E', 'Y'};

    // Message types
    enum class MessageType : uint8_t {
        VERIFY_REQUEST = 0x01,
        VERIFY_RESPONSE = 0x02,
        BATCH_REQUEST = 0x03,
        BATCH_RESPONSE = 0x04,
        HEALTH_CHECK = 0x05,
        HEALTH_RESPONSE = 0x06
    };

    // Verification status codes
    enum class VerifyStatus : uint8_t {
        GOOD = 0x00,    // Certificate is valid
        REVOKED = 0x01, // Certificate is revoked
        UNKNOWN = 0x02  // Certificate status unknown
    };

    // Request flags
    enum class RequestFlags : uint8_t { NONE = 0x00, INCLUDE_RESPONDER_CERT = 0x01 };

    inline RequestFlags operator|(RequestFlags lhs, RequestFlags rhs) {
        return static_cast<RequestFlags>(static_cast<uint8_t>(lhs) | static_cast<uint8_t>(rhs));
    }

    inline RequestFlags operator&(RequestFlags lhs, RequestFlags rhs) {
        return static_cast<RequestFlags>(static_cast<uint8_t>(lhs) & static_cast<uint8_t>(rhs));
    }

    // Single certificate in a chain
    struct CertificateData {
        std::vector<uint8_t> der_bytes;
    };

    // Verification request
    // Wire format: [magic][version][type][chain_count][certs...][timestamp][flags][nonce]
    struct VerifyRequest {
        std::vector<CertificateData> certificate_chain;
        std::chrono::system_clock::time_point validation_timestamp;
        RequestFlags flags{RequestFlags::NONE};
        std::vector<uint8_t> nonce; // 32 bytes for replay protection

        VerifyRequest() = default;

        VerifyRequest(std::vector<CertificateData> chain, std::chrono::system_clock::time_point timestamp,
                      RequestFlags flags_val = RequestFlags::NONE)
            : certificate_chain(std::move(chain)), validation_timestamp(timestamp), flags(flags_val) {
            // Generate 32-byte random nonce
            nonce.resize(32);
            // Will be filled by serializer with random data
        }
    };

    // Verification response
    // Wire format:
    // [magic][version][type][status][reason_len][reason][revocation_time][signature][nonce][responder_cert_len][responder_cert]
    struct VerifyResponse {
        VerifyStatus status{VerifyStatus::UNKNOWN};
        std::string reason;
        std::chrono::system_clock::time_point revocation_time;
        std::chrono::system_clock::time_point this_update;
        std::chrono::system_clock::time_point next_update;
        std::vector<uint8_t> signature;          // Ed25519 signature (64 bytes)
        std::vector<uint8_t> nonce;              // Echo from request (32 bytes)
        std::vector<uint8_t> responder_cert_der; // Optional responder certificate

        VerifyResponse() = default;
    };

    // Batch verification request
    struct BatchVerifyRequest {
        std::vector<VerifyRequest> requests;

        BatchVerifyRequest() = default;

        explicit BatchVerifyRequest(std::vector<VerifyRequest> reqs) : requests(std::move(reqs)) {}
    };

    // Batch verification response
    struct BatchVerifyResponse {
        std::vector<VerifyResponse> responses;

        BatchVerifyResponse() = default;

        explicit BatchVerifyResponse(std::vector<VerifyResponse> resps) : responses(std::move(resps)) {}
    };

    // Health check request
    struct HealthCheckRequest {
        // Empty for now
    };

    // Health check response
    struct HealthCheckResponse {
        enum class ServingStatus : uint8_t { UNKNOWN = 0x00, SERVING = 0x01, NOT_SERVING = 0x02 };

        ServingStatus status{ServingStatus::UNKNOWN};
    };

    // Serialization/Deserialization interface
    class Serializer {
      public:
        // Serialize requests
        static std::vector<uint8_t> serialize(const VerifyRequest &request);
        static std::vector<uint8_t> serialize(const BatchVerifyRequest &request);
        static std::vector<uint8_t> serialize(const HealthCheckRequest &request);

        // Serialize responses
        static std::vector<uint8_t> serialize(const VerifyResponse &response);
        static std::vector<uint8_t> serialize(const BatchVerifyResponse &response);
        static std::vector<uint8_t> serialize(const HealthCheckResponse &response);

        // Deserialize requests
        static bool deserialize(const std::vector<uint8_t> &data, VerifyRequest &out);
        static bool deserialize(const std::vector<uint8_t> &data, BatchVerifyRequest &out);
        static bool deserialize(const std::vector<uint8_t> &data, HealthCheckRequest &out);

        // Deserialize responses
        static bool deserialize(const std::vector<uint8_t> &data, VerifyResponse &out);
        static bool deserialize(const std::vector<uint8_t> &data, BatchVerifyResponse &out);
        static bool deserialize(const std::vector<uint8_t> &data, HealthCheckResponse &out);

      private:
        // Helper methods for serialization primitives
        static void write_uint8(std::vector<uint8_t> &buffer, uint8_t value);
        static void write_uint16(std::vector<uint8_t> &buffer, uint16_t value);
        static void write_uint32(std::vector<uint8_t> &buffer, uint32_t value);
        static void write_uint64(std::vector<uint8_t> &buffer, uint64_t value);
        static void write_bytes(std::vector<uint8_t> &buffer, const std::vector<uint8_t> &data);
        static void write_string(std::vector<uint8_t> &buffer, const std::string &str);
        static void write_timestamp(std::vector<uint8_t> &buffer, const std::chrono::system_clock::time_point &time);

        // Helper methods for deserialization primitives
        static bool read_uint8(const std::vector<uint8_t> &buffer, size_t &pos, uint8_t &out);
        static bool read_uint16(const std::vector<uint8_t> &buffer, size_t &pos, uint16_t &out);
        static bool read_uint32(const std::vector<uint8_t> &buffer, size_t &pos, uint32_t &out);
        static bool read_uint64(const std::vector<uint8_t> &buffer, size_t &pos, uint64_t &out);
        static bool read_bytes(const std::vector<uint8_t> &buffer, size_t &pos, size_t length,
                               std::vector<uint8_t> &out);
        static bool read_string(const std::vector<uint8_t> &buffer, size_t &pos, size_t length, std::string &out);
        static bool read_timestamp(const std::vector<uint8_t> &buffer, size_t &pos,
                                   std::chrono::system_clock::time_point &out);

        // Validation helpers
        static bool validate_header(const std::vector<uint8_t> &buffer, size_t &pos, MessageType expected_type);
    };

} // namespace keylock::verify::wire
