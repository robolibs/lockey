#pragma once

#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include <keylock/cert/asn1_utils.hpp>

namespace keylock::cert {

    struct PemBlock {
        std::string label;
        std::vector<uint8_t> data;
    };

    struct PemResult {
        bool success{};
        PemBlock block{};
        std::string error{};
    };

    PemResult pem_decode(std::string_view pem, std::optional<std::string_view> expected_label = std::nullopt);
    std::string pem_encode(ByteSpan der, std::string_view label, size_t line_length = 64);

    PemResult pem_decode_certificate(std::string_view pem);
    PemResult pem_decode_private_key(std::string_view pem);
    std::string pem_encode_certificate(ByteSpan der);
    std::string pem_encode_private_key(ByteSpan der);

} // namespace keylock::cert
