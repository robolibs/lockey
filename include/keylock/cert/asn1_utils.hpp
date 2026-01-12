#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

#include <keylock/cert/asn1_common.hpp>

namespace keylock::cert {

    using ByteSpan = std::span<const uint8_t>;

    template <typename T> struct ASN1Result {
        bool success{};
        T value{};
        size_t bytes_consumed{};
        std::string error{};

        static ASN1Result<T> failure(std::string message) { return ASN1Result<T>{false, {}, 0, std::move(message)}; }

        static ASN1Result<T> ok(T value, size_t consumed) {
            return ASN1Result<T>{true, std::move(value), consumed, {}};
        }
    };

    struct ParsedHeader {
        ASN1Identifier identifier{};
        size_t length{};
        size_t header_bytes{};
    };

    struct BitStringView {
        uint8_t unused_bits{};
        ByteSpan bytes{};
    };

    ASN1Result<ParsedHeader> parse_id_len(ByteSpan input);
    ASN1Result<size_t> get_length(ByteSpan input);

    ASN1Result<ByteSpan> parse_integer(ByteSpan input);
    ASN1Result<BitStringView> parse_bit_string(ByteSpan input);
    ASN1Result<ByteSpan> parse_octet_string(ByteSpan input);
    ASN1Result<Oid> parse_oid(ByteSpan input);
    ASN1Result<ByteSpan> parse_sequence(ByteSpan input);
    ASN1Result<ByteSpan> parse_set(ByteSpan input);
    ASN1Result<bool> parse_boolean(ByteSpan input);
    ASN1Result<std::chrono::system_clock::time_point> parse_utc_time(ByteSpan input);
    ASN1Result<std::chrono::system_clock::time_point> parse_generalized_time(ByteSpan input);
    ASN1Result<std::string> parse_directory_string(ByteSpan input);

} // namespace keylock::cert
