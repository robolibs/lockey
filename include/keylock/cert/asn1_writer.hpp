#pragma once

#include <chrono>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include <keylock/cert/asn1_common.hpp>
#include <keylock/cert/asn1_utils.hpp>

namespace keylock::cert::der {

    std::vector<uint8_t> encode_tlv(ASN1Class cls, bool constructed, uint32_t tag, ByteSpan content);
    std::vector<uint8_t> encode_sequence(const std::vector<uint8_t> &content);
    std::vector<uint8_t> encode_set(const std::vector<uint8_t> &content);
    std::vector<uint8_t> encode_integer(const std::vector<uint8_t> &value);
    std::vector<uint8_t> encode_integer(uint64_t value);
    std::vector<uint8_t> encode_bit_string(ByteSpan bits, uint8_t unused_bits = 0);
    std::vector<uint8_t> encode_octet_string(ByteSpan bytes);
    std::vector<uint8_t> encode_boolean(bool value);
    std::vector<uint8_t> encode_oid(const Oid &oid);
    std::vector<uint8_t> encode_utf8_string(std::string_view str);
    std::vector<uint8_t> encode_printable_string(std::string_view str);
    std::vector<uint8_t> encode_ia5_string(std::string_view str);
    std::vector<uint8_t> encode_utctime(const std::string &view);
    std::vector<uint8_t> encode_generalized_time(const std::string &view);

    std::string format_time(std::chrono::system_clock::time_point tp, bool utc_time);
    std::vector<uint8_t> serialize_time(std::chrono::system_clock::time_point tp);

    std::vector<uint8_t> concat(const std::vector<std::vector<uint8_t>> &parts);

} // namespace keylock::cert::der
