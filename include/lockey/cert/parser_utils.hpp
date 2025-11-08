#pragma once

#include <lockey/cert/asn1_utils.hpp>
#include <lockey/cert/certificate.hpp>

namespace lockey::cert::detail {

class DerCursor {
  public:
    explicit DerCursor(ByteSpan span) : data_(span) {}
    ByteSpan remaining() const { return data_.subspan(offset_); }
    bool empty() const { return offset_ >= data_.size(); }
    bool advance(size_t count) {
        if (offset_ + count > data_.size()) {
            return false;
        }
        offset_ += count;
        return true;
    }

  private:
    ByteSpan data_;
    size_t offset_{0};
};

ASN1Result<DistinguishedName> parse_name(ByteSpan input);
ASN1Result<AlgorithmIdentifier> parse_algorithm_identifier(ByteSpan input);
ASN1Result<SubjectPublicKeyInfo> parse_subject_public_key_info(ByteSpan input);
ASN1Result<std::vector<RawExtension>> parse_extensions(ByteSpan input);
ASN1Result<std::chrono::system_clock::time_point> parse_time_choice(ByteSpan input);

} // namespace lockey::cert::detail

