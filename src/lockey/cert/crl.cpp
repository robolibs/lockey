#include <lockey/cert/crl.hpp>

#include <algorithm>

#include <lockey/cert/asn1_utils.hpp>
#include <lockey/cert/oid_registry.hpp>
#include <lockey/cert/pem.hpp>
#include <lockey/crypto/context.hpp>
#include <lockey/io/files.hpp>

namespace lockey::cert {

namespace {

class DerCursor {
  public:
    explicit DerCursor(ByteSpan data) : data_(data) {}
    ByteSpan remaining() const { return data_.subspan(offset_); }
    bool empty() const { return offset_ >= data_.size(); }
    bool advance(size_t bytes) {
        if (offset_ + bytes > data_.size()) {
            return false;
        }
        offset_ += bytes;
        return true;
    }

  private:
    ByteSpan data_;
    size_t offset_{0};
};

std::vector<uint8_t> copy_span(ByteSpan span) {
    return std::vector<uint8_t>(span.begin(), span.end());
}

ASN1Result<DistinguishedName> parse_name(ByteSpan input) {
    auto seq = parse_sequence(input);
    if (!seq.success) {
        return ASN1Result<DistinguishedName>::failure(seq.error);
    }
    auto encoded = copy_span(input.first(seq.bytes_consumed));
    DistinguishedName dn(encoded);
    return ASN1Result<DistinguishedName>::ok(dn, seq.bytes_consumed);
}

ASN1Result<AlgorithmIdentifier> parse_algorithm_identifier(ByteSpan input) {
    auto seq_result = parse_sequence(input);
    if (!seq_result.success) {
        return ASN1Result<AlgorithmIdentifier>::failure(seq_result.error);
    }
    DerCursor cursor(seq_result.value);
    auto oid_result = parse_oid(cursor.remaining());
    if (!oid_result.success) {
        return ASN1Result<AlgorithmIdentifier>::failure(oid_result.error);
    }
    cursor.advance(oid_result.bytes_consumed);

    AlgorithmIdentifier identifier{};
    identifier.signature = find_sig_alg_by_oid(oid_result.value);
    if (auto hash_alg = find_hash_by_oid(oid_result.value)) {
        identifier.hash = *hash_alg;
    }
    return ASN1Result<AlgorithmIdentifier>::ok(identifier, seq_result.bytes_consumed);
}

ASN1Result<std::chrono::system_clock::time_point> parse_time(ByteSpan input) {
    if (input.empty()) {
        return ASN1Result<std::chrono::system_clock::time_point>::failure("empty time");
    }
    const uint8_t first = input[0];
    if ((first & 0x1FU) == static_cast<uint8_t>(ASN1Tag::UTCTime)) {
        return parse_utc_time(input);
    }
    if ((first & 0x1FU) == static_cast<uint8_t>(ASN1Tag::GeneralizedTime)) {
        return parse_generalized_time(input);
    }
    return ASN1Result<std::chrono::system_clock::time_point>::failure("unsupported time");
}

std::optional<CrlReason> parse_reason(ByteSpan ext) {
    if (ext.size() != 3 || ext[0] != static_cast<uint8_t>(ASN1Tag::Enumerated) || ext[1] != 0x01) {
        return std::nullopt;
    }
    auto value = ext[2];
    switch (value) {
    case 0:
        return CrlReason::Unspecified;
    case 1:
        return CrlReason::KeyCompromise;
    case 2:
        return CrlReason::CaCompromise;
    case 3:
        return CrlReason::AffiliationChanged;
    case 4:
        return CrlReason::Superseded;
    case 5:
        return CrlReason::CessationOfOperation;
    case 6:
        return CrlReason::CertificateHold;
    case 8:
        return CrlReason::RemoveFromCrl;
    case 9:
        return CrlReason::PrivilegeWithdrawn;
    case 10:
        return CrlReason::AaCompromise;
    default:
        return std::nullopt;
    }
}

} // namespace

CertificateResult<Crl> parse_crl(ByteSpan der) {
    auto top = parse_sequence(der);
    if (!top.success) {
        return CertificateResult<Crl>::failure(top.error);
    }

    DerCursor top_cursor(top.value);
    auto tbs_seq = parse_sequence(top_cursor.remaining());
    if (!tbs_seq.success) {
        return CertificateResult<Crl>::failure(tbs_seq.error);
    }
    ByteSpan tbs_bytes = top_cursor.remaining().first(tbs_seq.bytes_consumed);
    top_cursor.advance(tbs_seq.bytes_consumed);

    auto sig_alg = parse_algorithm_identifier(top_cursor.remaining());
    if (!sig_alg.success) {
        return CertificateResult<Crl>::failure(sig_alg.error);
    }
    top_cursor.advance(sig_alg.bytes_consumed);

    auto sig_value = parse_bit_string(top_cursor.remaining());
    if (!sig_value.success) {
        return CertificateResult<Crl>::failure(sig_value.error);
    }

    Crl crl{};
    crl.der.assign(der.begin(), der.end());
    crl.tbs_der = copy_span(tbs_bytes);
    crl.signature_value.assign(sig_value.value.bytes.begin(), sig_value.value.bytes.end());

    DerCursor cursor(tbs_seq.value);
    auto version_header = parse_id_len(cursor.remaining());
    if (!version_header.success) {
        return CertificateResult<Crl>::failure(version_header.error);
    }
    if (version_header.value.identifier.tag_class == ASN1Class::ContextSpecific &&
        version_header.value.identifier.tag_number == 0) {
        auto version_int = parse_integer(cursor.remaining());
        if (!version_int.success) {
            return CertificateResult<Crl>::failure(version_int.error);
        }
        int version = 0;
        for (auto byte : version_int.value) {
            version = (version << 8) | byte;
        }
        crl.version = version + 1;
        cursor.advance(version_int.bytes_consumed);
    } else {
        crl.version = 1;
    }

    auto sig = parse_algorithm_identifier(cursor.remaining());
    if (!sig.success) {
        return CertificateResult<Crl>::failure(sig.error);
    }
    crl.signature = sig.value;
    cursor.advance(sig.bytes_consumed);

    auto issuer = parse_name(cursor.remaining());
    if (!issuer.success) {
        return CertificateResult<Crl>::failure(issuer.error);
    }
    crl.issuer = issuer.value;
    cursor.advance(issuer.bytes_consumed);

    auto this_update = parse_time(cursor.remaining());
    if (!this_update.success) {
        return CertificateResult<Crl>::failure(this_update.error);
    }
    crl.this_update = this_update.value;
    cursor.advance(this_update.bytes_consumed);

    auto next_update = parse_time(cursor.remaining());
    if (next_update.success) {
        crl.next_update = next_update.value;
        cursor.advance(next_update.bytes_consumed);
    }

    auto revoked_seq = parse_sequence(cursor.remaining());
    if (revoked_seq.success) {
        DerCursor revoked_cursor(revoked_seq.value);
        while (!revoked_cursor.empty()) {
            auto entry_seq = parse_sequence(revoked_cursor.remaining());
            if (!entry_seq.success) {
                break;
            }
            DerCursor entry_cursor(entry_seq.value);
            RevokedCertificate rc{};
            auto serial = parse_integer(entry_cursor.remaining());
            if (!serial.success) {
                return CertificateResult<Crl>::failure(serial.error);
            }
            rc.serial_number.assign(serial.value.begin(), serial.value.end());
            entry_cursor.advance(serial.bytes_consumed);

            auto revocation_time = parse_time(entry_cursor.remaining());
            if (!revocation_time.success) {
                return CertificateResult<Crl>::failure(revocation_time.error);
            }
            rc.revocation_date = revocation_time.value;
            entry_cursor.advance(revocation_time.bytes_consumed);

            if (!entry_cursor.empty()) {
                auto extensions = parse_sequence(entry_cursor.remaining());
                if (extensions.success) {
                    DerCursor ext_cursor(extensions.value);
                    while (!ext_cursor.empty()) {
                        auto ext_seq = parse_sequence(ext_cursor.remaining());
                        if (!ext_seq.success) {
                            break;
                        }
                        DerCursor ext_fields(ext_seq.value);
                        auto oid = parse_oid(ext_fields.remaining());
                        if (!oid.success) {
                            break;
                        }
                        ext_fields.advance(oid.bytes_consumed);
                        auto value = parse_octet_string(ext_fields.remaining());
                        if (!value.success) {
                            break;
                        }
                        if (oid.value.nodes == std::vector<uint32_t>{2, 5, 29, 21}) {
                            auto reason = parse_reason(value.value);
                            if (reason) {
                                rc.reason = reason;
                            }
                        } else if (oid.value.nodes == std::vector<uint32_t>{2, 5, 29, 24}) {
                            auto time = parse_generalized_time(value.value);
                            if (time.success) {
                                rc.invalidity_date = time.value;
                            }
                        }
                        ext_cursor.advance(ext_seq.bytes_consumed);
                    }
                    entry_cursor.advance(extensions.bytes_consumed);
                }
            }

            crl.revoked.push_back(std::move(rc));
            revoked_cursor.advance(entry_seq.bytes_consumed);
        }
        cursor.advance(revoked_seq.bytes_consumed);
    }

    crl.outer_signature = sig_alg.value;

    return CertificateResult<Crl>::ok(std::move(crl));
}

CertificateResult<Crl> load_crl(const std::string &path) {
    auto file = io::read_binary(path);
    if (!file.success) {
        return CertificateResult<Crl>::failure(file.error_message);
    }
    const std::string_view contents(reinterpret_cast<const char *>(file.data.data()), file.data.size());
    if (contents.find("-----BEGIN") != std::string_view::npos) {
        auto pem = pem_decode(contents, "CRL");
        if (!pem.success) {
            return CertificateResult<Crl>::failure(pem.error);
        }
        return parse_crl(ByteSpan(pem.block.data.data(), pem.block.data.size()));
    }
    return parse_crl(ByteSpan(file.data.data(), file.data.size()));
}

CertificateBoolResult Crl::verify_signature(const Certificate &issuer) const {
    if (outer_signature.signature != SignatureAlgorithmId::Ed25519) {
        return CertificateBoolResult::failure("Unsupported signature algorithm for CRL");
    }
    crypto::Lockey verifier(crypto::Lockey::Algorithm::Ed25519);
    auto result = verifier.verify(tbs_der, signature_value, issuer.tbs().subject_public_key_info.public_key);
    if (!result.success) {
        return CertificateBoolResult::failure(result.error_message);
    }
    return CertificateBoolResult::ok(result.success);
}

} // namespace lockey::cert
