#include <keylock/cert/crl.hpp>

#include <algorithm>
#include <cstring>

#include <keylock/cert/asn1_utils.hpp>
#include <keylock/cert/oid_registry.hpp>
#include <keylock/cert/pem.hpp>
#include <keylock/crypto/context.hpp>
#include <keylock/io/files.hpp>

namespace keylock::cert {

    namespace {

        // Helper class for cursor-based parsing
        class DerCursor {
          public:
            explicit DerCursor(ByteSpan data) : data_(data) {}

            [[nodiscard]] ByteSpan remaining() const { return data_.subspan(offset_); }

            [[nodiscard]] bool empty() const { return offset_ >= data_.size(); }

            [[nodiscard]] size_t offset() const { return offset_; }

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

        std::vector<uint8_t> copy_span(ByteSpan span) { return std::vector<uint8_t>(span.begin(), span.end()); }

        // Parse X.500 Name (DistinguishedName)
        ASN1Result<DistinguishedName> parse_name(ByteSpan input) {
            auto seq = parse_sequence(input);
            if (!seq.success) {
                return ASN1Result<DistinguishedName>::failure(seq.error);
            }
            auto encoded = copy_span(input.first(seq.bytes_consumed));
            DistinguishedName dn(encoded);
            return ASN1Result<DistinguishedName>::ok(dn, seq.bytes_consumed);
        }

        // Parse AlgorithmIdentifier
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

        // Parse Time (UTCTime or GeneralizedTime)
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

            return ASN1Result<std::chrono::system_clock::time_point>::failure("unsupported time type");
        }

        // Parse CRL Reason enumerated value
        std::optional<CrlReason> parse_reason_code(ByteSpan ext) {
            // ReasonCode is encoded as: ENUMERATED (1 byte length, 1 byte value)
            if (ext.size() != 3 || ext[0] != static_cast<uint8_t>(ASN1Tag::Enumerated) || ext[1] != 0x01) {
                return std::nullopt;
            }

            uint8_t value = ext[2];
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

        // Map OID to CRL Entry Extension ID
        CrlEntryExtensionId identify_crl_entry_extension(const Oid &oid) {
            // ReasonCode: 2.5.29.21
            if (oid.nodes == std::vector<uint32_t>{2, 5, 29, 21}) {
                return CrlEntryExtensionId::ReasonCode;
            }
            // InvalidityDate: 2.5.29.24
            if (oid.nodes == std::vector<uint32_t>{2, 5, 29, 24}) {
                return CrlEntryExtensionId::InvalidityDate;
            }
            // CertificateIssuer: 2.5.29.29
            if (oid.nodes == std::vector<uint32_t>{2, 5, 29, 29}) {
                return CrlEntryExtensionId::CertificateIssuer;
            }
            return CrlEntryExtensionId::Unknown;
        }

        // Map OID to CRL Extension ID
        CrlExtensionId identify_crl_extension(const Oid &oid) {
            // AuthorityKeyIdentifier: 2.5.29.35
            if (oid.nodes == std::vector<uint32_t>{2, 5, 29, 35}) {
                return CrlExtensionId::AuthorityKeyIdentifier;
            }
            // IssuerAltName: 2.5.29.18
            if (oid.nodes == std::vector<uint32_t>{2, 5, 29, 18}) {
                return CrlExtensionId::IssuerAltName;
            }
            // CRLNumber: 2.5.29.20
            if (oid.nodes == std::vector<uint32_t>{2, 5, 29, 20}) {
                return CrlExtensionId::CRLNumber;
            }
            // DeltaCRLIndicator: 2.5.29.27
            if (oid.nodes == std::vector<uint32_t>{2, 5, 29, 27}) {
                return CrlExtensionId::DeltaCRLIndicator;
            }
            // IssuingDistributionPoint: 2.5.29.28
            if (oid.nodes == std::vector<uint32_t>{2, 5, 29, 28}) {
                return CrlExtensionId::IssuingDistributionPoint;
            }
            // FreshestCRL: 2.5.29.46
            if (oid.nodes == std::vector<uint32_t>{2, 5, 29, 46}) {
                return CrlExtensionId::FreshestCRL;
            }
            // AuthorityInfoAccess: 1.3.6.1.5.5.7.1.1
            if (oid.nodes == std::vector<uint32_t>{1, 3, 6, 1, 5, 5, 7, 1, 1}) {
                return CrlExtensionId::AuthorityInfoAccess;
            }
            // ExpiredCertsOnCRL: 2.5.29.60
            if (oid.nodes == std::vector<uint32_t>{2, 5, 29, 60}) {
                return CrlExtensionId::ExpiredCertsOnCRL;
            }
            return CrlExtensionId::Unknown;
        }

        // Parse CRL Entry Extensions (within a revoked certificate entry)
        ASN1Result<std::vector<CrlEntryExtension>> parse_crl_entry_extensions(ByteSpan input, RevokedCertificate &rc) {
            std::vector<CrlEntryExtension> extensions;

            auto seq = parse_sequence(input);
            if (!seq.success) {
                return ASN1Result<std::vector<CrlEntryExtension>>::failure(seq.error);
            }

            DerCursor cursor(seq.value);
            while (!cursor.empty()) {
                auto ext_seq = parse_sequence(cursor.remaining());
                if (!ext_seq.success) {
                    break;
                }

                DerCursor ext_cursor(ext_seq.value);

                // Parse OID
                auto oid_result = parse_oid(ext_cursor.remaining());
                if (!oid_result.success) {
                    break;
                }
                ext_cursor.advance(oid_result.bytes_consumed);

                // Parse optional critical flag
                bool critical = false;
                auto bool_result = parse_boolean(ext_cursor.remaining());
                if (bool_result.success && bool_result.value) {
                    critical = true;
                    ext_cursor.advance(bool_result.bytes_consumed);
                }

                // Parse extension value (OCTET STRING)
                auto value_result = parse_octet_string(ext_cursor.remaining());
                if (!value_result.success) {
                    break;
                }

                CrlEntryExtension ext;
                ext.oid = oid_result.value;
                ext.id = identify_crl_entry_extension(oid_result.value);
                ext.critical = critical;
                ext.value = copy_span(value_result.value);

                // Parse specific extension types
                switch (ext.id) {
                case CrlEntryExtensionId::ReasonCode: {
                    auto reason = parse_reason_code(value_result.value);
                    if (reason) {
                        rc.reason = *reason;
                    }
                    break;
                }
                case CrlEntryExtensionId::InvalidityDate: {
                    auto time = parse_generalized_time(value_result.value);
                    if (time.success) {
                        rc.invalidity_date = time.value;
                    }
                    break;
                }
                case CrlEntryExtensionId::CertificateIssuer: {
                    // CertificateIssuer is a GeneralNames sequence
                    // For simplicity, we'll try to parse it as a Name
                    auto name = parse_name(value_result.value);
                    if (name.success) {
                        rc.certificate_issuer = name.value;
                    }
                    break;
                }
                default:
                    break;
                }

                extensions.push_back(std::move(ext));
                cursor.advance(ext_seq.bytes_consumed);
            }

            return ASN1Result<std::vector<CrlEntryExtension>>::ok(std::move(extensions), seq.bytes_consumed);
        }

        // Parse CRL Extensions (at CRL level)
        ASN1Result<std::vector<CrlExtension>> parse_crl_extensions(ByteSpan input, Crl &crl) {
            std::vector<CrlExtension> extensions;

            // CRL extensions are wrapped in [0] EXPLICIT
            auto explicit_result = parse_id_len(input);
            if (!explicit_result.success) {
                return ASN1Result<std::vector<CrlExtension>>::failure(explicit_result.error);
            }

            if (explicit_result.value.identifier.tag_class != ASN1Class::ContextSpecific ||
                explicit_result.value.identifier.tag_number != 0) {
                return ASN1Result<std::vector<CrlExtension>>::failure(
                    "expected context-specific [0] tag for CRL extensions");
            }

            size_t explicit_consumed = explicit_result.bytes_consumed;
            ByteSpan explicit_content = input.subspan(explicit_result.value.header_bytes, explicit_result.value.length);

            auto seq = parse_sequence(explicit_content);
            if (!seq.success) {
                return ASN1Result<std::vector<CrlExtension>>::failure(seq.error);
            }

            DerCursor cursor(seq.value);
            while (!cursor.empty()) {
                auto ext_seq = parse_sequence(cursor.remaining());
                if (!ext_seq.success) {
                    break;
                }

                DerCursor ext_cursor(ext_seq.value);

                // Parse OID
                auto oid_result = parse_oid(ext_cursor.remaining());
                if (!oid_result.success) {
                    break;
                }
                ext_cursor.advance(oid_result.bytes_consumed);

                // Parse optional critical flag
                bool critical = false;
                auto bool_result = parse_boolean(ext_cursor.remaining());
                if (bool_result.success && bool_result.value) {
                    critical = true;
                    ext_cursor.advance(bool_result.bytes_consumed);
                }

                // Parse extension value (OCTET STRING)
                auto value_result = parse_octet_string(ext_cursor.remaining());
                if (!value_result.success) {
                    break;
                }

                CrlExtension ext;
                ext.oid = oid_result.value;
                ext.id = identify_crl_extension(oid_result.value);
                ext.critical = critical;
                ext.value = copy_span(value_result.value);

                // Parse specific extension types
                switch (ext.id) {
                case CrlExtensionId::AuthorityKeyIdentifier: {
                    // AKI contains SEQUENCE with [0] IMPLICIT OCTET STRING
                    auto aki_seq = parse_sequence(value_result.value);
                    if (aki_seq.success) {
                        // Look for [0] tag (keyIdentifier)
                        if (!aki_seq.value.empty() && (aki_seq.value[0] & 0x1F) == 0) {
                            DerCursor aki_cursor(aki_seq.value);
                            auto ki_result = parse_id_len(aki_cursor.remaining());
                            if (ki_result.success &&
                                ki_result.value.identifier.tag_class == ASN1Class::ContextSpecific &&
                                ki_result.value.identifier.tag_number == 0) {
                                ByteSpan ki_data = aki_cursor.remaining().subspan(ki_result.value.header_bytes,
                                                                                  ki_result.value.length);
                                crl.authority_key_identifier = copy_span(ki_data);
                            }
                        }
                    }
                    break;
                }
                case CrlExtensionId::CRLNumber: {
                    // CRL Number is an INTEGER
                    auto int_result = parse_integer(value_result.value);
                    if (int_result.success) {
                        crl.crl_number = copy_span(int_result.value);
                    }
                    break;
                }
                case CrlExtensionId::DeltaCRLIndicator: {
                    // Delta CRL Indicator is an INTEGER (base CRL number)
                    auto int_result = parse_integer(value_result.value);
                    if (int_result.success) {
                        crl.delta_crl_indicator = copy_span(int_result.value);
                    }
                    break;
                }
                case CrlExtensionId::IssuingDistributionPoint: {
                    crl.has_issuing_distribution_point = true;
                    break;
                }
                default:
                    break;
                }

                extensions.push_back(std::move(ext));
                cursor.advance(ext_seq.bytes_consumed);
            }

            return ASN1Result<std::vector<CrlExtension>>::ok(std::move(extensions), explicit_consumed);
        }

    } // anonymous namespace

    // Main CRL parsing function
    CertificateResult<Crl> parse_crl(ByteSpan der, bool relaxed) {
        // Parse outer SEQUENCE (CertificateList)
        auto top = parse_sequence(der);
        if (!top.success) {
            return CertificateResult<Crl>::failure("CRL outer sequence: " + top.error);
        }

        DerCursor top_cursor(top.value);

        // Parse tbsCertList SEQUENCE
        auto tbs_seq = parse_sequence(top_cursor.remaining());
        if (!tbs_seq.success) {
            return CertificateResult<Crl>::failure(tbs_seq.error);
        }
        ByteSpan tbs_bytes = top_cursor.remaining().first(tbs_seq.bytes_consumed);
        top_cursor.advance(tbs_seq.bytes_consumed);

        // Parse signatureAlgorithm
        auto sig_alg = parse_algorithm_identifier(top_cursor.remaining());
        if (!sig_alg.success) {
            return CertificateResult<Crl>::failure(sig_alg.error);
        }
        top_cursor.advance(sig_alg.bytes_consumed);

        // Parse signatureValue (BIT STRING)
        auto sig_value = parse_bit_string(top_cursor.remaining());
        if (!sig_value.success) {
            return CertificateResult<Crl>::failure(sig_value.error);
        }

        // Check for trailing data (unless in relaxed mode)
        if (!relaxed && !top_cursor.empty() && (top_cursor.offset() + sig_value.bytes_consumed != top.value.size())) {
            return CertificateResult<Crl>::failure("unexpected trailing data in CRL");
        }

        // Initialize CRL structure
        Crl crl{};
        crl.der = copy_span(der.first(top.bytes_consumed));
        crl.tbs_der = copy_span(tbs_bytes);
        crl.signature_value = copy_span(sig_value.value.bytes);
        crl.outer_signature = sig_alg.value;

        // Parse tbsCertList fields
        DerCursor tbs_cursor(tbs_seq.value);

        // Parse optional version
        // RFC 5280: version is OPTIONAL, if present MUST be v2 (INTEGER 1)
        // However, some implementations incorrectly wrap it in [0] EXPLICIT (like certificates)
        // We support both for compatibility
        auto version_header = parse_id_len(tbs_cursor.remaining());
        if (version_header.success) {
            if (version_header.value.identifier.tag_class == ASN1Class::ContextSpecific &&
                version_header.value.identifier.tag_number == 0) {
                // Incorrectly wrapped in [0] EXPLICIT - parse the inner INTEGER
                ByteSpan version_content =
                    tbs_cursor.remaining().subspan(version_header.value.header_bytes, version_header.value.length);
                auto version_int = parse_integer(version_content);
                if (version_int.success) {
                    int version = 0;
                    for (auto byte : version_int.value) {
                        version = (version << 8) | byte;
                    }
                    crl.version = version + 1; // Version encoding: 0 = v1, 1 = v2
                }
                tbs_cursor.advance(version_header.bytes_consumed);
            } else if (version_header.value.identifier.tag_class == ASN1Class::Universal &&
                       version_header.value.identifier.tag_number == static_cast<uint32_t>(ASN1Tag::Integer)) {
                // Correctly encoded as plain INTEGER
                auto version_int = parse_integer(tbs_cursor.remaining());
                if (version_int.success) {
                    int version = 0;
                    for (auto byte : version_int.value) {
                        version = (version << 8) | byte;
                    }
                    crl.version = version + 1; // Version encoding: 0 = v1, 1 = v2
                    tbs_cursor.advance(version_int.bytes_consumed);
                }
            }
            // Otherwise it's not a version field, continue parsing
        }

        // Parse signature algorithm (inner, from tbsCertList)
        auto inner_sig = parse_algorithm_identifier(tbs_cursor.remaining());
        if (!inner_sig.success) {
            return CertificateResult<Crl>::failure(inner_sig.error);
        }
        crl.signature = inner_sig.value;
        tbs_cursor.advance(inner_sig.bytes_consumed);

        // Parse issuer Name
        auto issuer = parse_name(tbs_cursor.remaining());
        if (!issuer.success) {
            return CertificateResult<Crl>::failure(issuer.error);
        }
        crl.issuer = issuer.value;
        tbs_cursor.advance(issuer.bytes_consumed);

        // Parse thisUpdate
        auto this_update = parse_time(tbs_cursor.remaining());
        if (!this_update.success) {
            return CertificateResult<Crl>::failure(this_update.error);
        }
        crl.this_update = this_update.value;
        tbs_cursor.advance(this_update.bytes_consumed);

        // Parse optional nextUpdate
        if (!tbs_cursor.empty()) {
            auto peek = tbs_cursor.remaining()[0];
            if ((peek == static_cast<uint8_t>(ASN1Tag::UTCTime)) ||
                (peek == static_cast<uint8_t>(ASN1Tag::GeneralizedTime))) {
                auto next_update = parse_time(tbs_cursor.remaining());
                if (next_update.success) {
                    crl.next_update = next_update.value;
                    tbs_cursor.advance(next_update.bytes_consumed);
                }
            }
        }

        // Parse optional revokedCertificates SEQUENCE
        if (!tbs_cursor.empty()) {
            auto peek_header = parse_id_len(tbs_cursor.remaining());
            if (peek_header.success && peek_header.value.identifier.tag_class == ASN1Class::Universal &&
                peek_header.value.identifier.tag_number == static_cast<uint32_t>(ASN1Tag::Sequence)) {

                auto revoked_seq = parse_sequence(tbs_cursor.remaining());
                if (revoked_seq.success) {
                    DerCursor revoked_cursor(revoked_seq.value);

                    while (!revoked_cursor.empty()) {
                        auto entry_seq = parse_sequence(revoked_cursor.remaining());
                        if (!entry_seq.success) {
                            break;
                        }

                        DerCursor entry_cursor(entry_seq.value);
                        RevokedCertificate rc{};

                        // Parse serial number
                        auto serial = parse_integer(entry_cursor.remaining());
                        if (!serial.success) {
                            return CertificateResult<Crl>::failure("failed to parse revoked cert serial: " +
                                                                   serial.error);
                        }
                        rc.serial_number = copy_span(serial.value);
                        entry_cursor.advance(serial.bytes_consumed);

                        // Parse revocation time
                        auto revocation_time = parse_time(entry_cursor.remaining());
                        if (!revocation_time.success) {
                            return CertificateResult<Crl>::failure("failed to parse revocation time: " +
                                                                   revocation_time.error);
                        }
                        rc.revocation_date = revocation_time.value;
                        entry_cursor.advance(revocation_time.bytes_consumed);

                        // Parse optional crlEntryExtensions
                        if (!entry_cursor.empty()) {
                            auto ext_result = parse_crl_entry_extensions(entry_cursor.remaining(), rc);
                            if (ext_result.success) {
                                rc.extensions = std::move(ext_result.value);
                            }
                        }

                        crl.revoked.push_back(std::move(rc));
                        revoked_cursor.advance(entry_seq.bytes_consumed);
                    }

                    tbs_cursor.advance(revoked_seq.bytes_consumed);
                }
            }
        }

        // Parse optional crlExtensions [0] EXPLICIT (v2 only)
        if (!tbs_cursor.empty() && crl.version >= 2) {
            auto ext_result = parse_crl_extensions(tbs_cursor.remaining(), crl);
            if (ext_result.success) {
                crl.extensions = std::move(ext_result.value);
            }
        }

        return CertificateResult<Crl>::ok(std::move(crl));
    }

    CertificateResult<Crl> parse_crl_relaxed(ByteSpan der) { return parse_crl(der, true); }

    CertificateResult<std::vector<Crl>> parse_pem_crl_chain(std::string_view pem) {
        std::vector<Crl> crls;
        size_t pos = 0;

        while (pos < pem.size()) {
            size_t start = pem.find("-----BEGIN", pos);
            if (start == std::string_view::npos) {
                break;
            }

            auto block_result = pem_decode(pem.substr(start), "CRL");
            if (!block_result.success) {
                block_result = pem_decode(pem.substr(start), "X509 CRL");
            }

            if (!block_result.success) {
                return CertificateResult<std::vector<Crl>>::failure(block_result.error);
            }

            auto crl_result = parse_crl(ByteSpan(block_result.block.data.data(), block_result.block.data.size()));
            if (!crl_result.success) {
                return CertificateResult<std::vector<Crl>>::failure(crl_result.error);
            }

            crls.push_back(std::move(crl_result.value));

            size_t end = pem.find("-----END", start);
            if (end == std::string_view::npos) {
                break;
            }
            pos = end + 1;
        }

        if (crls.empty()) {
            return CertificateResult<std::vector<Crl>>::failure("no CRLs found in PEM");
        }

        return CertificateResult<std::vector<Crl>>::ok(std::move(crls));
    }

    CertificateResult<Crl> load_crl(const std::string &path) {
        auto file = io::read_binary(path);
        if (!file.success) {
            return CertificateResult<Crl>::failure(file.error_message);
        }

        const std::string_view contents(reinterpret_cast<const char *>(file.data.data()), file.data.size());

        // Check if it's PEM format
        if (contents.find("-----BEGIN") != std::string_view::npos) {
            auto pem = pem_decode(contents, "CRL");
            if (!pem.success) {
                pem = pem_decode(contents, "X509 CRL");
            }
            if (!pem.success) {
                return CertificateResult<Crl>::failure(pem.error);
            }
            return parse_crl(ByteSpan(pem.block.data.data(), pem.block.data.size()));
        }

        // Assume DER format
        return parse_crl(ByteSpan(file.data.data(), file.data.size()));
    }

    // Helper methods implementation
    bool Crl::is_certificate_revoked(const std::vector<uint8_t> &serial) const {
        return find_revoked_cert(serial).has_value();
    }

    std::optional<const RevokedCertificate *> Crl::find_revoked_cert(const std::vector<uint8_t> &serial) const {
        for (const auto &rc : revoked) {
            if (rc.serial_number == serial) {
                return &rc;
            }
        }
        return std::nullopt;
    }

    bool Crl::check_validity(std::optional<std::chrono::system_clock::time_point> check_time) const {
        auto now = check_time.value_or(std::chrono::system_clock::now());

        // Check if CRL is not yet valid
        if (now < this_update) {
            return false;
        }

        // Check if CRL has expired
        if (next_update.has_value() && now > *next_update) {
            return false;
        }

        return true;
    }

    std::optional<CrlExtension> Crl::find_extension(CrlExtensionId id) const {
        for (const auto &ext : extensions) {
            if (ext.id == id) {
                return ext;
            }
        }
        return std::nullopt;
    }

    CertificateBoolResult Crl::verify_signature(const Certificate &issuer) const {
        // For now, only support Ed25519
        if (outer_signature.signature != SignatureAlgorithmId::Ed25519) {
            return CertificateBoolResult::failure("Unsupported signature algorithm for CRL verification");
        }

        crypto::Context verifier(crypto::Context::Algorithm::Ed25519);
        auto result = verifier.verify(tbs_der, signature_value, issuer.tbs().subject_public_key_info.public_key);

        if (!result.success) {
            return CertificateBoolResult::failure(result.error_message);
        }

        return CertificateBoolResult::ok(result.success);
    }

} // namespace keylock::cert
