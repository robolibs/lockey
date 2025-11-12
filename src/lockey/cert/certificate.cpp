#include <lockey/cert/certificate.hpp>

#include <algorithm>
#include <cctype>
#include <iomanip>
#include <sstream>
#include <string_view>

#include <lockey/cert/asn1_utils.hpp>
#include <lockey/cert/asn1_writer.hpp>
#include <lockey/cert/crl.hpp>
#include <lockey/cert/parser.hpp>
#include <lockey/cert/parser_utils.hpp>
#include <lockey/cert/pem.hpp>
#include <lockey/cert/trust_store.hpp>
#include <lockey/io/files.hpp>

#ifdef LOCKEY_HAS_VERIFY
#include <lockey/verify/client.hpp>
#endif

namespace lockey::cert {

    namespace {

        Certificate make_certificate_from_context(CertificateContext &&ctx) {
            TBSCertificate tbs{};
            tbs.version = ctx.version;
            tbs.serial_number = std::move(ctx.serial_number);
            tbs.signature = ctx.tbs_signature;
            tbs.issuer = std::move(ctx.issuer);
            tbs.subject = std::move(ctx.subject);
            tbs.validity = Validity{ctx.not_before, ctx.not_after};
            tbs.subject_public_key_info = std::move(ctx.subject_public_key_info);
            tbs.extensions = std::move(ctx.extensions);

            return Certificate(std::move(tbs), ctx.outer_signature, std::move(ctx.signature_value), std::move(ctx.der),
                               std::move(ctx.tbs_certificate));
        }

        bool contains_pem_marker(std::string_view view) { return view.find("-----BEGIN") != std::string_view::npos; }

        bool contains_pem_marker(const std::vector<uint8_t> &data) {
            if (data.empty()) {
                return false;
            }
            const auto view = std::string_view(reinterpret_cast<const char *>(data.data()), data.size());
            return contains_pem_marker(view);
        }

    } // namespace

    CertificateParseResult Certificate::parse(ByteSpan der, bool relaxed) {
        if (der.empty()) {
            return CertificateParseResult::failure("empty DER buffer");
        }

        ParseResult parsed = relaxed ? parse_x509_cert_relaxed(der) : parse_x509_cert(der);
        if (!parsed.success) {
            return CertificateParseResult::failure(parsed.error);
        }
        return CertificateParseResult::ok(make_certificate_from_context(std::move(parsed.certificate)));
    }

    CertificateParseResult Certificate::parse(const std::vector<uint8_t> &der, bool relaxed) {
        return parse(ByteSpan(der.data(), der.size()), relaxed);
    }

    CertificateChainResult Certificate::parse_pem_chain(std::string_view pem, bool relaxed) {
        constexpr std::string_view kLabel = "CERTIFICATE";
        std::vector<Certificate> certificates;
        size_t cursor = 0;

        while (cursor < pem.size()) {
            const auto begin = pem.find("-----BEGIN", cursor);
            if (begin == std::string_view::npos) {
                break;
            }

            const size_t label_start = begin + std::string_view("-----BEGIN ").size();
            const auto label_end = pem.find("-----", label_start);
            if (label_end == std::string_view::npos) {
                break;
            }

            const auto found_label = pem.substr(label_start, label_end - label_start);
            if (found_label != kLabel) {
                cursor = label_end + std::string_view("-----").size();
                continue;
            }

            const auto block_view = pem.substr(begin);
            auto pem_res = pem_decode(block_view, kLabel);
            if (!pem_res.success) {
                return CertificateChainResult::failure(pem_res.error);
            }

            auto cert_res = Certificate::parse(pem_res.block.data, relaxed);
            if (!cert_res.success) {
                return CertificateChainResult::failure(cert_res.error);
            }
            certificates.push_back(std::move(cert_res.value));

            const std::string end_marker = "-----END " + std::string(kLabel) + "-----";
            const auto end_pos = pem.find(end_marker, begin);
            if (end_pos == std::string_view::npos) {
                cursor = begin + block_view.size();
                break;
            }
            cursor = end_pos + end_marker.size();
        }

        if (certificates.empty()) {
            return CertificateChainResult::failure("no certificates found in PEM data");
        }
        return CertificateChainResult::ok(std::move(certificates));
    }

    CertificateChainResult Certificate::parse_der_chain(ByteSpan der, bool relaxed) {
        std::vector<Certificate> certificates;
        size_t offset = 0;
        while (offset < der.size()) {
            const auto seq_result = parse_sequence(der.subspan(offset));
            if (!seq_result.success) {
                if (certificates.empty()) {
                    return CertificateChainResult::failure(seq_result.error);
                }
                break;
            }
            const size_t length = seq_result.bytes_consumed;
            if (length == 0 || offset + length > der.size()) {
                return CertificateChainResult::failure("truncated DER certificate");
            }

            auto cert_res = Certificate::parse(der.subspan(offset, length), relaxed);
            if (!cert_res.success) {
                return CertificateChainResult::failure(cert_res.error);
            }
            certificates.push_back(std::move(cert_res.value));
            offset += length;
        }

        if (certificates.empty()) {
            return CertificateChainResult::failure("no DER certificates found");
        }
        return CertificateChainResult::ok(std::move(certificates));
    }

    CertificateChainResult Certificate::load(const std::string &path, bool relaxed) {
        auto file = io::read_binary(path);
        if (!file.success) {
            return CertificateChainResult::failure(file.error_message);
        }
        if (file.data.empty()) {
            return CertificateChainResult::failure("certificate file is empty");
        }

        if (contains_pem_marker(file.data)) {
            std::string pem_text(reinterpret_cast<const char *>(file.data.data()), file.data.size());
            return parse_pem_chain(pem_text, relaxed);
        }

        return parse_der_chain(ByteSpan(file.data.data(), file.data.size()), relaxed);
    }

    std::string Certificate::to_pem(size_t line_length) const {
        return pem_encode(ByteSpan(der_.data(), der_.size()), "CERTIFICATE", line_length);
    }

    bool Certificate::save(const std::string &path, CertificateFormat format) const {
        if (format == CertificateFormat::DER) {
            return io::write_binary(der_, path);
        }

        const auto pem = to_pem();
        std::vector<uint8_t> pem_bytes(pem.begin(), pem.end());
        return io::write_binary(pem_bytes, path);
    }

    CertificateSignatureResult Certificate::sign(const crypto::Lockey::KeyPair &issuer_key, hash::Algorithm) const {
        if (signature_algorithm_.signature != SignatureAlgorithmId::Ed25519) {
            return CertificateSignatureResult::failure("Unsupported signature algorithm");
        }
        crypto::Lockey signer(crypto::Lockey::Algorithm::Ed25519);
        auto result = signer.sign(tbs_der_, issuer_key.private_key);
        if (!result.success) {
            return CertificateSignatureResult::failure(result.error_message);
        }
        return CertificateSignatureResult::ok(result.data);
    }

    CertificateBoolResult Certificate::verify_signature(const Certificate &issuer) const {
        if (signature_algorithm_.signature != SignatureAlgorithmId::Ed25519 ||
            issuer.tbs_.subject_public_key_info.algorithm.signature != SignatureAlgorithmId::Ed25519) {
            return CertificateBoolResult::failure("Unsupported signature algorithm for verification");
        }

        crypto::Lockey verifier(crypto::Lockey::Algorithm::Ed25519);
        auto verify_result =
            verifier.verify(tbs_der_, signature_value_, issuer.tbs_.subject_public_key_info.public_key);
        if (!verify_result.success) {
            if (verify_result.error_message == "Ed25519 signature verification failed") {
                return CertificateBoolResult::ok(false);
            }
            return CertificateBoolResult::failure(verify_result.error_message);
        }
        return CertificateBoolResult::ok(true);
    }

    bool Certificate::check_validity(std::optional<std::chrono::system_clock::time_point> check_time) const {
        auto time = check_time.value_or(std::chrono::system_clock::now());
        return tbs_.validity.contains(time);
    }
    std::optional<RawExtension> Certificate::find_extension(ExtensionId id) const {
        auto it = std::find_if(tbs_.extensions.begin(), tbs_.extensions.end(),
                               [&](const RawExtension &ext) { return ext.id == id; });
        if (it == tbs_.extensions.end()) {
            return std::nullopt;
        }
        return *it;
    }

    std::optional<bool> Certificate::basic_constraints_ca() const {
        auto ext = find_extension(ExtensionId::BasicConstraints);
        if (!ext) {
            return std::nullopt;
        }
        auto seq = parse_sequence(ByteSpan(ext->value.data(), ext->value.size()));
        if (!seq.success) {
            return std::nullopt;
        }
        detail::DerCursor cursor(seq.value);
        if (cursor.empty()) {
            return false;
        }
        auto bool_res = parse_boolean(cursor.remaining());
        if (!bool_res.success) {
            return std::nullopt;
        }
        return bool_res.value;
    }

    std::optional<uint32_t> Certificate::basic_constraints_path_length() const {
        auto ext = find_extension(ExtensionId::BasicConstraints);
        if (!ext) {
            return std::nullopt;
        }
        auto seq = parse_sequence(ByteSpan(ext->value.data(), ext->value.size()));
        if (!seq.success) {
            return std::nullopt;
        }
        detail::DerCursor cursor(seq.value);
        auto bool_res = parse_boolean(cursor.remaining());
        if (bool_res.success) {
            cursor.advance(bool_res.bytes_consumed);
        }
        if (cursor.empty()) {
            return std::nullopt;
        }
        auto int_res = parse_integer(cursor.remaining());
        if (!int_res.success) {
            return std::nullopt;
        }
        uint32_t value = 0;
        for (auto byte : int_res.value) {
            value = (value << 8U) | byte;
        }
        return value;
    }

    std::optional<uint16_t> Certificate::key_usage_bits() const {
        auto ext = find_extension(ExtensionId::KeyUsage);
        if (!ext) {
            return std::nullopt;
        }
        auto bit = parse_bit_string(ByteSpan(ext->value.data(), ext->value.size()));
        if (!bit.success) {
            return std::nullopt;
        }
        uint16_t value = 0;
        for (auto byte : bit.value.bytes) {
            value = static_cast<uint16_t>((value << 8U) | byte);
        }
        return value;
    }

    std::vector<SubjectAltNameExtension::GeneralName> Certificate::subject_alt_names() const {
        std::vector<SubjectAltNameExtension::GeneralName> names;
        auto ext = find_extension(ExtensionId::SubjectAltName);
        if (!ext) {
            return names;
        }
        auto seq = parse_sequence(ByteSpan(ext->value.data(), ext->value.size()));
        if (!seq.success) {
            return names;
        }
        size_t offset = 0;
        auto view = seq.value;
        while (offset < view.size()) {
            auto header = parse_id_len(view.subspan(offset));
            if (!header.success) {
                break;
            }
            const auto &id = header.value.identifier;
            if (id.tag_class != ASN1Class::ContextSpecific) {
                break;
            }
            auto content = view.subspan(offset + header.value.header_bytes, header.value.length);
            SubjectAltNameExtension::GeneralName name{};
            switch (id.tag_number) {
            case 1:
                name.type = SubjectAltNameExtension::GeneralNameType::Email;
                name.value.assign(reinterpret_cast<const char *>(content.data()), content.size());
                break;
            case 2:
                name.type = SubjectAltNameExtension::GeneralNameType::DNSName;
                name.value.assign(reinterpret_cast<const char *>(content.data()), content.size());
                break;
            case 6:
                name.type = SubjectAltNameExtension::GeneralNameType::URI;
                name.value.assign(reinterpret_cast<const char *>(content.data()), content.size());
                break;
            case 7:
                name.type = SubjectAltNameExtension::GeneralNameType::IPAddress;
                name.value.assign(reinterpret_cast<const char *>(content.data()), content.size());
                break;
            default:
                name.type = SubjectAltNameExtension::GeneralNameType::Other;
                name.value.assign(reinterpret_cast<const char *>(content.data()), content.size());
                break;
            }
            names.push_back(std::move(name));
            offset += header.bytes_consumed;
        }
        return names;
    }

    std::optional<ExtendedKeyUsageExtension> Certificate::extended_key_usage() const {
        auto ext = find_extension(ExtensionId::ExtendedKeyUsage);
        if (!ext) {
            return std::nullopt;
        }
        auto seq = parse_sequence(ByteSpan(ext->value.data(), ext->value.size()));
        if (!seq.success) {
            return std::nullopt;
        }
        std::vector<Oid> oids;
        size_t offset = 0;
        while (offset < seq.value.size()) {
            auto oid_res = parse_oid(seq.value.subspan(offset));
            if (!oid_res.success) {
                break;
            }
            oids.push_back(oid_res.value);
            offset += oid_res.bytes_consumed;
        }
        return ExtendedKeyUsageExtension(ext->critical, std::move(oids));
    }

    // Phase 13: Enterprise Extensions Implementation

    std::vector<IssuerAltNameExtension::GeneralName> Certificate::issuer_alt_names() const {
        std::vector<IssuerAltNameExtension::GeneralName> names;
        auto ext = find_extension(ExtensionId::IssuerAltName);
        if (!ext) {
            return names;
        }

        // IAN has same structure as SAN (GeneralNames SEQUENCE)
        auto seq = parse_sequence(ByteSpan(ext->value.data(), ext->value.size()));
        if (!seq.success) {
            return names;
        }

        size_t offset = 0;
        auto view = seq.value;
        while (offset < view.size()) {
            auto header = parse_id_len(view.subspan(offset));
            if (!header.success) {
                break;
            }
            const auto &id = header.value.identifier;
            if (id.tag_class != ASN1Class::ContextSpecific) {
                break;
            }
            auto content = view.subspan(offset + header.value.header_bytes, header.value.length);
            IssuerAltNameExtension::GeneralName name{};
            switch (id.tag_number) {
            case 1: // rfc822Name
                name.type = IssuerAltNameExtension::GeneralNameType::Email;
                name.value.assign(reinterpret_cast<const char *>(content.data()), content.size());
                break;
            case 2: // dNSName
                name.type = IssuerAltNameExtension::GeneralNameType::DNSName;
                name.value.assign(reinterpret_cast<const char *>(content.data()), content.size());
                break;
            case 6: // uniformResourceIdentifier
                name.type = IssuerAltNameExtension::GeneralNameType::URI;
                name.value.assign(reinterpret_cast<const char *>(content.data()), content.size());
                break;
            case 7: // iPAddress
                name.type = IssuerAltNameExtension::GeneralNameType::IPAddress;
                name.value.assign(reinterpret_cast<const char *>(content.data()), content.size());
                break;
            default: // otherName, x400Address, directoryName, ediPartyName, registeredID
                name.type = IssuerAltNameExtension::GeneralNameType::Other;
                name.value.assign(reinterpret_cast<const char *>(content.data()), content.size());
                break;
            }
            names.push_back(std::move(name));
            offset += header.bytes_consumed;
        }
        return names;
    }

    std::vector<PolicyMappingsExtension::PolicyMapping> Certificate::policy_mappings() const {
        std::vector<PolicyMappingsExtension::PolicyMapping> mappings;
        auto ext = find_extension(ExtensionId::PolicyMappings);
        if (!ext) {
            return mappings;
        }

        // MUST be critical per RFC 5280 (but we're lenient)
        auto seq = parse_sequence(ByteSpan(ext->value.data(), ext->value.size()));
        if (!seq.success) {
            return mappings;
        }

        size_t offset = 0;
        auto view = seq.value;
        while (offset < view.size()) {
            // Each mapping is a SEQUENCE { issuerDomainPolicy, subjectDomainPolicy }
            auto mapping_seq = parse_sequence(view.subspan(offset));
            if (!mapping_seq.success) {
                break;
            }

            size_t mapping_offset = 0;
            auto mapping_view = mapping_seq.value;

            // Parse issuerDomainPolicy (OID)
            auto issuer_oid = parse_oid(mapping_view.subspan(mapping_offset));
            if (!issuer_oid.success) {
                break;
            }
            mapping_offset += issuer_oid.bytes_consumed;

            // Parse subjectDomainPolicy (OID)
            auto subject_oid = parse_oid(mapping_view.subspan(mapping_offset));
            if (!subject_oid.success) {
                break;
            }

            PolicyMappingsExtension::PolicyMapping mapping{};
            mapping.issuer_domain_policy = issuer_oid.value.nodes;
            mapping.subject_domain_policy = subject_oid.value.nodes;
            mappings.push_back(std::move(mapping));

            offset += mapping_seq.bytes_consumed;
        }
        return mappings;
    }

    std::optional<PolicyConstraintsExtension> Certificate::policy_constraints() const {
        auto ext = find_extension(ExtensionId::PolicyConstraints);
        if (!ext) {
            return std::nullopt;
        }

        // MUST be critical per RFC 5280
        auto seq = parse_sequence(ByteSpan(ext->value.data(), ext->value.size()));
        if (!seq.success) {
            return std::nullopt;
        }

        std::optional<uint32_t> require_explicit_policy;
        std::optional<uint32_t> inhibit_policy_mapping;

        size_t offset = 0;
        auto view = seq.value;

        // Try to parse requireExplicitPolicy [0] IMPLICIT INTEGER OPTIONAL
        if (offset < view.size()) {
            auto header = parse_id_len(view.subspan(offset));
            if (header.success && header.value.identifier.tag_class == ASN1Class::ContextSpecific &&
                header.value.identifier.tag_number == 0) {
                auto content = view.subspan(offset + header.value.header_bytes, header.value.length);
                if (content.size() >= 1 && content.size() <= 4) {
                    uint32_t value = 0;
                    for (size_t i = 0; i < content.size(); ++i) {
                        value = (value << 8) | content[i];
                    }
                    require_explicit_policy = value;
                }
                offset += header.bytes_consumed;
            }
        }

        // Try to parse inhibitPolicyMapping [1] IMPLICIT INTEGER OPTIONAL
        if (offset < view.size()) {
            auto header = parse_id_len(view.subspan(offset));
            if (header.success && header.value.identifier.tag_class == ASN1Class::ContextSpecific &&
                header.value.identifier.tag_number == 1) {
                auto content = view.subspan(offset + header.value.header_bytes, header.value.length);
                if (content.size() >= 1 && content.size() <= 4) {
                    uint32_t value = 0;
                    for (size_t i = 0; i < content.size(); ++i) {
                        value = (value << 8) | content[i];
                    }
                    inhibit_policy_mapping = value;
                }
            }
        }

        // RFC 5280: MUST NOT issue certificates where policyConstraints is an empty sequence
        if (!require_explicit_policy && !inhibit_policy_mapping) {
            return std::nullopt;
        }

        return PolicyConstraintsExtension(ext->critical, require_explicit_policy, inhibit_policy_mapping);
    }

    std::optional<uint32_t> Certificate::inhibit_any_policy() const {
        auto ext = find_extension(ExtensionId::InhibitAnyPolicy);
        if (!ext) {
            return std::nullopt;
        }

        // MUST be critical per RFC 5280
        // Extension value is just a plain INTEGER (SkipCerts)
        auto int_result = parse_integer(ByteSpan(ext->value.data(), ext->value.size()));
        if (!int_result.success) {
            return std::nullopt;
        }

        // Convert bytes to uint32_t
        const auto &int_bytes = int_result.value;
        if (int_bytes.size() > 4) {
            return std::nullopt; // Too large
        }

        uint32_t value = 0;
        for (uint8_t byte : int_bytes) {
            value = (value << 8) | byte;
        }

        // RFC 5280: Reasonable limit (x509-parser uses 64)
        constexpr uint32_t MAX_SKIP_CERTS = 64;
        if (value > MAX_SKIP_CERTS) {
            return std::nullopt;
        }

        return value;
    }

    bool Certificate::verify_key_usage(uint16_t required_bits) const {
        auto bits = key_usage_bits();
        if (!bits) {
            return required_bits == 0;
        }
        return (bits.value() & required_bits) == required_bits;
    }

    namespace {

        bool equals_case_insensitive(std::string_view a, std::string_view b) {
            if (a.size() != b.size()) {
                return false;
            }
            for (size_t i = 0; i < a.size(); ++i) {
                if (std::tolower(static_cast<unsigned char>(a[i])) != std::tolower(static_cast<unsigned char>(b[i]))) {
                    return false;
                }
            }
            return true;
        }

        std::vector<Oid> parse_extended_key_usage(const RawExtension &ext) {
            std::vector<Oid> oids;
            auto seq = parse_sequence(ByteSpan(ext.value.data(), ext.value.size()));
            if (!seq.success) {
                return oids;
            }
            size_t offset = 0;
            while (offset < seq.value.size()) {
                auto oid_res = parse_oid(seq.value.subspan(offset));
                if (!oid_res.success) {
                    break;
                }
                oids.push_back(oid_res.value);
                offset += oid_res.bytes_consumed;
            }
            return oids;
        }

        bool wildcard_match(std::string_view pattern, std::string_view hostname) {
            auto star = pattern.find('*');
            if (star == std::string_view::npos) {
                return equals_case_insensitive(pattern, hostname);
            }
            auto suffix = pattern.substr(star + 1);
            if (hostname.size() < suffix.size()) {
                return false;
            }
            auto host_suffix = hostname.substr(hostname.size() - suffix.size());
            return equals_case_insensitive(suffix, host_suffix);
        }

    } // namespace

    bool Certificate::verify_extensions(CertificatePurpose purpose) const {
        auto eku = extended_key_usage();

        // Helper to check if purpose is allowed
        // If EKU is not present, all purposes are allowed (per RFC 5280)
        auto require_eku = [&](ExtendedKeyUsageExtension::KeyPurposeId purpose_id) {
            if (!eku.has_value()) {
                return true; // EKU not present, treat as any usage
            }
            return eku->has_purpose(purpose_id);
        };

        switch (purpose) {
        case CertificatePurpose::TLSServer: {
            if (!require_eku(ExtendedKeyUsageExtension::KeyPurposeId::ServerAuth)) {
                return false;
            }
            // For TLS Server: DigitalSignature is required for ECDSA/EdDSA
            // KeyEncipherment is only needed for RSA key exchange (TLS < 1.3)
            // We accept either DigitalSignature OR KeyEncipherment
            auto ku = key_usage_bits();
            if (!ku.has_value()) {
                return true; // No KeyUsage extension means any usage is allowed
            }
            return ((*ku & KeyUsageExtension::DigitalSignature) != 0) ||
                   ((*ku & KeyUsageExtension::KeyEncipherment) != 0);
        }
        case CertificatePurpose::TLSClient: {
            if (!require_eku(ExtendedKeyUsageExtension::KeyPurposeId::ClientAuth)) {
                return false;
            }
            constexpr uint16_t required = KeyUsageExtension::DigitalSignature;
            return verify_key_usage(required);
        }
        case CertificatePurpose::CodeSigning: {
            if (!require_eku(ExtendedKeyUsageExtension::KeyPurposeId::CodeSigning)) {
                return false;
            }
            constexpr uint16_t required = KeyUsageExtension::DigitalSignature | KeyUsageExtension::NonRepudiation;
            return verify_key_usage(required);
        }
        }
        return true;
    }

    bool Certificate::match_hostname(std::string_view hostname) const {
        auto names = subject_alt_names();
        for (const auto &name : names) {
            if (name.type != SubjectAltNameExtension::GeneralNameType::DNSName) {
                continue;
            }
            if (wildcard_match(name.value, hostname)) {
                return true;
            }
        }
        if (auto cn = tbs_.subject.first(DistinguishedNameAttribute::CommonName)) {
            return wildcard_match(*cn, hostname);
        }
        return false;
    }

    bool Certificate::match_subject(const DistinguishedName &dn) const { return tbs_.subject.der() == dn.der(); }

    bool Certificate::is_revoked(const Crl &crl) const {
        for (const auto &entry : crl.revoked) {
            if (entry.serial_number == tbs_.serial_number) {
                return true;
            }
        }
        return false;
    }

    std::vector<uint8_t> Certificate::fingerprint(lockey::hash::Algorithm algo) const {
        auto result = lockey::hash::digest(algo, der_);
        if (!result.success) {
            throw std::runtime_error("Failed to compute certificate fingerprint: " + result.error_message);
        }
        return result.data;
    }

    void Certificate::print_info(std::ostream &os) const {
        auto to_string_time = [](std::chrono::system_clock::time_point tp) {
            auto t = std::chrono::system_clock::to_time_t(tp);
            std::tm tm{};
#if defined(_WIN32)
            gmtime_s(&tm, &t);
#else
            gmtime_r(&t, &tm);
#endif
            std::ostringstream ss;
            ss << std::put_time(&tm, "%Y-%m-%d %H:%M:%SZ");
            return ss.str();
        };

        os << "Subject: " << tbs_.subject.to_string() << "\n";
        os << "Issuer: " << tbs_.issuer.to_string() << "\n";
        os << "Serial:";
        for (auto byte : tbs_.serial_number) {
            os << ' ' << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
        }
        os << std::dec << "\n";
        os << "Validity:\n"
           << "  Not Before: " << to_string_time(tbs_.validity.not_before) << "\n"
           << "  Not After : " << to_string_time(tbs_.validity.not_after) << "\n";
    }

    std::string Certificate::to_json() const {
        std::ostringstream oss;
        oss << "{"
            << "\"subject\":\"" << tbs_.subject.to_string() << "\","
            << "\"issuer\":\"" << tbs_.issuer.to_string() << "\""
            << "}";
        return oss.str();
    }

    bool Certificate::equals_identity(const Certificate &other) const {
        return tbs_.subject.der() == other.tbs_.subject.der() &&
               tbs_.subject_public_key_info.public_key == other.tbs_.subject_public_key_info.public_key;
    }

    CertificateBoolResult Certificate::validate_chain(const std::vector<Certificate> &chain,
                                                      const TrustStore &trust) const {
        std::vector<const Certificate *> order;
        order.push_back(this);
        for (const auto &cert : chain) {
            order.push_back(&cert);
        }

        std::vector<bool> is_ca(order.size(), false);
        for (size_t idx = 0; idx < order.size(); ++idx) {
            is_ca[idx] = order[idx]->basic_constraints_ca().value_or(false);
        }

        // Count intermediate CAs between subject and issuer (not including issuer itself)
        // This is used to check pathLenConstraint
        auto intermediate_ca_count = [&](size_t subject_idx, size_t issuer_idx) -> size_t {
            size_t count = 0;
            // Count CAs between subject and issuer (exclusive on both ends)
            for (size_t i = subject_idx + 1; i < issuer_idx; ++i) {
                if (is_ca[i]) {
                    ++count;
                }
            }
            return count;
        };

        auto validate_link = [&](size_t child_idx, size_t issuer_idx, const Certificate &child,
                                 const Certificate &issuer) -> CertificateBoolResult {
            auto sig = child.verify_signature(issuer);
            if (!sig.success) {
                return sig;
            }
            if (!sig.value) {
                return CertificateBoolResult::ok(false);
            }
            if (!child.check_validity()) {
                return CertificateBoolResult::ok(false);
            }
            if (!issuer.basic_constraints_ca().value_or(false)) {
                return CertificateBoolResult::ok(false);
            }
            auto path_len = issuer.basic_constraints_path_length();
            if (path_len.has_value()) {
                // pathLenConstraint specifies the maximum number of intermediate CAs
                // that can follow this CA in the certification path
                const auto intermediates = intermediate_ca_count(child_idx, issuer_idx);
                if (intermediates > path_len.value()) {
                    return CertificateBoolResult::ok(false);
                }
            }
            return CertificateBoolResult::ok(true);
        };

        for (size_t i = 0; i + 1 < order.size(); ++i) {
            auto result = validate_link(i, i + 1, *order[i], *order[i + 1]);
            if (!result.success || !result.value) {
                return result;
            }
        }

        const Certificate &last = *order.back();
        auto anchor = trust.find_issuer(last);
        if (!anchor.has_value()) {
            return CertificateBoolResult::ok(false);
        }
        auto anchor_result = validate_link(order.size() - 1, order.size(), last, *anchor);
        if (!anchor_result.success || !anchor_result.value) {
            return anchor_result;
        }

        return CertificateBoolResult::ok(true);
    }

    std::vector<uint8_t> Certificate::public_key_der() const {
        const auto &spki = tbs_.subject_public_key_info;
        std::vector<std::vector<uint8_t>> fields;
        auto oid = oid_for_signature(spki.algorithm.signature);
        if (!oid) {
            throw std::runtime_error("Failed to get OID for signature algorithm in subject public key info");
        }
        fields.push_back(der::encode_sequence(der::encode_oid(*oid)));
        fields.push_back(
            der::encode_bit_string(ByteSpan(spki.public_key.data(), spki.public_key.size()), spki.unused_bits));
        return der::encode_sequence(der::concat(fields));
    }

    // ExtendedKeyUsageExtension implementation

    Oid ExtendedKeyUsageExtension::purpose_to_oid(KeyPurposeId purpose) {
        switch (purpose) {
        case KeyPurposeId::ServerAuth:
            return Oid{{1, 3, 6, 1, 5, 5, 7, 3, 1}};
        case KeyPurposeId::ClientAuth:
            return Oid{{1, 3, 6, 1, 5, 5, 7, 3, 2}};
        case KeyPurposeId::CodeSigning:
            return Oid{{1, 3, 6, 1, 5, 5, 7, 3, 3}};
        case KeyPurposeId::EmailProtection:
            return Oid{{1, 3, 6, 1, 5, 5, 7, 3, 4}};
        case KeyPurposeId::TimeStamping:
            return Oid{{1, 3, 6, 1, 5, 5, 7, 3, 8}};
        case KeyPurposeId::OCSPSigning:
            return Oid{{1, 3, 6, 1, 5, 5, 7, 3, 9}};
        case KeyPurposeId::AnyExtendedKeyUsage:
            return Oid{{2, 5, 29, 37, 0}};
        default:
            return Oid{};
        }
    }

    ExtendedKeyUsageExtension::KeyPurposeId ExtendedKeyUsageExtension::oid_to_purpose(const Oid &oid) {
        if (oid.nodes == std::vector<uint32_t>{1, 3, 6, 1, 5, 5, 7, 3, 1}) {
            return KeyPurposeId::ServerAuth;
        }
        if (oid.nodes == std::vector<uint32_t>{1, 3, 6, 1, 5, 5, 7, 3, 2}) {
            return KeyPurposeId::ClientAuth;
        }
        if (oid.nodes == std::vector<uint32_t>{1, 3, 6, 1, 5, 5, 7, 3, 3}) {
            return KeyPurposeId::CodeSigning;
        }
        if (oid.nodes == std::vector<uint32_t>{1, 3, 6, 1, 5, 5, 7, 3, 4}) {
            return KeyPurposeId::EmailProtection;
        }
        if (oid.nodes == std::vector<uint32_t>{1, 3, 6, 1, 5, 5, 7, 3, 8}) {
            return KeyPurposeId::TimeStamping;
        }
        if (oid.nodes == std::vector<uint32_t>{1, 3, 6, 1, 5, 5, 7, 3, 9}) {
            return KeyPurposeId::OCSPSigning;
        }
        if (oid.nodes == std::vector<uint32_t>{2, 5, 29, 37, 0}) {
            return KeyPurposeId::AnyExtendedKeyUsage;
        }
        return KeyPurposeId::Unknown;
    }

    bool ExtendedKeyUsageExtension::has_purpose(KeyPurposeId purpose) const noexcept {
        if (purpose == KeyPurposeId::Unknown) {
            return false;
        }
        auto target_oid = purpose_to_oid(purpose);
        return has_purpose(target_oid);
    }

    bool ExtendedKeyUsageExtension::has_purpose(const Oid &purpose_oid) const noexcept {
        // anyExtendedKeyUsage means all purposes are allowed
        for (const auto &oid : purpose_oids_) {
            if (oid.nodes == std::vector<uint32_t>{2, 5, 29, 37, 0}) {
                return true;
            }
        }
        // Check for exact match
        for (const auto &oid : purpose_oids_) {
            if (oid.nodes == purpose_oid.nodes) {
                return true;
            }
        }
        return false;
    }

    std::vector<ExtendedKeyUsageExtension::KeyPurposeId>
    ExtendedKeyUsageExtension::recognized_purposes() const noexcept {
        std::vector<KeyPurposeId> purposes;
        for (const auto &oid : purpose_oids_) {
            auto purpose = oid_to_purpose(oid);
            if (purpose != KeyPurposeId::Unknown) {
                purposes.push_back(purpose);
            }
        }
        return purposes;
    }

#ifdef LOCKEY_HAS_VERIFY
    CertificateBoolResult Certificate::check_revocation(verify::Client &client) const {
        // Create a single certificate chain with just this certificate
        std::vector<Certificate> chain = {*this};

        // Call the verify client
        auto result = client.verify_chain(chain);

        if (!result.success) {
            return CertificateBoolResult::failure("Failed to check revocation: " + result.error);
        }

        // Check if certificate is revoked
        if (result.value.status == verify::wire::VerifyStatus::REVOKED) {
            return CertificateBoolResult::failure("Certificate is revoked: " + result.value.reason);
        }

        if (result.value.status == verify::wire::VerifyStatus::UNKNOWN) {
            return CertificateBoolResult::failure("Certificate revocation status unknown");
        }

        // Certificate is good
        return CertificateBoolResult::ok(true);
    }
#endif

} // namespace lockey::cert
