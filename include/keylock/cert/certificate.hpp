#pragma once

#include <chrono>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <keylock/cert/asn1_common.hpp>
#include <keylock/cert/asn1_utils.hpp>
#include <keylock/cert/distinguished_name.hpp>
#include <keylock/crypto/context.hpp>
#include <keylock/hash/algorithms.hpp>

// Forward declarations for verify module
namespace keylock::verify {
    class Client;
}

namespace keylock::cert {

    struct Validity {
        std::chrono::system_clock::time_point not_before{};
        std::chrono::system_clock::time_point not_after{};

        [[nodiscard]] bool contains(std::chrono::system_clock::time_point time) const noexcept {
            return time >= not_before && time <= not_after;
        }
    };

    struct SubjectPublicKeyInfo {
        AlgorithmIdentifier algorithm{};
        std::vector<uint8_t> public_key;
        uint8_t unused_bits{};
    };

    struct RawExtension {
        Oid oid{};
        ExtensionId id{ExtensionId::Unknown};
        bool critical{};
        std::vector<uint8_t> value;
    };

    enum class CertificateFormat { DER, PEM };

    template <typename T> struct CertificateResult {
        bool success{};
        T value{};
        std::string error{};

        static CertificateResult<T> failure(std::string message) {
            return CertificateResult<T>{false, {}, std::move(message)};
        }

        static CertificateResult<T> ok(T value) { return CertificateResult<T>{true, std::move(value), {}}; }
    };

    class Certificate;
    class Crl;

    using CertificateParseResult = CertificateResult<Certificate>;
    using CertificateChainResult = CertificateResult<std::vector<Certificate>>;
    using CertificateSignatureResult = CertificateResult<std::vector<uint8_t>>;
    using CertificateBoolResult = CertificateResult<bool>;

    enum class CertificatePurpose { TLSServer, TLSClient, CodeSigning };

    class TrustStore;

    class Extension {
      public:
        Extension(ExtensionId id, bool critical) : id_(id), critical_(critical) {}
        virtual ~Extension() = default;

        [[nodiscard]] ExtensionId id() const noexcept { return id_; }

        [[nodiscard]] bool critical() const noexcept { return critical_; }

      private:
        ExtensionId id_;
        bool critical_;
    };

    class BasicConstraintsExtension : public Extension {
      public:
        BasicConstraintsExtension(bool critical, bool ca_flag, std::optional<uint32_t> path_length)
            : Extension(ExtensionId::BasicConstraints, critical), ca_(ca_flag), path_length_(path_length) {}

        [[nodiscard]] bool is_ca() const noexcept { return ca_; }

        [[nodiscard]] const std::optional<uint32_t> &path_length() const noexcept { return path_length_; }

      private:
        bool ca_{false};
        std::optional<uint32_t> path_length_{};
    };

    class KeyUsageExtension : public Extension {
      public:
        enum : uint16_t {
            DigitalSignature = 0x8000,
            NonRepudiation = 0x4000,
            KeyEncipherment = 0x2000,
            DataEncipherment = 0x1000,
            KeyAgreement = 0x0800,
            KeyCertSign = 0x0400,
            CRLSign = 0x0200,
            EncipherOnly = 0x0100,
            DecipherOnly = 0x0080
        };

        KeyUsageExtension(bool critical, uint16_t bits) : Extension(ExtensionId::KeyUsage, critical), bits_(bits) {}

        [[nodiscard]] bool has(uint16_t flag) const noexcept { return (bits_ & flag) != 0; }

        [[nodiscard]] uint16_t bits() const noexcept { return bits_; }

      private:
        uint16_t bits_{0};
    };

    class SubjectKeyIdentifierExtension : public Extension {
      public:
        SubjectKeyIdentifierExtension(bool critical, std::vector<uint8_t> identifier)
            : Extension(ExtensionId::SubjectKeyIdentifier, critical), identifier_(std::move(identifier)) {}

        [[nodiscard]] const std::vector<uint8_t> &identifier() const noexcept { return identifier_; }

      private:
        std::vector<uint8_t> identifier_;
    };

    class AuthorityKeyIdentifierExtension : public Extension {
      public:
        AuthorityKeyIdentifierExtension(bool critical, std::vector<uint8_t> key_id)
            : Extension(ExtensionId::AuthorityKeyIdentifier, critical), key_identifier_(std::move(key_id)) {}

        [[nodiscard]] const std::vector<uint8_t> &key_identifier() const noexcept { return key_identifier_; }

      private:
        std::vector<uint8_t> key_identifier_;
    };

    class SubjectAltNameExtension : public Extension {
      public:
        enum class GeneralNameType { DNSName, URI, IPAddress, Email, Other };

        struct GeneralName {
            GeneralNameType type;
            std::string value;
        };

        SubjectAltNameExtension(bool critical, std::vector<GeneralName> names)
            : Extension(ExtensionId::SubjectAltName, critical), names_(std::move(names)) {}

        [[nodiscard]] const std::vector<GeneralName> &names() const noexcept { return names_; }

      private:
        std::vector<GeneralName> names_;
    };

    class ExtendedKeyUsageExtension : public Extension {
      public:
        // RFC 5280 standard Extended Key Usage OIDs
        enum class KeyPurposeId {
            Unknown,
            ServerAuth,         // TLS Web Server Authentication (1.3.6.1.5.5.7.3.1)
            ClientAuth,         // TLS Web Client Authentication (1.3.6.1.5.5.7.3.2)
            CodeSigning,        // Code Signing (1.3.6.1.5.5.7.3.3)
            EmailProtection,    // E-mail Protection (1.3.6.1.5.5.7.3.4)
            TimeStamping,       // Time Stamping (1.3.6.1.5.5.7.3.8)
            OCSPSigning,        // OCSP Signing (1.3.6.1.5.5.7.3.9)
            AnyExtendedKeyUsage // anyExtendedKeyUsage (2.5.29.37.0)
        };

        ExtendedKeyUsageExtension(bool critical, std::vector<Oid> purpose_oids)
            : Extension(ExtensionId::ExtendedKeyUsage, critical), purpose_oids_(std::move(purpose_oids)) {}

        [[nodiscard]] const std::vector<Oid> &purpose_oids() const noexcept { return purpose_oids_; }

        [[nodiscard]] bool has_purpose(KeyPurposeId purpose) const noexcept;
        [[nodiscard]] bool has_purpose(const Oid &purpose_oid) const noexcept;
        [[nodiscard]] std::vector<KeyPurposeId> recognized_purposes() const noexcept;

        // Helper methods for common purposes
        [[nodiscard]] bool allows_server_auth() const noexcept { return has_purpose(KeyPurposeId::ServerAuth); }
        [[nodiscard]] bool allows_client_auth() const noexcept { return has_purpose(KeyPurposeId::ClientAuth); }
        [[nodiscard]] bool allows_code_signing() const noexcept { return has_purpose(KeyPurposeId::CodeSigning); }
        [[nodiscard]] bool allows_email_protection() const noexcept {
            return has_purpose(KeyPurposeId::EmailProtection);
        }
        [[nodiscard]] bool allows_any() const noexcept { return has_purpose(KeyPurposeId::AnyExtendedKeyUsage); }

        // Static helper to convert KeyPurposeId to OID
        static Oid purpose_to_oid(KeyPurposeId purpose);
        static KeyPurposeId oid_to_purpose(const Oid &oid);

      private:
        std::vector<Oid> purpose_oids_;
    };

    // Phase 13: Enterprise Extensions

    class IssuerAltNameExtension : public Extension {
      public:
        using GeneralNameType = SubjectAltNameExtension::GeneralNameType;
        using GeneralName = SubjectAltNameExtension::GeneralName;

        IssuerAltNameExtension(bool critical, std::vector<GeneralName> names)
            : Extension(ExtensionId::IssuerAltName, critical), names_(std::move(names)) {}

        [[nodiscard]] const std::vector<GeneralName> &names() const noexcept { return names_; }

      private:
        std::vector<GeneralName> names_;
    };

    class PolicyMappingsExtension : public Extension {
      public:
        struct PolicyMapping {
            std::vector<uint32_t> issuer_domain_policy;
            std::vector<uint32_t> subject_domain_policy;
        };

        PolicyMappingsExtension(bool critical, std::vector<PolicyMapping> mappings)
            : Extension(ExtensionId::PolicyMappings, critical), mappings_(std::move(mappings)) {}

        [[nodiscard]] const std::vector<PolicyMapping> &mappings() const noexcept { return mappings_; }

      private:
        std::vector<PolicyMapping> mappings_;
    };

    class PolicyConstraintsExtension : public Extension {
      public:
        PolicyConstraintsExtension(bool critical, std::optional<uint32_t> require_explicit_policy,
                                   std::optional<uint32_t> inhibit_policy_mapping)
            : Extension(ExtensionId::PolicyConstraints, critical), require_explicit_policy_(require_explicit_policy),
              inhibit_policy_mapping_(inhibit_policy_mapping) {}

        [[nodiscard]] std::optional<uint32_t> require_explicit_policy() const noexcept {
            return require_explicit_policy_;
        }

        [[nodiscard]] std::optional<uint32_t> inhibit_policy_mapping() const noexcept {
            return inhibit_policy_mapping_;
        }

      private:
        std::optional<uint32_t> require_explicit_policy_;
        std::optional<uint32_t> inhibit_policy_mapping_;
    };

    class InhibitAnyPolicyExtension : public Extension {
      public:
        InhibitAnyPolicyExtension(bool critical, uint32_t skip_certs)
            : Extension(ExtensionId::InhibitAnyPolicy, critical), skip_certs_(skip_certs) {}

        [[nodiscard]] uint32_t skip_certs() const noexcept { return skip_certs_; }

      private:
        uint32_t skip_certs_;
    };

    struct TBSCertificate {
        int version{1};
        std::vector<uint8_t> serial_number;
        AlgorithmIdentifier signature{};
        DistinguishedName issuer{};
        Validity validity{};
        DistinguishedName subject{};
        SubjectPublicKeyInfo subject_public_key_info{};
        std::vector<RawExtension> extensions;
    };

    class Certificate {
      public:
        Certificate() = default;
        Certificate(TBSCertificate tbs, AlgorithmIdentifier signature_algorithm, std::vector<uint8_t> signature_value,
                    std::vector<uint8_t> der, std::vector<uint8_t> tbs_der)
            : tbs_(std::move(tbs)), signature_algorithm_(signature_algorithm),
              signature_value_(std::move(signature_value)), der_(std::move(der)), tbs_der_(std::move(tbs_der)) {}

        [[nodiscard]] const TBSCertificate &tbs() const noexcept { return tbs_; }

        [[nodiscard]] const AlgorithmIdentifier &signature_algorithm() const noexcept { return signature_algorithm_; }

        [[nodiscard]] const std::vector<uint8_t> &signature_value() const noexcept { return signature_value_; }

        [[nodiscard]] const std::vector<uint8_t> &der() const noexcept { return der_; }

        [[nodiscard]] const std::vector<uint8_t> &tbs_der() const noexcept { return tbs_der_; }

        [[nodiscard]] std::vector<uint8_t> to_der() const { return der_; }

        [[nodiscard]] std::string to_pem(size_t line_length = 64) const;

        [[nodiscard]] bool save(const std::string &path, CertificateFormat format = CertificateFormat::PEM) const;
        CertificateSignatureResult sign(const crypto::Context::KeyPair &issuer_key,
                                        hash::Algorithm hash_alg = hash::Algorithm::SHA256) const;
        CertificateBoolResult verify_signature(const Certificate &issuer) const;
        bool check_validity(std::optional<std::chrono::system_clock::time_point> check_time = std::nullopt) const;

        static CertificateParseResult parse(ByteSpan der, bool relaxed = false);
        static CertificateParseResult parse(const std::vector<uint8_t> &der, bool relaxed = false);
        static CertificateChainResult parse_pem_chain(std::string_view pem, bool relaxed = false);
        static CertificateChainResult parse_der_chain(ByteSpan der, bool relaxed = false);
        static CertificateChainResult load(const std::string &path, bool relaxed = false);
        [[nodiscard]] std::optional<RawExtension> find_extension(ExtensionId id) const;
        [[nodiscard]] std::optional<bool> basic_constraints_ca() const;
        [[nodiscard]] std::optional<uint32_t> basic_constraints_path_length() const;
        [[nodiscard]] std::optional<uint16_t> key_usage_bits() const;
        [[nodiscard]] std::vector<SubjectAltNameExtension::GeneralName> subject_alt_names() const;
        [[nodiscard]] std::optional<ExtendedKeyUsageExtension> extended_key_usage() const;
        // Phase 13: Enterprise extensions
        [[nodiscard]] std::vector<IssuerAltNameExtension::GeneralName> issuer_alt_names() const;
        [[nodiscard]] std::vector<PolicyMappingsExtension::PolicyMapping> policy_mappings() const;
        [[nodiscard]] std::optional<PolicyConstraintsExtension> policy_constraints() const;
        [[nodiscard]] std::optional<uint32_t> inhibit_any_policy() const;
        bool verify_key_usage(uint16_t required_bits) const;
        bool verify_extensions(CertificatePurpose purpose) const;
        bool match_hostname(std::string_view hostname) const;
        bool match_subject(const DistinguishedName &dn) const;
        bool is_revoked(const Crl &crl) const;

        // Check revocation status via verification service
        CertificateBoolResult check_revocation(verify::Client &client) const;

        CertificateBoolResult validate_chain(const std::vector<Certificate> &chain, const TrustStore &trust) const;

        std::vector<uint8_t> public_key_der() const;
        std::vector<uint8_t> fingerprint(::keylock::hash::Algorithm algo) const;
        void print_info(std::ostream &os) const;
        std::string to_json() const;
        bool operator==(const Certificate &other) const noexcept { return der_ == other.der_; }
        bool equals_identity(const Certificate &other) const;

      private:
        TBSCertificate tbs_{};
        AlgorithmIdentifier signature_algorithm_{};
        std::vector<uint8_t> signature_value_{};
        std::vector<uint8_t> der_{};
        std::vector<uint8_t> tbs_der_{};
    };

} // namespace keylock::cert
