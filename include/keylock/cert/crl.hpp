#pragma once

#include <chrono>
#include <optional>
#include <string>
#include <vector>

#include <keylock/cert/asn1_common.hpp>
#include <keylock/cert/certificate.hpp>
#include <keylock/cert/distinguished_name.hpp>

namespace keylock::cert {

    // CRL Revocation Reasons (RFC 5280 Section 5.3.1)
    enum class CrlReason : uint8_t {
        Unspecified = 0,
        KeyCompromise = 1,
        CaCompromise = 2,
        AffiliationChanged = 3,
        Superseded = 4,
        CessationOfOperation = 5,
        CertificateHold = 6,
        // value 7 is not used
        RemoveFromCrl = 8,
        PrivilegeWithdrawn = 9,
        AaCompromise = 10
    };

    // CRL Entry Extension (stored in revoked certificate entries)
    struct CrlEntryExtension {
        CrlEntryExtensionId id{CrlEntryExtensionId::Unknown};
        Oid oid{};
        bool critical{false};
        std::vector<uint8_t> value;
    };

    // CRL Extension (stored at CRL level)
    struct CrlExtension {
        CrlExtensionId id{CrlExtensionId::Unknown};
        Oid oid{};
        bool critical{false};
        std::vector<uint8_t> value;
    };

    // Revoked Certificate Entry
    struct RevokedCertificate {
        std::vector<uint8_t> serial_number;
        std::chrono::system_clock::time_point revocation_date;

        // Parsed CRL entry extensions
        std::optional<CrlReason> reason;
        std::optional<std::chrono::system_clock::time_point> invalidity_date;
        std::optional<DistinguishedName> certificate_issuer;

        // Raw extensions for inspection
        std::vector<CrlEntryExtension> extensions;
    };

    // Complete CRL structure
    struct Crl {
        // Version: 1 (v1) or 2 (v2)
        int version{1};

        // Signature algorithm (from tbsCertList)
        AlgorithmIdentifier signature{};

        // Issuer DN
        DistinguishedName issuer{};

        // Validity period
        std::chrono::system_clock::time_point this_update{};
        std::optional<std::chrono::system_clock::time_point> next_update{};

        // Revoked certificates
        std::vector<RevokedCertificate> revoked;

        // CRL Extensions (v2 only)
        std::vector<CrlExtension> extensions;

        // Parsed CRL-level extensions
        std::optional<std::vector<uint8_t>> authority_key_identifier;
        std::optional<std::vector<uint8_t>> crl_number;
        std::optional<std::vector<uint8_t>> delta_crl_indicator;
        bool has_issuing_distribution_point{false};

        // Outer signature algorithm
        AlgorithmIdentifier outer_signature{};

        // Signature value
        std::vector<uint8_t> signature_value;

        // DER encoding
        std::vector<uint8_t> der;
        std::vector<uint8_t> tbs_der;

        // Helper methods
        [[nodiscard]] bool is_certificate_revoked(const std::vector<uint8_t> &serial) const;
        [[nodiscard]] std::optional<const RevokedCertificate *>
        find_revoked_cert(const std::vector<uint8_t> &serial) const;
        [[nodiscard]] bool
        check_validity(std::optional<std::chrono::system_clock::time_point> check_time = std::nullopt) const;

        // Signature verification
        CertificateBoolResult verify_signature(const Certificate &issuer) const;

        // Extension access
        [[nodiscard]] std::optional<CrlExtension> find_extension(CrlExtensionId id) const;
    };

    // Parsing functions
    CertificateResult<Crl> parse_crl(ByteSpan der, bool relaxed = false);
    CertificateResult<Crl> parse_crl_relaxed(ByteSpan der);
    CertificateResult<std::vector<Crl>> parse_pem_crl_chain(std::string_view pem);
    CertificateResult<Crl> load_crl(const std::string &path);

} // namespace keylock::cert
