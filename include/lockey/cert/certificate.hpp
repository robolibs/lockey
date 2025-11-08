#pragma once

#include <chrono>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <lockey/cert/asn1_common.hpp>
#include <lockey/cert/asn1_utils.hpp>
#include <lockey/cert/distinguished_name.hpp>
#include <lockey/hash/algorithms.hpp>
#include <lockey/crypto/context.hpp>

namespace lockey::cert {

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

enum class CertificateFormat {
    DER,
    PEM
};

template <typename T> struct CertificateResult {
    bool success{};
    T value{};
    std::string error{};

    static CertificateResult<T> failure(std::string message) {
        return CertificateResult<T>{false, {}, std::move(message)};
    }

    static CertificateResult<T> ok(T value) {
        return CertificateResult<T>{true, std::move(value), {}};
    }
};

class Certificate;
class Crl;

using CertificateParseResult = CertificateResult<Certificate>;
using CertificateChainResult = CertificateResult<std::vector<Certificate>>;
using CertificateSignatureResult = CertificateResult<std::vector<uint8_t>>;
using CertificateBoolResult = CertificateResult<bool>;

enum class CertificatePurpose {
    TLSServer,
    TLSClient,
    CodeSigning
};

class TrustStore;

class Extension {
  public:
    Extension(ExtensionId id, bool critical) : id_(id), critical_(critical) {}
    virtual ~Extension() = default;

    [[nodiscard]] ExtensionId id() const noexcept {
        return id_;
    }

    [[nodiscard]] bool critical() const noexcept {
        return critical_;
    }

  private:
    ExtensionId id_;
    bool critical_;
};

class BasicConstraintsExtension : public Extension {
  public:
    BasicConstraintsExtension(bool critical, bool ca_flag, std::optional<uint32_t> path_length)
        : Extension(ExtensionId::BasicConstraints, critical), ca_(ca_flag), path_length_(path_length) {}

    [[nodiscard]] bool is_ca() const noexcept {
        return ca_;
    }

    [[nodiscard]] const std::optional<uint32_t> &path_length() const noexcept {
        return path_length_;
    }

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

    KeyUsageExtension(bool critical, uint16_t bits)
        : Extension(ExtensionId::KeyUsage, critical), bits_(bits) {}

    [[nodiscard]] bool has(uint16_t flag) const noexcept {
        return (bits_ & flag) != 0;
    }

    [[nodiscard]] uint16_t bits() const noexcept {
        return bits_;
    }

  private:
    uint16_t bits_{0};
};

class SubjectKeyIdentifierExtension : public Extension {
  public:
    SubjectKeyIdentifierExtension(bool critical, std::vector<uint8_t> identifier)
        : Extension(ExtensionId::SubjectKeyIdentifier, critical), identifier_(std::move(identifier)) {}

    [[nodiscard]] const std::vector<uint8_t> &identifier() const noexcept {
        return identifier_;
    }

  private:
    std::vector<uint8_t> identifier_;
};

class AuthorityKeyIdentifierExtension : public Extension {
  public:
    AuthorityKeyIdentifierExtension(bool critical, std::vector<uint8_t> key_id)
        : Extension(ExtensionId::AuthorityKeyIdentifier, critical), key_identifier_(std::move(key_id)) {}

    [[nodiscard]] const std::vector<uint8_t> &key_identifier() const noexcept {
        return key_identifier_;
    }

  private:
    std::vector<uint8_t> key_identifier_;
};

class SubjectAltNameExtension : public Extension {
  public:
    enum class GeneralNameType {
        DNSName,
        URI,
        IPAddress,
        Email,
        Other
    };

    struct GeneralName {
        GeneralNameType type;
        std::string value;
    };

    SubjectAltNameExtension(bool critical, std::vector<GeneralName> names)
        : Extension(ExtensionId::SubjectAltName, critical), names_(std::move(names)) {}

    [[nodiscard]] const std::vector<GeneralName> &names() const noexcept {
        return names_;
    }

  private:
    std::vector<GeneralName> names_;
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
        : tbs_(std::move(tbs)), signature_algorithm_(signature_algorithm), signature_value_(std::move(signature_value)),
          der_(std::move(der)), tbs_der_(std::move(tbs_der)) {}

    [[nodiscard]] const TBSCertificate &tbs() const noexcept {
        return tbs_;
    }

    [[nodiscard]] const AlgorithmIdentifier &signature_algorithm() const noexcept {
        return signature_algorithm_;
    }

    [[nodiscard]] const std::vector<uint8_t> &signature_value() const noexcept {
        return signature_value_;
    }

    [[nodiscard]] const std::vector<uint8_t> &der() const noexcept {
        return der_;
    }

    [[nodiscard]] const std::vector<uint8_t> &tbs_der() const noexcept {
        return tbs_der_;
    }

    [[nodiscard]] std::vector<uint8_t> to_der() const {
        return der_;
    }

    [[nodiscard]] std::string to_pem(size_t line_length = 64) const;

    [[nodiscard]] bool save(const std::string &path, CertificateFormat format = CertificateFormat::PEM) const;
    CertificateSignatureResult sign(const crypto::Lockey::KeyPair &issuer_key,
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
    bool verify_key_usage(uint16_t required_bits) const;
    bool verify_extensions(CertificatePurpose purpose) const;
    bool match_hostname(std::string_view hostname) const;
    bool match_subject(const DistinguishedName &dn) const;
    bool is_revoked(const Crl &crl) const;
    CertificateBoolResult validate_chain(const std::vector<Certificate> &chain, const TrustStore &trust) const;

    std::vector<uint8_t> public_key_der() const;
    std::vector<uint8_t> fingerprint(lockey::hash::Algorithm algo) const;
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

} // namespace lockey::cert
