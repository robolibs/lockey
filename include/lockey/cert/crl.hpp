#pragma once

#include <chrono>
#include <optional>
#include <string>
#include <vector>

#include <lockey/cert/certificate.hpp>
#include <lockey/cert/distinguished_name.hpp>

namespace lockey::cert {

enum class CrlReason {
    Unspecified = 0,
    KeyCompromise = 1,
    CaCompromise = 2,
    AffiliationChanged = 3,
    Superseded = 4,
    CessationOfOperation = 5,
    CertificateHold = 6,
    RemoveFromCrl = 8,
    PrivilegeWithdrawn = 9,
    AaCompromise = 10
};

struct RevokedCertificate {
    std::vector<uint8_t> serial_number;
    std::chrono::system_clock::time_point revocation_date;
    std::optional<CrlReason> reason;
    std::optional<std::chrono::system_clock::time_point> invalidity_date;
};

struct Crl {
    int version{1};
    AlgorithmIdentifier signature{};
    DistinguishedName issuer{};
    std::chrono::system_clock::time_point this_update{};
    std::optional<std::chrono::system_clock::time_point> next_update{};
    std::vector<RevokedCertificate> revoked;
    AlgorithmIdentifier outer_signature{};
    std::vector<uint8_t> signature_value;
    std::vector<uint8_t> der;
    std::vector<uint8_t> tbs_der;

    CertificateBoolResult verify_signature(const Certificate &issuer) const;
};

CertificateResult<Crl> parse_crl(ByteSpan der);
CertificateResult<Crl> load_crl(const std::string &path);

} // namespace lockey::cert

