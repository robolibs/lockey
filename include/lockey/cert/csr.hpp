#pragma once

#include <optional>
#include <vector>

#include <lockey/cert/certificate.hpp>

namespace lockey::cert {

struct CertificationRequestInfo {
    int version{0};
    DistinguishedName subject{};
    SubjectPublicKeyInfo subject_public_key_info{};
    std::vector<RawExtension> extensions;
};

struct CertificateRequest {
    CertificationRequestInfo info{};
    AlgorithmIdentifier signature_algorithm{};
    std::vector<uint8_t> signature;
    std::vector<uint8_t> der;
    std::vector<uint8_t> cri_der;

    CertificateSignatureResult sign(const crypto::Lockey::KeyPair &key) const;
};

CertificateResult<CertificateRequest> parse_csr(ByteSpan der);
CertificateResult<CertificateRequest> load_csr(const std::string &path);

} // namespace lockey::cert

