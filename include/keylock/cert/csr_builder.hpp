#pragma once

#include <optional>

#include <keylock/cert/csr.hpp>

namespace keylock::cert {

    class CsrBuilder {
      public:
        CsrBuilder &set_subject(const DistinguishedName &dn);
        CsrBuilder &set_subject_from_string(std::string_view dn);
        CsrBuilder &set_subject_public_key(const SubjectPublicKeyInfo &spki);
        CsrBuilder &set_subject_public_key_ed25519(const std::vector<uint8_t> &public_key);
        CsrBuilder &add_extension(const RawExtension &extension);

        CertificateResult<CertificateRequest> build_ed25519(const crypto::Context::KeyPair &key) const;

      private:
        std::optional<std::string> validate_inputs() const;
        std::vector<uint8_t> encode_cri() const;

        CertificationRequestInfo info_{};
        bool subject_set_{false};
        bool spki_set_{false};
    };

} // namespace keylock::cert
