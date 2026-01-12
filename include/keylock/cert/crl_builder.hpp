#pragma once

#include <optional>
#include <vector>

#include <keylock/cert/crl.hpp>

namespace keylock::cert {

    class CrlBuilder {
      public:
        CrlBuilder &set_issuer(const DistinguishedName &dn);
        CrlBuilder &set_issuer_from_string(std::string_view dn);
        CrlBuilder &set_this_update(std::chrono::system_clock::time_point tp);
        CrlBuilder &set_next_update(std::chrono::system_clock::time_point tp);
        CrlBuilder &add_revoked(const RevokedCertificate &entry);
        CrlBuilder &add_revoked(std::vector<uint8_t> serial, std::chrono::system_clock::time_point when,
                                std::optional<CrlReason> reason = std::nullopt,
                                std::optional<std::chrono::system_clock::time_point> invalidity = std::nullopt);
        CertificateResult<Crl> build_ed25519(const crypto::Context::KeyPair &issuer_key) const;

      private:
        CertificateResult<Crl> build(const crypto::Context::KeyPair &issuer_key) const;
        std::optional<std::string> validate_inputs() const;
        std::vector<uint8_t> encode_tbs() const;
        std::vector<uint8_t> encode_revoked_entries() const;

        DistinguishedName issuer_;
        bool issuer_set_{false};
        std::chrono::system_clock::time_point this_update_{};
        std::optional<std::chrono::system_clock::time_point> next_update_;
        std::vector<RevokedCertificate> entries_;
    };

} // namespace keylock::cert
