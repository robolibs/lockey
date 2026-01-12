#pragma once

#include <optional>
#include <string>
#include <vector>

#include <keylock/cert/certificate.hpp>

namespace keylock::cert {

    class TrustStore {
      public:
        TrustStore() = default;

        bool add(const Certificate &cert);
        bool remove_by_subject(const DistinguishedName &subject);
        std::optional<Certificate> find_issuer(const Certificate &cert) const;
        const std::vector<Certificate> &anchors() const { return anchors_; }

        static CertificateResult<TrustStore> load_from_pem(const std::string &path);
        static CertificateResult<TrustStore> load_from_der(const std::string &path);
        static CertificateResult<TrustStore> load_from_file(const std::string &path);
        static CertificateResult<TrustStore> load_from_system();

      private:
        std::vector<Certificate> anchors_;
    };

} // namespace keylock::cert
