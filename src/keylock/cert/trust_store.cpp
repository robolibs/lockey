#include <keylock/cert/trust_store.hpp>

#include <algorithm>
#include <cstdlib>
#include <string_view>

#include <keylock/cert/pem.hpp>
#include <keylock/io/files.hpp>

namespace keylock::cert {

    bool TrustStore::add(const Certificate &cert) {
        anchors_.push_back(cert);
        return true;
    }

    bool TrustStore::remove_by_subject(const DistinguishedName &subject) {
        auto original = anchors_.size();
        anchors_.erase(
            std::remove_if(anchors_.begin(), anchors_.end(),
                           [&](const Certificate &cert) { return cert.tbs().subject.der() == subject.der(); }),
            anchors_.end());
        return anchors_.size() != original;
    }

    std::optional<Certificate> TrustStore::find_issuer(const Certificate &cert) const {
        for (const auto &anchor : anchors_) {
            if (anchor.tbs().subject.der() == cert.tbs().issuer.der()) {
                return anchor;
            }
        }
        return std::nullopt;
    }

    CertificateResult<TrustStore> TrustStore::load_from_pem(const std::string &path) {
        auto chain = Certificate::load(path, true);
        if (!chain.success) {
            return CertificateResult<TrustStore>::failure(chain.error);
        }
        TrustStore store;
        for (const auto &cert : chain.value) {
            store.add(cert);
        }
        return CertificateResult<TrustStore>::ok(std::move(store));
    }

    CertificateResult<TrustStore> TrustStore::load_from_der(const std::string &path) {
        auto chain = Certificate::load(path, true);
        if (!chain.success) {
            return CertificateResult<TrustStore>::failure(chain.error);
        }
        TrustStore store;
        for (const auto &cert : chain.value) {
            store.add(cert);
        }
        return CertificateResult<TrustStore>::ok(std::move(store));
    }

    CertificateResult<TrustStore> TrustStore::load_from_file(const std::string &path) {
        auto file = io::read_binary(path);
        if (!file.success) {
            return CertificateResult<TrustStore>::failure(file.error_message);
        }
        const std::string_view contents(reinterpret_cast<const char *>(file.data.data()), file.data.size());
        if (contents.find("-----BEGIN") != std::string_view::npos) {
            return load_from_pem(path);
        }
        return load_from_der(path);
    }

    CertificateResult<TrustStore> TrustStore::load_from_system() {
        // 1) Explicit file via environment - if set, use it exclusively (no fallback)
        if (const char *env_file = std::getenv("SSL_CERT_FILE"); env_file && env_file[0] != '\0') {
            auto store = load_from_file(env_file);
            if (store.success) {
                return store;
            }
            return CertificateResult<TrustStore>::failure("SSL_CERT_FILE set but failed to load: " + store.error);
        }

        // 2) Directory of CA files (hashed or flat), take first readable cert bundle inside
        if (const char *env_dir = std::getenv("SSL_CERT_DIR"); env_dir && env_dir[0] != '\0') {
            // Common hashed dir layout: many individual PEMs or symlinks; we can try well-known distro bundle names in
            // it
            const std::string dir(env_dir);
            const std::string candidates[] = {
                dir + "/ca-certificates.crt",
                dir + "/ca-bundle.crt",
                dir + "/cert.pem",
            };
            for (const auto &path : candidates) {
                if (auto store = load_from_file(path); store.success) {
                    return store;
                }
            }
        }

        // 3) OS defaults
        constexpr const char *default_paths[] = {
            "/etc/ssl/certs/ca-certificates.crt",    // Debian/Ubuntu
            "/etc/pki/tls/certs/ca-bundle.crt",      // CentOS/RHEL
            "/usr/local/share/certs/ca-root-nss.crt" // FreeBSD
        };
        for (const auto *path : default_paths) {
            if (auto store = load_from_file(path); store.success) {
                return store;
            }
        }

        return CertificateResult<TrustStore>::failure("unable to locate system trust store");
    }

} // namespace keylock::cert
