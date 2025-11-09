#include <chrono>
#include <iostream>
#include <string>

#include "lockey/cert/builder.hpp"
#include "lockey/cert/key_utils.hpp"

int main() {
    using namespace std::chrono_literals;
    using lockey::cert::CertificateBuilder;

    const auto ca_key = lockey::cert::generate_ed25519_keypair();
    CertificateBuilder builder;
    const auto now = std::chrono::system_clock::now();

    builder.set_subject_from_string("CN=Lockey Dev CA,O=Lockey Labs,C=US")
        .set_subject_public_key_ed25519(ca_key.public_key)
        .set_validity(now - 24h, now + 2 * 365 * 24h)
        .set_basic_constraints(true, 1)
        .set_key_usage(lockey::cert::KeyUsageExtension::KeyCertSign |
                       lockey::cert::KeyUsageExtension::CRLSign)
        .set_subject_key_identifier(ca_key.public_key);

    auto certificate = builder.build_ed25519(ca_key, true);
    if (!certificate.success) {
        std::cerr << "Failed to create CA certificate: " << certificate.error << "\n";
        return 1;
    }

    const std::string pem_path = "dev_ca.pem";
    if (!certificate.value.save(pem_path)) {
        std::cerr << "Unable to write " << pem_path << "\n";
        return 1;
    }

    std::cout << "CA certificate saved to " << pem_path << "\n";
    return 0;
}
