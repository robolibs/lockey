#include <chrono>
#include <iostream>
#include <string>

#include "lockey/cert/builder.hpp"
#include "lockey/cert/key_utils.hpp"

namespace {

void announce(const std::string &path) {
    std::cout << "Wrote PEM certificate to " << path << "\n";
}

} // namespace

int main() {
    using namespace std::chrono_literals;
    using lockey::cert::CertificateBuilder;

    const auto subject_key = lockey::cert::generate_ed25519_keypair();
    CertificateBuilder builder;
    const auto now = std::chrono::system_clock::now();

    builder.set_subject_from_string("CN=Lockey Self-Signed,O=Lockey,C=US")
        .set_subject_public_key_ed25519(subject_key.public_key)
        .set_validity(now - 1h, now + 365 * 24h)
        .set_basic_constraints(false, std::nullopt)
        .set_key_usage(lockey::cert::KeyUsageExtension::DigitalSignature);

    auto certificate = builder.build_ed25519(subject_key, true);
    if (!certificate.success) {
        std::cerr << "Failed to build certificate: " << certificate.error << "\n";
        return 1;
    }

    const std::string path = "self_signed.pem";
    if (!certificate.value.save(path)) {
        std::cerr << "Could not write " << path << "\n";
        return 1;
    }

    announce(path);
    std::cout << certificate.value.to_pem();
    return 0;
}
