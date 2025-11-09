#include <chrono>
#include <iostream>
#include <string>
#include <vector>

#include "lockey/cert/builder.hpp"
#include "lockey/cert/certificate.hpp"
#include "lockey/cert/key_utils.hpp"
#include "lockey/utils/common.hpp"

int main(int argc, char **argv) {
    using namespace std::chrono_literals;

    lockey::cert::Certificate certificate;
    if (argc > 1) {
        auto loaded = lockey::cert::Certificate::load(argv[1]);
        if (!loaded.success) {
            std::cerr << "Failed to load certificate: " << loaded.error << "\n";
            return 1;
        }
        certificate = loaded.value.front();
    } else {
        auto keypair = lockey::cert::generate_ed25519_keypair();
        lockey::cert::CertificateBuilder builder;
        const auto now = std::chrono::system_clock::now();
        builder.set_subject_from_string("CN=On-The-Fly Cert,O=Lockey")
            .set_subject_public_key_ed25519(keypair.public_key)
            .set_validity(now - 1h, now + 90 * 24h)
            .set_basic_constraints(false, std::nullopt)
            .set_key_usage(lockey::cert::KeyUsageExtension::DigitalSignature);
        auto cert = builder.build_ed25519(keypair, true);
        if (!cert.success) {
            std::cerr << "Unable to generate fallback certificate: " << cert.error << "\n";
            return 1;
        }
        certificate = cert.value;
    }

    certificate.print_info(std::cout);
    auto sans = certificate.subject_alt_names();
    std::cout << "SubjectAltName count: " << sans.size() << "\n";
    const auto fingerprint = certificate.fingerprint(lockey::hash::Algorithm::SHA256);
    std::cout << "Fingerprint (SHA-256): " << lockey::utils::to_hex(fingerprint) << "\n";
    return 0;
}
