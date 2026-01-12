#include <chrono>
#include <iostream>
#include <string>
#include <vector>

#include "keylock/cert/builder.hpp"
#include "keylock/cert/certificate.hpp"
#include "keylock/cert/key_utils.hpp"
#include "keylock/utils/common.hpp"

int main(int argc, char **argv) {
    using namespace std::chrono_literals;

    keylock::cert::Certificate certificate;
    if (argc > 1) {
        auto loaded = keylock::cert::Certificate::load(argv[1]);
        if (!loaded.success) {
            std::cerr << "Failed to load certificate: " << loaded.error << "\n";
            return 1;
        }
        certificate = loaded.value.front();
    } else {
        auto keypair = keylock::cert::generate_ed25519_keypair();
        keylock::cert::CertificateBuilder builder;
        const auto now = std::chrono::system_clock::now();
        builder.set_subject_from_string("CN=On-The-Fly Cert,O=keylock")
            .set_subject_public_key_ed25519(keypair.public_key)
            .set_validity(now - 1h, now + 90 * 24h)
            .set_basic_constraints(false, std::nullopt)
            .set_key_usage(keylock::cert::KeyUsageExtension::DigitalSignature);
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
    const auto fingerprint = certificate.fingerprint(::keylock::hash::Algorithm::SHA256);
    std::cout << "Fingerprint (SHA-256): " << keylock::utils::to_hex(fingerprint) << "\n";
    return 0;
}
