#include <chrono>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

#include "keylock/cert/builder.hpp"
#include "keylock/cert/csr_builder.hpp"
#include "keylock/cert/csr.hpp"
#include "keylock/cert/key_utils.hpp"

namespace {

keylock::cert::CertificateResult<keylock::cert::Certificate> make_ca(keylock::crypto::Context::KeyPair &keypair) {
    using namespace std::chrono_literals;
    keylock::cert::CertificateBuilder ca_builder;
    const auto now = std::chrono::system_clock::now();
    ca_builder.set_subject_from_string("CN=keylock Signing CA,O=keylock")
        .set_subject_public_key_ed25519(keypair.public_key)
        .set_validity(now - 1h, now + 730 * 24h)
        .set_basic_constraints(true, 2)
        .set_key_usage(keylock::cert::KeyUsageExtension::KeyCertSign |
                       keylock::cert::KeyUsageExtension::CRLSign)
        .set_subject_key_identifier(keypair.public_key);
    return ca_builder.build_ed25519(keypair, true);
}

keylock::cert::CertificateRequest make_sample_csr(keylock::crypto::Context::KeyPair &leaf_key) {
    keylock::cert::CsrBuilder builder;
    builder.set_subject_from_string("CN=keylock Service,O=keylock")
        .set_subject_public_key_ed25519(leaf_key.public_key);
    auto csr = builder.build_ed25519(leaf_key);
    if (!csr.success) {
        throw std::runtime_error(csr.error);
    }
    return csr.value;
}

} // namespace

int main() {
    using namespace std::chrono_literals;

    auto ca_key = keylock::cert::generate_ed25519_keypair();
    auto ca_cert = make_ca(ca_key);
    if (!ca_cert.success) {
        std::cerr << "Unable to create issuing CA: " << ca_cert.error << "\n";
        return 1;
    }

    auto leaf_key = keylock::cert::generate_ed25519_keypair();
    auto csr = make_sample_csr(leaf_key);

    keylock::cert::CertificateBuilder builder;
    const auto now = std::chrono::system_clock::now();
    builder.set_subject(csr.info.subject)
        .set_subject_public_key_info(csr.info.subject_public_key_info)
        .set_validity(now, now + 365 * 24h)
        .set_issuer(ca_cert.value.tbs().subject)
        .set_basic_constraints(false, std::nullopt)
        .set_key_usage(keylock::cert::KeyUsageExtension::DigitalSignature |
                       keylock::cert::KeyUsageExtension::KeyAgreement);

    auto issued = builder.build_ed25519(ca_key, false);
    if (!issued.success) {
        std::cerr << "Failed to sign CSR: " << issued.error << "\n";
        return 1;
    }

    std::cout << "Issued certificate:\n" << issued.value.to_pem() << "\n";
    auto verified = issued.value.verify_signature(ca_cert.value);
    std::cout << "Signature verification against CA: "
              << (verified.success && verified.value ? "success" : "failed") << "\n";
    return 0;
}
