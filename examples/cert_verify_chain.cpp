#include <chrono>
#include <iostream>
#include <optional>
#include <vector>

#include "lockey/cert/builder.hpp"
#include "lockey/cert/certificate.hpp"
#include "lockey/cert/key_utils.hpp"
#include "lockey/cert/trust_store.hpp"

namespace {

using namespace std::chrono_literals;

lockey::cert::CertificateResult<lockey::cert::Certificate>
make_certificate(const std::string &subject_dn, const lockey::crypto::Lockey::KeyPair &subject_key,
                 const lockey::cert::Certificate *issuer_cert, lockey::crypto::Lockey::KeyPair &issuer_key,
                 bool is_ca, std::optional<uint32_t> path_length) {
    lockey::cert::CertificateBuilder builder;
    const auto now = std::chrono::system_clock::now();
    builder.set_subject_from_string(subject_dn)
        .set_subject_public_key_ed25519(subject_key.public_key)
        .set_validity(now - 12h, now + 365 * 24h)
        .set_basic_constraints(is_ca, path_length)
        .set_key_usage(is_ca ? (lockey::cert::KeyUsageExtension::KeyCertSign |
                                lockey::cert::KeyUsageExtension::CRLSign)
                             : lockey::cert::KeyUsageExtension::DigitalSignature)
        .set_subject_key_identifier(subject_key.public_key);

    if (issuer_cert) {
        builder.set_issuer(issuer_cert->tbs().subject)
            .set_authority_key_identifier(issuer_cert->tbs().subject_public_key_info.public_key);
        return builder.build_ed25519(issuer_key, false);
    }

    return builder.build_ed25519(issuer_key, true);
}

} // namespace

int main() {
    auto root_key = lockey::cert::generate_ed25519_keypair();
    auto root_cert = make_certificate("CN=Lockey Root CA,O=Lockey", root_key, nullptr, root_key, true, 2);
    if (!root_cert.success) {
        std::cerr << "Failed to build root: " << root_cert.error << "\n";
        return 1;
    }

    auto intermediate_key = lockey::cert::generate_ed25519_keypair();
    auto intermediate_cert =
        make_certificate("CN=Lockey Intermediate CA,O=Lockey", intermediate_key, &root_cert.value, root_key, true, 0);
    if (!intermediate_cert.success) {
        std::cerr << "Failed to build intermediate: " << intermediate_cert.error << "\n";
        return 1;
    }

    auto leaf_key = lockey::cert::generate_ed25519_keypair();
    auto leaf_cert =
        make_certificate("CN=Leaf Service,O=Lockey", leaf_key, &intermediate_cert.value, intermediate_key, false, std::nullopt);
    if (!leaf_cert.success) {
        std::cerr << "Failed to build leaf: " << leaf_cert.error << "\n";
        return 1;
    }

    lockey::cert::TrustStore store;
    store.add(root_cert.value);

    std::vector<lockey::cert::Certificate> intermediates{intermediate_cert.value};
    auto verdict = leaf_cert.value.validate_chain(intermediates, store);
    std::cout << "Chain validation: " << (verdict.success && verdict.value ? "success" : "failed") << "\n";
    return verdict.success && verdict.value ? 0 : 1;
}
