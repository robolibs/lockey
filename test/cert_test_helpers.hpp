#pragma once

#include <chrono>
#include <string>

#include <lockey/cert/builder.hpp>
#include <lockey/cert/key_utils.hpp>
#include <lockey/cert/trust_store.hpp>

namespace cert_test {

inline lockey::cert::DistinguishedName dn_from_string(std::string_view str) {
    auto parsed = lockey::cert::DistinguishedName::from_string(str);
    REQUIRE(parsed.success);
    return parsed.value;
}

inline lockey::cert::Certificate make_certificate(const lockey::cert::DistinguishedName &issuer_dn,
                                                  const lockey::cert::DistinguishedName &subject_dn,
                                                  const lockey::crypto::Lockey::KeyPair &issuer_key,
                                                  const lockey::crypto::Lockey::KeyPair &subject_key, bool is_ca,
                                                  uint16_t key_usage) {
    using namespace std::chrono;
    auto now = system_clock::now();
    lockey::cert::CertificateBuilder builder;
    builder.set_serial(1)
        .set_subject(subject_dn)
        .set_issuer(issuer_dn)
        .set_validity(now - hours(1), now + hours(24))
        .set_subject_public_key_ed25519(subject_key.public_key)
        .set_key_usage(key_usage)
        .set_basic_constraints(is_ca, is_ca ? std::optional<uint32_t>(0) : std::nullopt, true);
    auto result = builder.build_ed25519(issuer_key, issuer_dn.der() == subject_dn.der());
    REQUIRE(result.success);
    return result.value;
}

inline lockey::cert::Certificate make_self_signed_certificate(const std::string &subject_cn,
                                                              lockey::crypto::Lockey::KeyPair &key_out) {
    lockey::crypto::Lockey ctx(lockey::crypto::Lockey::Algorithm::Ed25519);
    key_out = ctx.generate_keypair();
    auto dn = dn_from_string("CN=" + subject_cn);
    return make_certificate(dn, dn, key_out, key_out, true, lockey::cert::KeyUsageExtension::KeyCertSign);
}

} // namespace cert_test

