#pragma once

#include <chrono>
#include <tuple>

#include <doctest/doctest.h>

#include <lockey/cert/builder.hpp>
#include <lockey/cert/key_utils.hpp>

namespace cert_test {

    inline std::chrono::system_clock::time_point fixed_time() {
        // Return a fixed time for deterministic tests (2024-01-01 00:00:00 UTC)
        return std::chrono::system_clock::from_time_t(1704067200);
    }

    inline lockey::cert::DistinguishedName dn_from_string(std::string_view str) {
        auto parsed = lockey::cert::DistinguishedName::from_string(str);
        REQUIRE(parsed.success);
        return parsed.value;
    }

    inline lockey::cert::Certificate make_certificate(const lockey::cert::DistinguishedName &issuer_dn,
                                                      const lockey::cert::DistinguishedName &subject_dn,
                                                      const lockey::crypto::Lockey::KeyPair &issuer_key,
                                                      const lockey::crypto::Lockey::KeyPair &subject_key, bool is_ca,
                                                      uint16_t key_usage, uint64_t serial = 1) {
        using namespace std::chrono;
        lockey::cert::CertificateBuilder builder;
        builder.set_serial(serial)
            .set_subject(subject_dn)
            .set_issuer(issuer_dn)
            .set_validity(system_clock::now() - hours(1), system_clock::now() + hours(24))
            .set_subject_public_key_ed25519(subject_key.public_key)
            .set_key_usage(key_usage)
            .set_basic_constraints(is_ca, std::nullopt, true);
        auto result = builder.build_ed25519(issuer_key, issuer_dn.der() == subject_dn.der());
        REQUIRE(result.success);
        return result.value;
    }

    inline lockey::cert::Certificate make_self_signed_certificate(const std::string &subject_cn,
                                                                  lockey::crypto::Lockey::KeyPair &key_out,
                                                                  uint64_t serial = 1) {
        lockey::crypto::Lockey ctx(lockey::crypto::Lockey::Algorithm::Ed25519);
        key_out = ctx.generate_keypair();
        auto dn = dn_from_string("CN=" + subject_cn);
        return make_certificate(dn, dn, key_out, key_out, true, lockey::cert::KeyUsageExtension::KeyCertSign, serial);
    }

    inline lockey::cert::Certificate make_self_signed_certificate_with_key(const lockey::cert::DistinguishedName &dn,
                                                                           const lockey::crypto::Lockey::KeyPair &key,
                                                                           uint64_t serial) {
        return make_certificate(dn, dn, key, key, true, lockey::cert::KeyUsageExtension::KeyCertSign, serial);
    }

    inline std::tuple<lockey::cert::Certificate, lockey::cert::Certificate, lockey::cert::Certificate>
    make_chain(lockey::crypto::Lockey::KeyPair &root_key, lockey::crypto::Lockey::KeyPair &intermediate_key,
               lockey::crypto::Lockey::KeyPair &leaf_key) {
        auto root = make_self_signed_certificate("Test Root", root_key, 10);
        lockey::crypto::Lockey ctx(lockey::crypto::Lockey::Algorithm::Ed25519);
        intermediate_key = ctx.generate_keypair();
        auto intermediate_dn = dn_from_string("CN=Test Intermediate");
        auto intermediate = make_certificate(root.tbs().subject, intermediate_dn, root_key, intermediate_key, true,
                                             lockey::cert::KeyUsageExtension::KeyCertSign, 11);
        leaf_key = ctx.generate_keypair();
        auto leaf_dn = dn_from_string("CN=Test Leaf");
        auto leaf = make_certificate(intermediate_dn, leaf_dn, intermediate_key, leaf_key, false,
                                     lockey::cert::KeyUsageExtension::DigitalSignature, 12);
        return {root, intermediate, leaf};
    }

} // namespace cert_test
