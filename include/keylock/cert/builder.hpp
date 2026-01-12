#pragma once

#include <chrono>
#include <optional>
#include <string>
#include <vector>

#include <keylock/cert/certificate.hpp>
#include <keylock/cert/distinguished_name.hpp>
#include <keylock/cert/oid_registry.hpp>
#include <keylock/crypto/context.hpp>

namespace keylock::cert {

    class CertificateBuilder {
      public:
        CertificateBuilder &set_version(int version);
        CertificateBuilder &set_serial(const std::vector<uint8_t> &serial);
        CertificateBuilder &set_serial(uint64_t serial);
        CertificateBuilder &set_signature_algorithm(SignatureAlgorithmId algorithm,
                                                    hash::Algorithm hash_alg = hash::Algorithm::SHA256);
        CertificateBuilder &set_issuer(const DistinguishedName &dn);
        CertificateBuilder &set_subject(const DistinguishedName &dn);
        CertificateBuilder &set_subject_from_string(std::string_view dn);
        CertificateBuilder &set_issuer_from_string(std::string_view dn);
        CertificateBuilder &set_validity(std::chrono::system_clock::time_point not_before,
                                         std::chrono::system_clock::time_point not_after);
        CertificateBuilder &set_subject_public_key_info(const SubjectPublicKeyInfo &spki);
        CertificateBuilder &set_subject_public_key_ed25519(const std::vector<uint8_t> &public_key);

        CertificateBuilder &add_extension(const RawExtension &extension);
        CertificateBuilder &set_basic_constraints(bool is_ca, std::optional<uint32_t> path_length,
                                                  bool critical = true);
        CertificateBuilder &set_key_usage(uint16_t bits, bool critical = true);
        CertificateBuilder &set_subject_alt_name(const std::vector<SubjectAltNameExtension::GeneralName> &names,
                                                 bool critical = false);
        CertificateBuilder &set_extended_key_usage(const std::vector<Oid> &purpose_oids, bool critical = false);
        CertificateBuilder &set_subject_key_identifier(const std::vector<uint8_t> &key_id, bool critical = false);
        CertificateBuilder &set_authority_key_identifier(const std::vector<uint8_t> &key_id, bool critical = false);

        CertificateResult<Certificate> build(const crypto::Context::KeyPair &issuer_key,
                                             bool self_signed = false) const;
        CertificateResult<Certificate> build_ed25519(const crypto::Context::KeyPair &issuer_key,
                                                     bool self_signed = false) const;

      private:
        std::optional<std::string> validate_inputs(bool self_signed) const;
        RawExtension build_basic_constraints_extension(bool is_ca, std::optional<uint32_t> path_length,
                                                       bool critical) const;
        RawExtension build_key_usage_extension(uint16_t bits, bool critical) const;
        RawExtension build_extended_key_usage_extension(const std::vector<Oid> &purpose_oids, bool critical) const;
        RawExtension build_subject_alt_name_extension(const std::vector<SubjectAltNameExtension::GeneralName> &names,
                                                      bool critical) const;
        RawExtension build_key_identifier_extension(const std::vector<uint8_t> &key_id, bool critical,
                                                    ExtensionId id) const;
        std::vector<uint8_t> encode_tbs_certificate(const DistinguishedName &issuer_dn) const;
        std::vector<uint8_t> encode_algorithm_identifier(const AlgorithmIdentifier &alg) const;
        std::vector<uint8_t> encode_validity(const Validity &validity) const;
        std::vector<uint8_t> encode_subject_public_key_info(const SubjectPublicKeyInfo &spki) const;
        std::vector<uint8_t> encode_extensions(const std::vector<RawExtension> &extensions) const;
        std::vector<uint8_t> encode_general_names(const std::vector<SubjectAltNameExtension::GeneralName> &names) const;

        static std::vector<uint8_t> format_time(std::chrono::system_clock::time_point tp, bool utc_time);
        static std::vector<uint8_t> serialize_time(std::chrono::system_clock::time_point tp);
        static std::vector<uint8_t> serialize_serial(const std::vector<uint8_t> &serial);
        static std::vector<uint8_t> encode_extension(const RawExtension &extension);
        static std::vector<uint8_t> encode_ip_address(const std::string &ip);

        int version_{3};
        std::vector<uint8_t> serial_number_;
        bool issuer_explicit_{false};
        bool subject_explicit_{false};
        DistinguishedName issuer_;
        DistinguishedName subject_;
        Validity validity_{};
        SubjectPublicKeyInfo subject_public_key_info_{};
        AlgorithmIdentifier signature_algorithm_{SignatureAlgorithmId::Ed25519, hash::Algorithm::SHA256,
                                                 CurveId::Ed25519};
        std::vector<RawExtension> extensions_;
    };

} // namespace keylock::cert
