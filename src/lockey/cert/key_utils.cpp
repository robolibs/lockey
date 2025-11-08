#include <lockey/cert/key_utils.hpp>

#include <lockey/cert/asn1_writer.hpp>
#include <lockey/cert/oid_registry.hpp>

namespace lockey::cert {

crypto::Lockey::KeyPair generate_ed25519_keypair() {
    crypto::Lockey ctx(crypto::Lockey::Algorithm::Ed25519);
    return ctx.generate_keypair();
}

std::vector<uint8_t> spki_from_ed25519_public(const std::vector<uint8_t> &public_key) {
    auto oid = oid_for_signature(SignatureAlgorithmId::Ed25519);
    if (!oid) {
        return {};
    }
    std::vector<std::vector<uint8_t>> fields;
    fields.push_back(der::encode_sequence(der::encode_oid(*oid)));
    fields.push_back(der::encode_bit_string(ByteSpan(public_key.data(), public_key.size())));
    return der::encode_sequence(der::concat(fields));
}

} // namespace lockey::cert
