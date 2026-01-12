#pragma once

#include <keylock/cert/certificate.hpp>
#include <keylock/crypto/context.hpp>

namespace keylock::cert {

    crypto::Context::KeyPair generate_ed25519_keypair();
    std::vector<uint8_t> spki_from_ed25519_public(const std::vector<uint8_t> &public_key);

} // namespace keylock::cert
