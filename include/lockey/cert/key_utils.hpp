#pragma once

#include <lockey/cert/certificate.hpp>
#include <lockey/crypto/context.hpp>

namespace lockey::cert {

crypto::Lockey::KeyPair generate_ed25519_keypair();
std::vector<uint8_t> spki_from_ed25519_public(const std::vector<uint8_t> &public_key);

} // namespace lockey::cert

