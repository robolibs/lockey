#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace keylock::hash {

    enum class Algorithm { SHA256, SHA512, BLAKE2b };

    struct Result {
        bool success;
        std::vector<uint8_t> data;
        std::string error_message;
    };

    Result digest(Algorithm algo, const std::vector<uint8_t> &data);
    Result hmac(Algorithm algo, const std::vector<uint8_t> &data, const std::vector<uint8_t> &key);

    // HKDF (RFC 5869) - HMAC-based Key Derivation Function
    // Extract: PRK = HMAC(salt, IKM)
    Result hkdf_extract(Algorithm algo, const std::vector<uint8_t> &ikm, const std::vector<uint8_t> &salt = {});

    // Expand: OKM = HKDF-Expand(PRK, info, length)
    Result hkdf_expand(Algorithm algo, const std::vector<uint8_t> &prk, const std::vector<uint8_t> &info,
                       size_t length);

    // Combined: OKM = HKDF(salt, IKM, info, length)
    Result hkdf(Algorithm algo, const std::vector<uint8_t> &ikm, const std::vector<uint8_t> &salt,
                const std::vector<uint8_t> &info, size_t length);

} // namespace keylock::hash
