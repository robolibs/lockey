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

} // namespace keylock::hash
