#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace keylock::io {

    struct LoadResult {
        bool success;
        std::vector<uint8_t> data;
        std::string error_message;
    };

    bool write_binary(const std::vector<uint8_t> &data, const std::string &path);
    LoadResult read_binary(const std::string &path);

} // namespace keylock::io
