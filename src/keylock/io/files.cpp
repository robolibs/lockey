#include "keylock/io/files.hpp"

#include <fstream>

namespace keylock::io {

    bool write_binary(const std::vector<uint8_t> &data, const std::string &path) {
        try {
            std::ofstream file(path, std::ios::binary);
            if (!file) {
                return false;
            }
            file.write(reinterpret_cast<const char *>(data.data()), data.size());
            return file.good();
        } catch (...) {
            return false;
        }
    }

    LoadResult read_binary(const std::string &path) {
        try {
            std::ifstream file(path, std::ios::binary);
            if (!file) {
                return {false, {}, "Cannot open file"};
            }
            std::vector<uint8_t> data((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
            if (data.empty()) {
                return {false, {}, "File empty"};
            }
            return {true, std::move(data), ""};
        } catch (const std::exception &e) {
            return {false, {}, e.what()};
        }
    }

} // namespace keylock::io
