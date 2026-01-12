#include "keylock/utils/common.hpp"

#include <algorithm>
#include <stdexcept>

#include "keylock/utils/sodium_utils.hpp"

namespace keylock::utils {

    std::vector<uint8_t> Common::generate_random_bytes(size_t size) {
        ensure_sodium_init();
        std::vector<uint8_t> bytes(size);
        randombytes_buf(bytes.data(), bytes.size());
        return bytes;
    }

    bool Common::secure_compare(const uint8_t *a, const uint8_t *b, size_t size) {
        uint8_t result = 0;
        for (size_t i = 0; i < size; ++i) {
            result |= a[i] ^ b[i];
        }
        return result == 0;
    }

    void Common::secure_clear(uint8_t *data, size_t size) {
        volatile uint8_t *ptr = data;
        for (size_t i = 0; i < size; ++i) {
            ptr[i] = 0;
        }
    }

    std::string Common::bytes_to_hex(const std::vector<uint8_t> &data) {
        std::string hex;
        hex.reserve(data.size() * 2);
        for (uint8_t byte : data) {
            hex.push_back(byte_to_hex_char((byte >> 4) & 0x0F));
            hex.push_back(byte_to_hex_char(byte & 0x0F));
        }
        return hex;
    }

    std::vector<uint8_t> Common::hex_to_bytes(const std::string &hex) {
        if (hex.size() % 2 != 0) {
            return {}; // Invalid: odd-length hex string
        }

        std::vector<uint8_t> bytes;
        bytes.reserve(hex.size() / 2);
        try {
            for (size_t i = 0; i < hex.size(); i += 2) {
                uint8_t byte = (hex_char_to_byte(hex[i]) << 4) | hex_char_to_byte(hex[i + 1]);
                bytes.push_back(byte);
            }
        } catch (const std::invalid_argument &) {
            // Invalid hex character encountered
            return {};
        }
        return bytes;
    }

    std::vector<uint8_t> Common::xor_bytes(const std::vector<uint8_t> &a, const std::vector<uint8_t> &b) {
        if (a.size() != b.size()) {
            throw std::invalid_argument("Arrays must be same size for XOR");
        }

        std::vector<uint8_t> result(a.size());
        for (size_t i = 0; i < a.size(); ++i) {
            result[i] = a[i] ^ b[i];
        }
        return result;
    }

    std::vector<uint8_t> Common::pkcs7_pad(const std::vector<uint8_t> &data, size_t block_size) {
        if (block_size == 0 || block_size > 255) {
            throw std::invalid_argument("Invalid block size for PKCS#7");
        }

        size_t padding_length = block_size - (data.size() % block_size);
        std::vector<uint8_t> padded = data;
        padded.resize(data.size() + padding_length, static_cast<uint8_t>(padding_length));
        return padded;
    }

    std::vector<uint8_t> Common::pkcs7_unpad(const std::vector<uint8_t> &data) {
        if (data.empty()) {
            throw std::invalid_argument("Cannot unpad empty data");
        }

        uint8_t padding_length = data.back();
        if (padding_length == 0 || padding_length > data.size()) {
            throw std::invalid_argument("Invalid PKCS#7 padding");
        }

        for (size_t i = data.size() - padding_length; i < data.size(); ++i) {
            if (data[i] != padding_length) {
                throw std::invalid_argument("Invalid PKCS#7 padding");
            }
        }

        return std::vector<uint8_t>(data.begin(), data.end() - padding_length);
    }

    uint8_t Common::hex_char_to_byte(char c) {
        if (c >= '0' && c <= '9')
            return static_cast<uint8_t>(c - '0');
        if (c >= 'A' && c <= 'F')
            return static_cast<uint8_t>(c - 'A' + 10);
        if (c >= 'a' && c <= 'f')
            return static_cast<uint8_t>(c - 'a' + 10);
        throw std::invalid_argument("Invalid hex character");
    }

    char Common::byte_to_hex_char(uint8_t b) {
        return b < 10 ? static_cast<char>('0' + b) : static_cast<char>('a' + b - 10);
    }

    std::string to_hex(const std::vector<uint8_t> &data) { return Common::bytes_to_hex(data); }

    std::vector<uint8_t> from_hex(const std::string &hex) { return Common::hex_to_bytes(hex); }

} // namespace keylock::utils
