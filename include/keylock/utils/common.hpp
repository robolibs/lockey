#pragma once

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

#include <sodium.h>

#include "keylock/utils/sodium_utils.hpp"

namespace keylock::utils {

    enum class KeyFormat { RAW, PKCS8 };

    class Common {
      public:
        static constexpr size_t XCHACHA20_KEY_SIZE = crypto_aead_xchacha20poly1305_ietf_KEYBYTES;
        static constexpr size_t XCHACHA20_NONCE_SIZE = crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
        static constexpr size_t XCHACHA20_TAG_SIZE = crypto_aead_xchacha20poly1305_ietf_ABYTES;

        // ChaCha20-Poly1305 IETF (RFC 8439) - 96-bit nonce
        static constexpr size_t CHACHA20_IETF_KEY_SIZE = crypto_aead_chacha20poly1305_ietf_KEYBYTES;
        static constexpr size_t CHACHA20_IETF_NONCE_SIZE = crypto_aead_chacha20poly1305_ietf_NPUBBYTES;
        static constexpr size_t CHACHA20_IETF_TAG_SIZE = crypto_aead_chacha20poly1305_ietf_ABYTES;

        // AES-256-GCM (requires AES-NI hardware)
        static constexpr size_t AES256_GCM_KEY_SIZE = crypto_aead_aes256gcm_KEYBYTES;
        static constexpr size_t AES256_GCM_NONCE_SIZE = crypto_aead_aes256gcm_NPUBBYTES;
        static constexpr size_t AES256_GCM_TAG_SIZE = crypto_aead_aes256gcm_ABYTES;

        static constexpr size_t SECRETBOX_KEY_SIZE = crypto_secretbox_KEYBYTES;
        static constexpr size_t SECRETBOX_NONCE_SIZE = crypto_secretbox_NONCEBYTES;
        static constexpr size_t SECRETBOX_MAC_SIZE = crypto_secretbox_MACBYTES;

        static constexpr size_t X25519_PUBLIC_KEY_SIZE = crypto_box_PUBLICKEYBYTES;
        static constexpr size_t X25519_PRIVATE_KEY_SIZE = crypto_box_PUBLICKEYBYTES + crypto_box_SECRETKEYBYTES;

        static constexpr size_t ED25519_PUBLIC_KEY_SIZE = crypto_sign_ed25519_PUBLICKEYBYTES;
        static constexpr size_t ED25519_PRIVATE_KEY_SIZE = crypto_sign_ed25519_SECRETKEYBYTES;

        static constexpr size_t SHA256_DIGEST_SIZE = crypto_hash_sha256_BYTES;
        static constexpr size_t SHA512_DIGEST_SIZE = crypto_hash_sha512_BYTES;
        static constexpr size_t BLAKE2B_DIGEST_SIZE = crypto_generichash_BYTES;

        static inline std::vector<uint8_t> generate_random_bytes(size_t size) {
            ensure_sodium_init();
            std::vector<uint8_t> bytes(size);
            randombytes_buf(bytes.data(), bytes.size());
            return bytes;
        }

        static inline bool secure_compare(const uint8_t *a, const uint8_t *b, size_t size) {
            uint8_t result = 0;
            for (size_t i = 0; i < size; ++i) {
                result |= a[i] ^ b[i];
            }
            return result == 0;
        }

        static inline void secure_clear(uint8_t *data, size_t size) {
            volatile uint8_t *ptr = data;
            for (size_t i = 0; i < size; ++i) {
                ptr[i] = 0;
            }
        }

        static inline std::string bytes_to_hex(const std::vector<uint8_t> &data) {
            std::string hex;
            hex.reserve(data.size() * 2);
            for (uint8_t byte : data) {
                hex.push_back(byte_to_hex_char((byte >> 4) & 0x0F));
                hex.push_back(byte_to_hex_char(byte & 0x0F));
            }
            return hex;
        }

        static inline std::vector<uint8_t> hex_to_bytes(const std::string &hex) {
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

        static inline std::vector<uint8_t> xor_bytes(const std::vector<uint8_t> &a, const std::vector<uint8_t> &b) {
            if (a.size() != b.size()) {
                throw std::invalid_argument("Arrays must be same size for XOR");
            }

            std::vector<uint8_t> result(a.size());
            for (size_t i = 0; i < a.size(); ++i) {
                result[i] = a[i] ^ b[i];
            }
            return result;
        }

        static inline std::vector<uint8_t> pkcs7_pad(const std::vector<uint8_t> &data, size_t block_size) {
            if (block_size == 0 || block_size > 255) {
                throw std::invalid_argument("Invalid block size for PKCS#7");
            }

            size_t padding_length = block_size - (data.size() % block_size);
            std::vector<uint8_t> padded = data;
            padded.resize(data.size() + padding_length, static_cast<uint8_t>(padding_length));
            return padded;
        }

        static inline std::vector<uint8_t> pkcs7_unpad(const std::vector<uint8_t> &data) {
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

      private:
        static inline uint8_t hex_char_to_byte(char c) {
            if (c >= '0' && c <= '9')
                return static_cast<uint8_t>(c - '0');
            if (c >= 'A' && c <= 'F')
                return static_cast<uint8_t>(c - 'A' + 10);
            if (c >= 'a' && c <= 'f')
                return static_cast<uint8_t>(c - 'a' + 10);
            throw std::invalid_argument("Invalid hex character");
        }

        static inline char byte_to_hex_char(uint8_t b) {
            return b < 10 ? static_cast<char>('0' + b) : static_cast<char>('a' + b - 10);
        }
    };

    inline std::string to_hex(const std::vector<uint8_t> &data) { return Common::bytes_to_hex(data); }

    inline std::vector<uint8_t> from_hex(const std::string &hex) { return Common::hex_to_bytes(hex); }

} // namespace keylock::utils
