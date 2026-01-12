#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include <sodium.h>

namespace keylock::utils {

    enum class KeyFormat { RAW, PKCS8 };

    class Common {
      public:
        static constexpr size_t XCHACHA20_KEY_SIZE = crypto_aead_xchacha20poly1305_ietf_KEYBYTES;
        static constexpr size_t XCHACHA20_NONCE_SIZE = crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
        static constexpr size_t XCHACHA20_TAG_SIZE = crypto_aead_xchacha20poly1305_ietf_ABYTES;

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

        static std::vector<uint8_t> generate_random_bytes(size_t size);
        static bool secure_compare(const uint8_t *a, const uint8_t *b, size_t size);
        static void secure_clear(uint8_t *data, size_t size);
        static std::string bytes_to_hex(const std::vector<uint8_t> &data);
        static std::vector<uint8_t> hex_to_bytes(const std::string &hex);
        static std::vector<uint8_t> xor_bytes(const std::vector<uint8_t> &a, const std::vector<uint8_t> &b);
        static std::vector<uint8_t> pkcs7_pad(const std::vector<uint8_t> &data, size_t block_size);
        static std::vector<uint8_t> pkcs7_unpad(const std::vector<uint8_t> &data);

      private:
        static uint8_t hex_char_to_byte(char c);
        static char byte_to_hex_char(uint8_t b);
    };

    std::string to_hex(const std::vector<uint8_t> &data);
    std::vector<uint8_t> from_hex(const std::string &hex);

} // namespace keylock::utils
