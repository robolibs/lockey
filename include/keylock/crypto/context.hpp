#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "keylock/hash/algorithms.hpp"
#include "keylock/utils/common.hpp"

namespace keylock::crypto {

    class Context {
      public:
        using HashAlgorithm = hash::Algorithm;

        enum class Algorithm { XChaCha20_Poly1305, SecretBox_XSalsa20, X25519_Box, Ed25519 };

        enum class KeyType { PUBLIC, PRIVATE };

        struct CryptoResult {
            bool success;
            std::vector<uint8_t> data;
            std::string error_message;
        };

        struct KeyPair {
            std::vector<uint8_t> public_key;
            std::vector<uint8_t> private_key;
            Algorithm algorithm;
        };

        explicit Context(Algorithm algorithm = Algorithm::XChaCha20_Poly1305,
                         HashAlgorithm hash_algo = HashAlgorithm::SHA256);

        void set_algorithm(Algorithm algorithm);
        void set_hash_algorithm(HashAlgorithm hash_algo);

        [[nodiscard]] Algorithm get_algorithm() const;
        [[nodiscard]] HashAlgorithm get_hash_algorithm() const;

        CryptoResult encrypt(const std::vector<uint8_t> &plaintext, const std::vector<uint8_t> &key,
                             const std::vector<uint8_t> &associated_data = {});
        CryptoResult decrypt(const std::vector<uint8_t> &ciphertext, const std::vector<uint8_t> &key,
                             const std::vector<uint8_t> &associated_data = {});

        CryptoResult encrypt_asymmetric(const std::vector<uint8_t> &plaintext, const std::vector<uint8_t> &public_key);
        CryptoResult decrypt_asymmetric(const std::vector<uint8_t> &ciphertext,
                                        const std::vector<uint8_t> &private_key);

        CryptoResult sign(const std::vector<uint8_t> &data, const std::vector<uint8_t> &private_key);
        CryptoResult verify(const std::vector<uint8_t> &data, const std::vector<uint8_t> &signature,
                            const std::vector<uint8_t> &public_key);

        KeyPair generate_keypair();
        CryptoResult generate_symmetric_key(size_t key_size = 32);

        CryptoResult hash(const std::vector<uint8_t> &data);
        CryptoResult hmac(const std::vector<uint8_t> &data, const std::vector<uint8_t> &key);

        bool save_key_to_file(const std::vector<uint8_t> &key, const std::string &filename, KeyType key_type,
                              utils::KeyFormat format = utils::KeyFormat::RAW);
        CryptoResult load_key_from_file(const std::string &filename, KeyType key_type);
        bool save_keypair_to_files(const KeyPair &keypair, const std::string &public_filename,
                                   const std::string &private_filename,
                                   utils::KeyFormat format = utils::KeyFormat::RAW);
        CryptoResult load_keypair_from_files(const std::string &public_filename, const std::string &private_filename);

        static std::string to_hex(const std::vector<uint8_t> &data);
        static std::vector<uint8_t> from_hex(const std::string &hex);

        static std::string algorithm_to_string(Algorithm algorithm);
        static std::string hash_algorithm_to_string(HashAlgorithm hash_algo);

      private:
        Algorithm current_algorithm_;
        HashAlgorithm current_hash_;

        std::optional<size_t> expected_key_size(KeyType key_type) const;
        bool is_symmetric_algorithm(Algorithm algo) const;
        bool is_asymmetric_algorithm(Algorithm algo) const;
        bool is_signature_algorithm(Algorithm algo) const;
    };

} // namespace keylock::crypto
