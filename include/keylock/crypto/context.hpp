#pragma once

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <fstream>
#include <iterator>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

#include <sodium.h>

#include "keylock/hash/algorithms.hpp"
#include "keylock/io/files.hpp"
#include "keylock/utils/common.hpp"
#include "keylock/utils/sodium_utils.hpp"

namespace keylock::crypto {

    namespace detail {

        inline std::vector<uint8_t> normalize_key(const std::vector<uint8_t> &key, size_t required) {
            if (key.size() == required) {
                return key;
            }

            std::vector<uint8_t> normalized(required);
            crypto_generichash(normalized.data(), normalized.size(), key.data(), key.size(), nullptr, 0);
            return normalized;
        }

    } // namespace detail

    class Context {
      public:
        using HashAlgorithm = hash::Algorithm;

        enum class Algorithm {
            XChaCha20_Poly1305, // 24-byte nonce (extended nonce)
            ChaCha20_Poly1305,  // 12-byte nonce (IETF RFC 8439)
            AES256_GCM,         // 12-byte nonce (requires AES-NI hardware)
            SecretBox_XSalsa20,
            X25519_Box,
            Ed25519
        };

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
                         HashAlgorithm hash_algo = HashAlgorithm::SHA256)
            : current_algorithm_(algorithm), current_hash_(hash_algo) {
            utils::ensure_sodium_init();
        }

        void set_algorithm(Algorithm algorithm) { current_algorithm_ = algorithm; }

        void set_hash_algorithm(HashAlgorithm hash_algo) { current_hash_ = hash_algo; }

        [[nodiscard]] Algorithm get_algorithm() const { return current_algorithm_; }

        [[nodiscard]] HashAlgorithm get_hash_algorithm() const { return current_hash_; }

        CryptoResult encrypt(const std::vector<uint8_t> &plaintext, const std::vector<uint8_t> &key,
                             const std::vector<uint8_t> &associated_data = {}) {
            if (!is_symmetric_algorithm(current_algorithm_)) {
                return {false, {}, "Current algorithm is not suitable for symmetric encryption"};
            }

            utils::ensure_sodium_init();

            switch (current_algorithm_) {
            case Algorithm::XChaCha20_Poly1305:
                return aead_xchacha_encrypt(plaintext, key, associated_data);
            case Algorithm::ChaCha20_Poly1305:
                return aead_chacha_ietf_encrypt(plaintext, key, associated_data);
            case Algorithm::AES256_GCM:
                return aead_aes256gcm_encrypt(plaintext, key, associated_data);
            case Algorithm::SecretBox_XSalsa20:
                return secretbox_encrypt(plaintext, key);
            default:
                return {false, {}, "Unsupported symmetric algorithm"};
            }
        }

        CryptoResult decrypt(const std::vector<uint8_t> &ciphertext, const std::vector<uint8_t> &key,
                             const std::vector<uint8_t> &associated_data = {}) {
            if (!is_symmetric_algorithm(current_algorithm_)) {
                return {false, {}, "Current algorithm is not suitable for symmetric decryption"};
            }

            utils::ensure_sodium_init();

            switch (current_algorithm_) {
            case Algorithm::XChaCha20_Poly1305:
                return aead_xchacha_decrypt(ciphertext, key, associated_data);
            case Algorithm::ChaCha20_Poly1305:
                return aead_chacha_ietf_decrypt(ciphertext, key, associated_data);
            case Algorithm::AES256_GCM:
                return aead_aes256gcm_decrypt(ciphertext, key, associated_data);
            case Algorithm::SecretBox_XSalsa20:
                return secretbox_decrypt(ciphertext, key);
            default:
                return {false, {}, "Unsupported symmetric algorithm"};
            }
        }

        CryptoResult encrypt_asymmetric(const std::vector<uint8_t> &plaintext, const std::vector<uint8_t> &public_key) {
            if (!is_asymmetric_algorithm(current_algorithm_)) {
                return {false, {}, "Current algorithm does not support asymmetric encryption"};
            }

            utils::ensure_sodium_init();

            if (public_key.size() != crypto_box_PUBLICKEYBYTES) {
                return {false, {}, "Invalid public key size"};
            }

            std::vector<uint8_t> ciphertext(plaintext.size() + crypto_box_SEALBYTES);
            if (crypto_box_seal(ciphertext.data(), plaintext.data(), plaintext.size(), public_key.data()) != 0) {
                return {false, {}, "crypto_box_seal failed"};
            }

            return {true, ciphertext, ""};
        }

        CryptoResult decrypt_asymmetric(const std::vector<uint8_t> &ciphertext,
                                        const std::vector<uint8_t> &private_key) {
            if (!is_asymmetric_algorithm(current_algorithm_)) {
                return {false, {}, "Current algorithm does not support asymmetric decryption"};
            }

            utils::ensure_sodium_init();

            if (private_key.size() != crypto_box_PUBLICKEYBYTES + crypto_box_SECRETKEYBYTES) {
                return {false, {}, "Invalid private key material"};
            }

            if (ciphertext.size() < crypto_box_SEALBYTES) {
                return {false, {}, "Ciphertext too short"};
            }

            std::vector<uint8_t> plaintext(ciphertext.size() - crypto_box_SEALBYTES);
            const uint8_t *pub = private_key.data();
            const uint8_t *sec = private_key.data() + crypto_box_PUBLICKEYBYTES;
            if (crypto_box_seal_open(plaintext.data(), ciphertext.data(), ciphertext.size(), pub, sec) != 0) {
                return {false, {}, "Decryption failed"};
            }

            return {true, plaintext, ""};
        }

        CryptoResult sign(const std::vector<uint8_t> &data, const std::vector<uint8_t> &private_key) {
            if (!is_signature_algorithm(current_algorithm_)) {
                return {false, {}, "Current algorithm does not support signing"};
            }

            utils::ensure_sodium_init();

            if (private_key.size() != crypto_sign_ed25519_SECRETKEYBYTES) {
                return {false, {}, "Invalid private key size"};
            }

            std::vector<uint8_t> signature(crypto_sign_ed25519_BYTES);
            unsigned long long sig_len = 0;
            if (crypto_sign_ed25519_detached(signature.data(), &sig_len, data.data(), data.size(),
                                             private_key.data()) != 0) {
                return {false, {}, "Ed25519 signing failed"};
            }

            signature.resize(sig_len);
            return {true, signature, ""};
        }

        CryptoResult verify(const std::vector<uint8_t> &data, const std::vector<uint8_t> &signature,
                            const std::vector<uint8_t> &public_key) {
            if (!is_signature_algorithm(current_algorithm_)) {
                return {false, {}, "Current algorithm does not support verification"};
            }

            utils::ensure_sodium_init();

            if (public_key.size() != crypto_sign_ed25519_PUBLICKEYBYTES) {
                return {false, {}, "Invalid public key size"};
            }

            int rc = crypto_sign_ed25519_verify_detached(signature.data(), data.data(), data.size(), public_key.data());
            return {rc == 0, {}, rc == 0 ? "" : "Ed25519 signature verification failed"};
        }

        KeyPair generate_keypair() {
            utils::ensure_sodium_init();

            switch (current_algorithm_) {
            case Algorithm::X25519_Box: {
                std::vector<uint8_t> pub(crypto_box_PUBLICKEYBYTES);
                std::vector<uint8_t> sec(crypto_box_SECRETKEYBYTES);
                if (crypto_box_keypair(pub.data(), sec.data()) != 0) {
                    throw std::runtime_error("Failed to generate X25519 keypair");
                }
                KeyPair pair;
                pair.algorithm = current_algorithm_;
                pair.public_key = pub;
                pair.private_key = pub;
                pair.private_key.insert(pair.private_key.end(), sec.begin(), sec.end());
                return pair;
            }
            case Algorithm::Ed25519: {
                std::vector<uint8_t> pub(crypto_sign_ed25519_PUBLICKEYBYTES);
                std::vector<uint8_t> sec(crypto_sign_ed25519_SECRETKEYBYTES);
                if (crypto_sign_ed25519_keypair(pub.data(), sec.data()) != 0) {
                    throw std::runtime_error("Failed to generate Ed25519 keypair");
                }
                KeyPair pair;
                pair.algorithm = current_algorithm_;
                pair.public_key = std::move(pub);
                pair.private_key = std::move(sec);
                return pair;
            }
            default:
                throw std::runtime_error("Key generation not supported for this algorithm");
            }
        }

        CryptoResult generate_symmetric_key(size_t key_size = 32) {
            try {
                utils::ensure_sodium_init();
                std::vector<uint8_t> key(key_size);
                randombytes_buf(key.data(), key.size());
                return {true, key, ""};
            } catch (const std::exception &e) {
                return {false, {}, e.what()};
            }
        }

        CryptoResult hash(const std::vector<uint8_t> &data) {
            auto result = ::keylock::hash::digest(current_hash_, data);
            return {result.success, std::move(result.data), std::move(result.error_message)};
        }

        CryptoResult hmac(const std::vector<uint8_t> &data, const std::vector<uint8_t> &key) {
            auto result = ::keylock::hash::hmac(current_hash_, data, key);
            return {result.success, std::move(result.data), std::move(result.error_message)};
        }

        bool save_key_to_file(const std::vector<uint8_t> &key, const std::string &filename, KeyType key_type,
                              utils::KeyFormat format = utils::KeyFormat::RAW);

        CryptoResult load_key_from_file(const std::string &filename, KeyType key_type);

        bool save_keypair_to_files(const KeyPair &keypair, const std::string &public_filename,
                                   const std::string &private_filename,
                                   utils::KeyFormat format = utils::KeyFormat::RAW) {
            return save_key_to_file(keypair.public_key, public_filename, KeyType::PUBLIC, format) &&
                   save_key_to_file(keypair.private_key, private_filename, KeyType::PRIVATE, format);
        }

        CryptoResult load_keypair_from_files(const std::string &public_filename, const std::string &private_filename) {
            auto pub = load_key_from_file(public_filename, KeyType::PUBLIC);
            if (!pub.success)
                return pub;

            auto priv = load_key_from_file(private_filename, KeyType::PRIVATE);
            if (!priv.success)
                return priv;

            return {true, priv.data, ""};
        }

        static std::string to_hex(const std::vector<uint8_t> &data) { return utils::Common::bytes_to_hex(data); }

        static std::vector<uint8_t> from_hex(const std::string &hex) { return utils::Common::hex_to_bytes(hex); }

        static std::string algorithm_to_string(Algorithm algorithm) {
            switch (algorithm) {
            case Algorithm::XChaCha20_Poly1305:
                return "XChaCha20-Poly1305";
            case Algorithm::ChaCha20_Poly1305:
                return "ChaCha20-Poly1305-IETF";
            case Algorithm::AES256_GCM:
                return "AES-256-GCM";
            case Algorithm::SecretBox_XSalsa20:
                return "SecretBox-XSalsa20-Poly1305";
            case Algorithm::X25519_Box:
                return "X25519-Box";
            case Algorithm::Ed25519:
                return "Ed25519";
            }
            return "Unknown";
        }

        static bool is_aes_gcm_available() {
            utils::ensure_sodium_init();
            return crypto_aead_aes256gcm_is_available() != 0;
        }

        static std::string hash_algorithm_to_string(HashAlgorithm hash_algo) {
            switch (hash_algo) {
            case HashAlgorithm::SHA256:
                return "SHA-256";
            case HashAlgorithm::SHA512:
                return "SHA-512";
            case HashAlgorithm::BLAKE2b:
                return "BLAKE2b";
            }
            return "Unknown";
        }

      private:
        Algorithm current_algorithm_;
        HashAlgorithm current_hash_;

        std::optional<size_t> expected_key_size(KeyType key_type) const {
            switch (current_algorithm_) {
            case Algorithm::X25519_Box:
                if (key_type == KeyType::PUBLIC)
                    return crypto_box_PUBLICKEYBYTES;
                return crypto_box_PUBLICKEYBYTES + crypto_box_SECRETKEYBYTES;
            case Algorithm::Ed25519:
                if (key_type == KeyType::PUBLIC)
                    return crypto_sign_ed25519_PUBLICKEYBYTES;
                return crypto_sign_ed25519_SECRETKEYBYTES;
            case Algorithm::XChaCha20_Poly1305:
            case Algorithm::ChaCha20_Poly1305:
            case Algorithm::AES256_GCM:
            case Algorithm::SecretBox_XSalsa20:
                break;
            }
            return std::nullopt;
        }

        bool is_symmetric_algorithm(Algorithm algo) const {
            return algo == Algorithm::XChaCha20_Poly1305 || algo == Algorithm::ChaCha20_Poly1305 ||
                   algo == Algorithm::AES256_GCM || algo == Algorithm::SecretBox_XSalsa20;
        }

        bool is_asymmetric_algorithm(Algorithm algo) const { return algo == Algorithm::X25519_Box; }

        bool is_signature_algorithm(Algorithm algo) const { return algo == Algorithm::Ed25519; }

        CryptoResult aead_xchacha_encrypt(const std::vector<uint8_t> &plaintext, const std::vector<uint8_t> &key,
                                          const std::vector<uint8_t> &aad) {
            try {
                auto normalized_key = detail::normalize_key(key, crypto_aead_xchacha20poly1305_ietf_KEYBYTES);

                std::vector<uint8_t> nonce(crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
                randombytes_buf(nonce.data(), nonce.size());

                std::vector<uint8_t> ciphertext(plaintext.size() + crypto_aead_xchacha20poly1305_ietf_ABYTES);
                unsigned long long ciphertext_len = 0;

                if (crypto_aead_xchacha20poly1305_ietf_encrypt(ciphertext.data(), &ciphertext_len, plaintext.data(),
                                                               plaintext.size(), aad.data(), aad.size(), nullptr,
                                                               nonce.data(), normalized_key.data()) != 0) {
                    return {false, {}, "AEAD encryption failed"};
                }

                ciphertext.resize(ciphertext_len);
                std::vector<uint8_t> result;
                result.reserve(nonce.size() + ciphertext.size());
                result.insert(result.end(), nonce.begin(), nonce.end());
                result.insert(result.end(), ciphertext.begin(), ciphertext.end());
                return {true, result, ""};
            } catch (const std::exception &e) {
                return {false, {}, e.what()};
            }
        }

        CryptoResult aead_xchacha_decrypt(const std::vector<uint8_t> &ciphertext_with_nonce,
                                          const std::vector<uint8_t> &key, const std::vector<uint8_t> &aad) {
            try {
                if (ciphertext_with_nonce.size() <
                    crypto_aead_xchacha20poly1305_ietf_NPUBBYTES + crypto_aead_xchacha20poly1305_ietf_ABYTES) {
                    return {false, {}, "Ciphertext too short"};
                }

                auto normalized_key = detail::normalize_key(key, crypto_aead_xchacha20poly1305_ietf_KEYBYTES);
                std::vector<uint8_t> nonce(ciphertext_with_nonce.begin(),
                                           ciphertext_with_nonce.begin() +
                                               crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
                std::vector<uint8_t> ciphertext(ciphertext_with_nonce.begin() +
                                                    crypto_aead_xchacha20poly1305_ietf_NPUBBYTES,
                                                ciphertext_with_nonce.end());

                if (ciphertext.size() < crypto_aead_xchacha20poly1305_ietf_ABYTES) {
                    return {false, {}, "Ciphertext too short"};
                }

                std::vector<uint8_t> plaintext(ciphertext.size() - crypto_aead_xchacha20poly1305_ietf_ABYTES);
                unsigned long long plaintext_len = 0;

                if (crypto_aead_xchacha20poly1305_ietf_decrypt(plaintext.data(), &plaintext_len, nullptr,
                                                               ciphertext.data(), ciphertext.size(), aad.data(),
                                                               aad.size(), nonce.data(), normalized_key.data()) != 0) {
                    return {false, {}, "Authentication failed"};
                }

                plaintext.resize(plaintext_len);
                return {true, plaintext, ""};
            } catch (const std::exception &e) {
                return {false, {}, e.what()};
            }
        }

        CryptoResult aead_chacha_ietf_encrypt(const std::vector<uint8_t> &plaintext, const std::vector<uint8_t> &key,
                                              const std::vector<uint8_t> &aad) {
            try {
                auto normalized_key = detail::normalize_key(key, crypto_aead_chacha20poly1305_ietf_KEYBYTES);

                std::vector<uint8_t> nonce(crypto_aead_chacha20poly1305_ietf_NPUBBYTES);
                randombytes_buf(nonce.data(), nonce.size());

                std::vector<uint8_t> ciphertext(plaintext.size() + crypto_aead_chacha20poly1305_ietf_ABYTES);
                unsigned long long ciphertext_len = 0;

                if (crypto_aead_chacha20poly1305_ietf_encrypt(ciphertext.data(), &ciphertext_len, plaintext.data(),
                                                              plaintext.size(), aad.data(), aad.size(), nullptr,
                                                              nonce.data(), normalized_key.data()) != 0) {
                    return {false, {}, "ChaCha20-Poly1305 IETF encryption failed"};
                }

                ciphertext.resize(ciphertext_len);
                std::vector<uint8_t> result;
                result.reserve(nonce.size() + ciphertext.size());
                result.insert(result.end(), nonce.begin(), nonce.end());
                result.insert(result.end(), ciphertext.begin(), ciphertext.end());
                return {true, result, ""};
            } catch (const std::exception &e) {
                return {false, {}, e.what()};
            }
        }

        CryptoResult aead_chacha_ietf_decrypt(const std::vector<uint8_t> &ciphertext_with_nonce,
                                              const std::vector<uint8_t> &key, const std::vector<uint8_t> &aad) {
            try {
                if (ciphertext_with_nonce.size() <
                    crypto_aead_chacha20poly1305_ietf_NPUBBYTES + crypto_aead_chacha20poly1305_ietf_ABYTES) {
                    return {false, {}, "Ciphertext too short"};
                }

                auto normalized_key = detail::normalize_key(key, crypto_aead_chacha20poly1305_ietf_KEYBYTES);
                std::vector<uint8_t> nonce(ciphertext_with_nonce.begin(),
                                           ciphertext_with_nonce.begin() + crypto_aead_chacha20poly1305_ietf_NPUBBYTES);
                std::vector<uint8_t> ciphertext(ciphertext_with_nonce.begin() +
                                                    crypto_aead_chacha20poly1305_ietf_NPUBBYTES,
                                                ciphertext_with_nonce.end());

                if (ciphertext.size() < crypto_aead_chacha20poly1305_ietf_ABYTES) {
                    return {false, {}, "Ciphertext too short"};
                }

                std::vector<uint8_t> plaintext(ciphertext.size() - crypto_aead_chacha20poly1305_ietf_ABYTES);
                unsigned long long plaintext_len = 0;

                if (crypto_aead_chacha20poly1305_ietf_decrypt(plaintext.data(), &plaintext_len, nullptr,
                                                              ciphertext.data(), ciphertext.size(), aad.data(),
                                                              aad.size(), nonce.data(), normalized_key.data()) != 0) {
                    return {false, {}, "Authentication failed"};
                }

                plaintext.resize(plaintext_len);
                return {true, plaintext, ""};
            } catch (const std::exception &e) {
                return {false, {}, e.what()};
            }
        }

        CryptoResult aead_aes256gcm_encrypt(const std::vector<uint8_t> &plaintext, const std::vector<uint8_t> &key,
                                            const std::vector<uint8_t> &aad) {
            try {
                if (crypto_aead_aes256gcm_is_available() == 0) {
                    return {false, {}, "AES-GCM not available (requires AES-NI hardware support)"};
                }

                auto normalized_key = detail::normalize_key(key, crypto_aead_aes256gcm_KEYBYTES);

                std::vector<uint8_t> nonce(crypto_aead_aes256gcm_NPUBBYTES);
                randombytes_buf(nonce.data(), nonce.size());

                std::vector<uint8_t> ciphertext(plaintext.size() + crypto_aead_aes256gcm_ABYTES);
                unsigned long long ciphertext_len = 0;

                if (crypto_aead_aes256gcm_encrypt(ciphertext.data(), &ciphertext_len, plaintext.data(),
                                                  plaintext.size(), aad.data(), aad.size(), nullptr, nonce.data(),
                                                  normalized_key.data()) != 0) {
                    return {false, {}, "AES-256-GCM encryption failed"};
                }

                ciphertext.resize(ciphertext_len);
                std::vector<uint8_t> result;
                result.reserve(nonce.size() + ciphertext.size());
                result.insert(result.end(), nonce.begin(), nonce.end());
                result.insert(result.end(), ciphertext.begin(), ciphertext.end());
                return {true, result, ""};
            } catch (const std::exception &e) {
                return {false, {}, e.what()};
            }
        }

        CryptoResult aead_aes256gcm_decrypt(const std::vector<uint8_t> &ciphertext_with_nonce,
                                            const std::vector<uint8_t> &key, const std::vector<uint8_t> &aad) {
            try {
                if (crypto_aead_aes256gcm_is_available() == 0) {
                    return {false, {}, "AES-GCM not available (requires AES-NI hardware support)"};
                }

                if (ciphertext_with_nonce.size() < crypto_aead_aes256gcm_NPUBBYTES + crypto_aead_aes256gcm_ABYTES) {
                    return {false, {}, "Ciphertext too short"};
                }

                auto normalized_key = detail::normalize_key(key, crypto_aead_aes256gcm_KEYBYTES);
                std::vector<uint8_t> nonce(ciphertext_with_nonce.begin(),
                                           ciphertext_with_nonce.begin() + crypto_aead_aes256gcm_NPUBBYTES);
                std::vector<uint8_t> ciphertext(ciphertext_with_nonce.begin() + crypto_aead_aes256gcm_NPUBBYTES,
                                                ciphertext_with_nonce.end());

                if (ciphertext.size() < crypto_aead_aes256gcm_ABYTES) {
                    return {false, {}, "Ciphertext too short"};
                }

                std::vector<uint8_t> plaintext(ciphertext.size() - crypto_aead_aes256gcm_ABYTES);
                unsigned long long plaintext_len = 0;

                if (crypto_aead_aes256gcm_decrypt(plaintext.data(), &plaintext_len, nullptr, ciphertext.data(),
                                                  ciphertext.size(), aad.data(), aad.size(), nonce.data(),
                                                  normalized_key.data()) != 0) {
                    return {false, {}, "Authentication failed"};
                }

                plaintext.resize(plaintext_len);
                return {true, plaintext, ""};
            } catch (const std::exception &e) {
                return {false, {}, e.what()};
            }
        }

        CryptoResult secretbox_encrypt(const std::vector<uint8_t> &plaintext, const std::vector<uint8_t> &key) {
            try {
                auto normalized_key = detail::normalize_key(key, crypto_secretbox_KEYBYTES);
                std::vector<uint8_t> nonce(crypto_secretbox_NONCEBYTES);
                randombytes_buf(nonce.data(), nonce.size());

                std::vector<uint8_t> ciphertext(crypto_secretbox_NONCEBYTES + crypto_secretbox_MACBYTES +
                                                plaintext.size());
                std::copy(nonce.begin(), nonce.end(), ciphertext.begin());

                if (crypto_secretbox_easy(ciphertext.data() + crypto_secretbox_NONCEBYTES, plaintext.data(),
                                          plaintext.size(), nonce.data(), normalized_key.data()) != 0) {
                    return {false, {}, "SecretBox encryption failed"};
                }

                return {true, ciphertext, ""};
            } catch (const std::exception &e) {
                return {false, {}, e.what()};
            }
        }

        CryptoResult secretbox_decrypt(const std::vector<uint8_t> &ciphertext_with_nonce,
                                       const std::vector<uint8_t> &key) {
            try {
                if (ciphertext_with_nonce.size() < crypto_secretbox_NONCEBYTES + crypto_secretbox_MACBYTES) {
                    return {false, {}, "Ciphertext too short"};
                }

                auto normalized_key = detail::normalize_key(key, crypto_secretbox_KEYBYTES);
                std::vector<uint8_t> nonce(ciphertext_with_nonce.begin(),
                                           ciphertext_with_nonce.begin() + crypto_secretbox_NONCEBYTES);
                std::vector<uint8_t> ciphertext(ciphertext_with_nonce.begin() + crypto_secretbox_NONCEBYTES,
                                                ciphertext_with_nonce.end());

                std::vector<uint8_t> plaintext(ciphertext.size() - crypto_secretbox_MACBYTES);
                if (crypto_secretbox_open_easy(plaintext.data(), ciphertext.data(), ciphertext.size(), nonce.data(),
                                               normalized_key.data()) != 0) {
                    return {false, {}, "SecretBox decryption failed"};
                }

                return {true, plaintext, ""};
            } catch (const std::exception &e) {
                return {false, {}, e.what()};
            }
        }
    };

} // namespace keylock::crypto

// Include dependencies for save/load functions after Context is defined
#include "keylock/cert/asn1_utils.hpp"
#include "keylock/cert/asn1_writer.hpp"
#include "keylock/cert/pem.hpp"

namespace keylock::crypto {

    inline bool Context::save_key_to_file(const std::vector<uint8_t> &key, const std::string &filename,
                                          KeyType key_type, utils::KeyFormat format) {
        // Support PKCS#8 PEM for Ed25519 private keys only (unencrypted)
        if (format == utils::KeyFormat::PKCS8 && current_algorithm_ == Algorithm::Ed25519 &&
            key_type == KeyType::PRIVATE) {
            // Convert libsodium 64-byte secret (seed||pub) into PKCS#8 PrivateKeyInfo wrapping Ed25519 OCTET STRING
            // (32-byte seed)
            if (key.size() != crypto_sign_ed25519_SECRETKEYBYTES) {
                return false;
            }
            // Extract 32-byte seed from libsodium secret
            std::vector<uint8_t> seed(32);
            std::copy(key.begin(), key.begin() + 32, seed.begin());

            // Build PrivateKeyInfo = SEQUENCE { version INTEGER 0, algorithm SEQ { OID Ed25519 }, privateKey OCTET
            // STRING }
            using namespace ::keylock::cert;
            using namespace ::keylock::cert::der;
            std::vector<std::vector<uint8_t>> pki_fields;
            pki_fields.push_back(encode_integer(0));
            // AlgorithmIdentifier
            std::vector<std::vector<uint8_t>> alg_fields;
            alg_fields.push_back(encode_oid(Oid{{1, 3, 101, 112}})); // id-Ed25519
            pki_fields.push_back(encode_sequence(concat(alg_fields)));
            pki_fields.push_back(encode_octet_string(ByteSpan(seed.data(), seed.size())));
            auto pki_der = encode_sequence(concat(pki_fields));

            // PEM wrap
            auto pem = cert::pem_encode(ByteSpan(pki_der.data(), pki_der.size()), "PRIVATE KEY");
            std::vector<uint8_t> pem_bytes(pem.begin(), pem.end());
            return io::write_binary(pem_bytes, filename);
        }

        return io::write_binary(key, filename);
    }

    inline Context::CryptoResult Context::load_key_from_file(const std::string &filename, KeyType key_type) {
        auto load = io::read_binary(filename);
        if (!load.success) {
            return {false, {}, load.error_message};
        }

        // Detect PEM and parse PKCS#8 for Ed25519 private keys
        const std::string_view contents(reinterpret_cast<const char *>(load.data.data()), load.data.size());
        if (contents.find("-----BEGIN") != std::string_view::npos && current_algorithm_ == Algorithm::Ed25519 &&
            key_type == KeyType::PRIVATE) {
            auto pem = ::keylock::cert::pem_decode(contents, "PRIVATE KEY");
            if (!pem.success) {
                return {false, {}, pem.error};
            }
            // Parse PrivateKeyInfo
            auto seq = ::keylock::cert::parse_sequence(
                ::keylock::cert::ByteSpan(pem.block.data.data(), pem.block.data.size()));
            if (!seq.success) {
                return {false, {}, seq.error};
            }
            size_t offset = 0;
            // version
            auto ver = ::keylock::cert::parse_integer(seq.value.subspan(offset));
            if (!ver.success) {
                return {false, {}, "Invalid PKCS#8 version"};
            }
            offset += ver.bytes_consumed;
            // algorithm identifier
            auto alg_seq = ::keylock::cert::parse_sequence(seq.value.subspan(offset));
            if (!alg_seq.success) {
                return {false, {}, "Invalid AlgorithmIdentifier"};
            }
            // Expect OID id-Ed25519
            auto oid = ::keylock::cert::parse_oid(alg_seq.value);
            if (!oid.success || oid.value.nodes != std::vector<uint32_t>({1, 3, 101, 112})) {
                return {false, {}, "Unsupported key algorithm in PKCS#8"};
            }
            offset += alg_seq.bytes_consumed;
            // privateKey OCTET STRING (may contain raw 32-byte seed or DER-encoded inner OCTET STRING)
            auto pkey_oct = ::keylock::cert::parse_octet_string(seq.value.subspan(offset));
            if (!pkey_oct.success) {
                return {false, {}, "Missing privateKey in PKCS#8"};
            }
            std::vector<uint8_t> seed;
            if (pkey_oct.value.size() == 32) {
                seed.assign(pkey_oct.value.begin(), pkey_oct.value.end());
            } else {
                // Try to parse inner OCTET STRING
                auto inner = ::keylock::cert::parse_octet_string(pkey_oct.value);
                if (!inner.success || inner.value.size() != 32) {
                    return {false, {}, "Unsupported Ed25519 PKCS#8 privateKey format"};
                }
                seed.assign(inner.value.begin(), inner.value.end());
            }
            // Reconstruct secret/public using seed
            std::vector<uint8_t> pub(crypto_sign_ed25519_PUBLICKEYBYTES);
            std::vector<uint8_t> sec(crypto_sign_ed25519_SECRETKEYBYTES);
            if (crypto_sign_ed25519_seed_keypair(pub.data(), sec.data(), seed.data()) != 0) {
                return {false, {}, "Failed to derive keypair from seed"};
            }
            return {true, sec, ""};
        }

        if (auto expected = expected_key_size(key_type)) {
            if (load.data.size() != *expected) {
                return {false, {}, "Unexpected key size"};
            }
        }
        return {true, load.data, ""};
    }

} // namespace keylock::crypto
