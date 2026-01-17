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

#include "keylock/cert/files.hpp"
#include "keylock/crypto/common.hpp"
#include "keylock/hash/blake2b/blake2b.hpp"
#include "keylock/hash/context.hpp"

// Our crypto implementations
#include "keylock/crypto/aead_aes256gcm/aead.hpp"
#include "keylock/crypto/aead_chacha20poly1305_ietf/aead.hpp"
#include "keylock/crypto/aead_xchacha20poly1305_ietf/aead.hpp"
#include "keylock/crypto/box_seal_x25519/seal.hpp"
#include "keylock/crypto/rng/randombytes.hpp"
#include "keylock/crypto/secretbox_xsalsa20poly1305/secretbox.hpp"
#include "keylock/crypto/sign_ed25519/ed25519.hpp"

namespace keylock::crypto {

    namespace detail {

        inline std::vector<uint8_t> normalize_key(const std::vector<uint8_t> &key, size_t required) {
            if (key.size() == required) {
                return key;
            }
            std::vector<uint8_t> normalized(required);
            hash::blake2b::hash(normalized.data(), normalized.size(), key.data(), key.size());
            return normalized;
        }

    } // namespace detail

    class Context {
      public:
        using HashAlgorithm = hash::Algorithm;

        enum class Algorithm {
            XChaCha20_Poly1305,
            ChaCha20_Poly1305,
            AES256_GCM,
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
            : current_algorithm_(algorithm), current_hash_(hash_algo) {}

        void set_algorithm(Algorithm algorithm) { current_algorithm_ = algorithm; }
        void set_hash_algorithm(HashAlgorithm hash_algo) { current_hash_ = hash_algo; }
        [[nodiscard]] Algorithm get_algorithm() const { return current_algorithm_; }
        [[nodiscard]] HashAlgorithm get_hash_algorithm() const { return current_hash_; }

        CryptoResult encrypt(const std::vector<uint8_t> &plaintext, const std::vector<uint8_t> &key,
                             const std::vector<uint8_t> &associated_data = {}) {
            if (!is_symmetric_algorithm(current_algorithm_)) {
                return {false, {}, "Current algorithm is not suitable for symmetric encryption"};
            }

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

            if (public_key.size() != box_seal::PUBLICKEYBYTES) {
                return {false, {}, "Invalid public key size"};
            }

            std::vector<uint8_t> ciphertext(plaintext.size() + box_seal::SEALBYTES);
            if (box_seal::seal(ciphertext.data(), plaintext.data(), plaintext.size(), public_key.data()) != 0) {
                return {false, {}, "seal failed"};
            }

            return {true, ciphertext, ""};
        }

        CryptoResult decrypt_asymmetric(const std::vector<uint8_t> &ciphertext,
                                        const std::vector<uint8_t> &private_key) {
            if (!is_asymmetric_algorithm(current_algorithm_)) {
                return {false, {}, "Current algorithm does not support asymmetric decryption"};
            }

            if (private_key.size() != box_seal::PUBLICKEYBYTES + box_seal::SECRETKEYBYTES) {
                return {false, {}, "Invalid private key material"};
            }

            if (ciphertext.size() < box_seal::SEALBYTES) {
                return {false, {}, "Ciphertext too short"};
            }

            std::vector<uint8_t> plaintext(ciphertext.size() - box_seal::SEALBYTES);
            const uint8_t *pub = private_key.data();
            const uint8_t *sec = private_key.data() + box_seal::PUBLICKEYBYTES;
            if (box_seal::seal_open(plaintext.data(), ciphertext.data(), ciphertext.size(), pub, sec) != 0) {
                return {false, {}, "Decryption failed"};
            }

            return {true, plaintext, ""};
        }

        CryptoResult sign(const std::vector<uint8_t> &data, const std::vector<uint8_t> &private_key) {
            if (!is_signature_algorithm(current_algorithm_)) {
                return {false, {}, "Current algorithm does not support signing"};
            }

            if (private_key.size() != ed25519::SECRETKEYBYTES) {
                return {false, {}, "Invalid private key size"};
            }

            std::vector<uint8_t> signature(ed25519::BYTES);
            unsigned long long sig_len = 0;
            if (ed25519::sign_detached(signature.data(), &sig_len, data.data(), data.size(), private_key.data()) != 0) {
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

            if (public_key.size() != ed25519::PUBLICKEYBYTES) {
                return {false, {}, "Invalid public key size"};
            }

            int rc = ed25519::verify_detached(signature.data(), data.data(), data.size(), public_key.data());
            return {rc == 0, {}, rc == 0 ? "" : "Ed25519 signature verification failed"};
        }

        KeyPair generate_keypair() {
            switch (current_algorithm_) {
            case Algorithm::X25519_Box: {
                std::vector<uint8_t> pub(box_seal::PUBLICKEYBYTES);
                std::vector<uint8_t> sec(box_seal::SECRETKEYBYTES);
                box_seal::keypair(pub.data(), sec.data());
                KeyPair pair;
                pair.algorithm = current_algorithm_;
                pair.public_key = pub;
                pair.private_key = pub;
                pair.private_key.insert(pair.private_key.end(), sec.begin(), sec.end());
                return pair;
            }
            case Algorithm::Ed25519: {
                std::vector<uint8_t> pub(ed25519::PUBLICKEYBYTES);
                std::vector<uint8_t> sec(ed25519::SECRETKEYBYTES);
                ed25519::keypair(pub.data(), sec.data());
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
                std::vector<uint8_t> key(key_size);
                rng::randombytes_buf(key.data(), key.size());
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
                              KeyFormat format = KeyFormat::RAW);

        CryptoResult load_key_from_file(const std::string &filename, KeyType key_type);

        bool save_keypair_to_files(const KeyPair &keypair, const std::string &public_filename,
                                   const std::string &private_filename, KeyFormat format = KeyFormat::RAW) {
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

        static std::string to_hex(const std::vector<uint8_t> &data) { return Common::bytes_to_hex(data); }
        static std::vector<uint8_t> from_hex(const std::string &hex) { return Common::hex_to_bytes(hex); }

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

        static bool is_aes_gcm_available() { return aead_aes256gcm::is_available() != 0; }

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
                    return box_seal::PUBLICKEYBYTES;
                return box_seal::PUBLICKEYBYTES + box_seal::SECRETKEYBYTES;
            case Algorithm::Ed25519:
                if (key_type == KeyType::PUBLIC)
                    return ed25519::PUBLICKEYBYTES;
                return ed25519::SECRETKEYBYTES;
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
                auto normalized_key = detail::normalize_key(key, aead_xchacha20poly1305::KEYBYTES);
                std::vector<uint8_t> nonce(aead_xchacha20poly1305::NPUBBYTES);
                rng::randombytes_buf(nonce.data(), nonce.size());

                std::vector<uint8_t> ciphertext(plaintext.size() + aead_xchacha20poly1305::ABYTES);
                unsigned long long ciphertext_len = 0;

                if (aead_xchacha20poly1305::encrypt(ciphertext.data(), &ciphertext_len, plaintext.data(),
                                                    plaintext.size(), aad.data(), aad.size(), nullptr, nonce.data(),
                                                    normalized_key.data()) != 0) {
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
                if (ciphertext_with_nonce.size() < aead_xchacha20poly1305::NPUBBYTES + aead_xchacha20poly1305::ABYTES) {
                    return {false, {}, "Ciphertext too short"};
                }

                auto normalized_key = detail::normalize_key(key, aead_xchacha20poly1305::KEYBYTES);
                std::vector<uint8_t> nonce(ciphertext_with_nonce.begin(),
                                           ciphertext_with_nonce.begin() + aead_xchacha20poly1305::NPUBBYTES);
                std::vector<uint8_t> ciphertext(ciphertext_with_nonce.begin() + aead_xchacha20poly1305::NPUBBYTES,
                                                ciphertext_with_nonce.end());

                if (ciphertext.size() < aead_xchacha20poly1305::ABYTES) {
                    return {false, {}, "Ciphertext too short"};
                }

                std::vector<uint8_t> plaintext(ciphertext.size() - aead_xchacha20poly1305::ABYTES);
                unsigned long long plaintext_len = 0;

                if (aead_xchacha20poly1305::decrypt(plaintext.data(), &plaintext_len, nullptr, ciphertext.data(),
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

        CryptoResult aead_chacha_ietf_encrypt(const std::vector<uint8_t> &plaintext, const std::vector<uint8_t> &key,
                                              const std::vector<uint8_t> &aad) {
            try {
                auto normalized_key = detail::normalize_key(key, aead_chacha20poly1305_ietf::KEYBYTES);
                std::vector<uint8_t> nonce(aead_chacha20poly1305_ietf::NPUBBYTES);
                rng::randombytes_buf(nonce.data(), nonce.size());

                std::vector<uint8_t> ciphertext(plaintext.size() + aead_chacha20poly1305_ietf::ABYTES);
                unsigned long long ciphertext_len = 0;

                if (aead_chacha20poly1305_ietf::encrypt(ciphertext.data(), &ciphertext_len, plaintext.data(),
                                                        plaintext.size(), aad.data(), aad.size(), nullptr, nonce.data(),
                                                        normalized_key.data()) != 0) {
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
                    aead_chacha20poly1305_ietf::NPUBBYTES + aead_chacha20poly1305_ietf::ABYTES) {
                    return {false, {}, "Ciphertext too short"};
                }

                auto normalized_key = detail::normalize_key(key, aead_chacha20poly1305_ietf::KEYBYTES);
                std::vector<uint8_t> nonce(ciphertext_with_nonce.begin(),
                                           ciphertext_with_nonce.begin() + aead_chacha20poly1305_ietf::NPUBBYTES);
                std::vector<uint8_t> ciphertext(ciphertext_with_nonce.begin() + aead_chacha20poly1305_ietf::NPUBBYTES,
                                                ciphertext_with_nonce.end());

                if (ciphertext.size() < aead_chacha20poly1305_ietf::ABYTES) {
                    return {false, {}, "Ciphertext too short"};
                }

                std::vector<uint8_t> plaintext(ciphertext.size() - aead_chacha20poly1305_ietf::ABYTES);
                unsigned long long plaintext_len = 0;

                if (aead_chacha20poly1305_ietf::decrypt(plaintext.data(), &plaintext_len, nullptr, ciphertext.data(),
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

        CryptoResult aead_aes256gcm_encrypt(const std::vector<uint8_t> &plaintext, const std::vector<uint8_t> &key,
                                            const std::vector<uint8_t> &aad) {
            try {
                if (aead_aes256gcm::is_available() == 0) {
                    return {false, {}, "AES-GCM not available (requires AES-NI hardware support)"};
                }

                auto normalized_key = detail::normalize_key(key, aead_aes256gcm::KEYBYTES);
                std::vector<uint8_t> nonce(aead_aes256gcm::NPUBBYTES);
                rng::randombytes_buf(nonce.data(), nonce.size());

                std::vector<uint8_t> ciphertext(plaintext.size() + aead_aes256gcm::ABYTES);
                unsigned long long ciphertext_len = 0;

                if (aead_aes256gcm::encrypt(ciphertext.data(), &ciphertext_len, plaintext.data(), plaintext.size(),
                                            aad.data(), aad.size(), nullptr, nonce.data(),
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
                if (aead_aes256gcm::is_available() == 0) {
                    return {false, {}, "AES-GCM not available (requires AES-NI hardware support)"};
                }

                if (ciphertext_with_nonce.size() < aead_aes256gcm::NPUBBYTES + aead_aes256gcm::ABYTES) {
                    return {false, {}, "Ciphertext too short"};
                }

                auto normalized_key = detail::normalize_key(key, aead_aes256gcm::KEYBYTES);
                std::vector<uint8_t> nonce(ciphertext_with_nonce.begin(),
                                           ciphertext_with_nonce.begin() + aead_aes256gcm::NPUBBYTES);
                std::vector<uint8_t> ciphertext(ciphertext_with_nonce.begin() + aead_aes256gcm::NPUBBYTES,
                                                ciphertext_with_nonce.end());

                if (ciphertext.size() < aead_aes256gcm::ABYTES) {
                    return {false, {}, "Ciphertext too short"};
                }

                std::vector<uint8_t> plaintext(ciphertext.size() - aead_aes256gcm::ABYTES);
                unsigned long long plaintext_len = 0;

                if (aead_aes256gcm::decrypt(plaintext.data(), &plaintext_len, nullptr, ciphertext.data(),
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
                auto normalized_key = detail::normalize_key(key, secretbox::KEYBYTES);
                std::vector<uint8_t> nonce(secretbox::NONCEBYTES);
                rng::randombytes_buf(nonce.data(), nonce.size());

                std::vector<uint8_t> ciphertext(secretbox::NONCEBYTES + secretbox::MACBYTES + plaintext.size());
                std::copy(nonce.begin(), nonce.end(), ciphertext.begin());

                if (secretbox::easy(ciphertext.data() + secretbox::NONCEBYTES, plaintext.data(), plaintext.size(),
                                    nonce.data(), normalized_key.data()) != 0) {
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
                if (ciphertext_with_nonce.size() < secretbox::NONCEBYTES + secretbox::MACBYTES) {
                    return {false, {}, "Ciphertext too short"};
                }

                auto normalized_key = detail::normalize_key(key, secretbox::KEYBYTES);
                std::vector<uint8_t> nonce(ciphertext_with_nonce.begin(),
                                           ciphertext_with_nonce.begin() + secretbox::NONCEBYTES);
                std::vector<uint8_t> ciphertext(ciphertext_with_nonce.begin() + secretbox::NONCEBYTES,
                                                ciphertext_with_nonce.end());

                std::vector<uint8_t> plaintext(ciphertext.size() - secretbox::MACBYTES);
                if (secretbox::open_easy(plaintext.data(), ciphertext.data(), ciphertext.size(), nonce.data(),
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
                                          KeyType key_type, KeyFormat format) {
        if (format == KeyFormat::PKCS8 && current_algorithm_ == Algorithm::Ed25519 && key_type == KeyType::PRIVATE) {
            if (key.size() != ed25519::SECRETKEYBYTES) {
                return false;
            }
            std::vector<uint8_t> seed(32);
            std::copy(key.begin(), key.begin() + 32, seed.begin());

            using namespace ::keylock::cert;
            using namespace ::keylock::cert::der;
            std::vector<std::vector<uint8_t>> pki_fields;
            pki_fields.push_back(encode_integer(0));
            std::vector<std::vector<uint8_t>> alg_fields;
            alg_fields.push_back(encode_oid(Oid{{1, 3, 101, 112}}));
            pki_fields.push_back(encode_sequence(concat(alg_fields)));
            pki_fields.push_back(encode_octet_string(ByteSpan(seed.data(), seed.size())));
            auto pki_der = encode_sequence(concat(pki_fields));

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

        const std::string_view contents(reinterpret_cast<const char *>(load.data.data()), load.data.size());
        if (contents.find("-----BEGIN") != std::string_view::npos && current_algorithm_ == Algorithm::Ed25519 &&
            key_type == KeyType::PRIVATE) {
            auto pem = ::keylock::cert::pem_decode(contents, "PRIVATE KEY");
            if (!pem.success) {
                return {false, {}, pem.error};
            }
            auto seq = ::keylock::cert::parse_sequence(
                ::keylock::cert::ByteSpan(pem.block.data.data(), pem.block.data.size()));
            if (!seq.success) {
                return {false, {}, seq.error};
            }
            size_t offset = 0;
            auto ver = ::keylock::cert::parse_integer(seq.value.subspan(offset));
            if (!ver.success) {
                return {false, {}, "Invalid PKCS#8 version"};
            }
            offset += ver.bytes_consumed;
            auto alg_seq = ::keylock::cert::parse_sequence(seq.value.subspan(offset));
            if (!alg_seq.success) {
                return {false, {}, "Invalid AlgorithmIdentifier"};
            }
            auto oid = ::keylock::cert::parse_oid(alg_seq.value);
            if (!oid.success || oid.value.nodes != std::vector<uint32_t>({1, 3, 101, 112})) {
                return {false, {}, "Unsupported key algorithm in PKCS#8"};
            }
            offset += alg_seq.bytes_consumed;
            auto pkey_oct = ::keylock::cert::parse_octet_string(seq.value.subspan(offset));
            if (!pkey_oct.success) {
                return {false, {}, "Missing privateKey in PKCS#8"};
            }
            std::vector<uint8_t> seed;
            if (pkey_oct.value.size() == 32) {
                seed.assign(pkey_oct.value.begin(), pkey_oct.value.end());
            } else {
                auto inner = ::keylock::cert::parse_octet_string(pkey_oct.value);
                if (!inner.success || inner.value.size() != 32) {
                    return {false, {}, "Unsupported Ed25519 PKCS#8 privateKey format"};
                }
                seed.assign(inner.value.begin(), inner.value.end());
            }
            std::vector<uint8_t> pub(ed25519::PUBLICKEYBYTES);
            std::vector<uint8_t> sec(ed25519::SECRETKEYBYTES);
            ed25519::seed_keypair(pub.data(), sec.data(), seed.data());
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
