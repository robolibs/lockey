#pragma once

#include <algorithm>
#include <cstdint>
#include <string>
#include <vector>

#include <sodium.h>

#include "keylock/utils/sodium_utils.hpp"

namespace keylock::hash {

    enum class Algorithm { SHA256, SHA512, BLAKE2b };

    struct Result {
        bool success;
        std::vector<uint8_t> data;
        std::string error_message;
    };

    namespace detail {
        inline size_t hash_output_size(Algorithm algo) {
            switch (algo) {
            case Algorithm::SHA256:
                return crypto_auth_hmacsha256_BYTES;
            case Algorithm::SHA512:
                return crypto_auth_hmacsha512_BYTES;
            case Algorithm::BLAKE2b:
                return crypto_generichash_BYTES;
            }
            return 0;
        }
    } // namespace detail

    inline Result digest(Algorithm algo, const std::vector<uint8_t> &data) {
        utils::ensure_sodium_init();

        switch (algo) {
        case Algorithm::SHA256: {
            std::vector<uint8_t> digest(crypto_hash_sha256_BYTES);
            crypto_hash_sha256(digest.data(), data.data(), data.size());
            return {true, digest, ""};
        }
        case Algorithm::SHA512: {
            std::vector<uint8_t> digest(crypto_hash_sha512_BYTES);
            crypto_hash_sha512(digest.data(), data.data(), data.size());
            return {true, digest, ""};
        }
        case Algorithm::BLAKE2b: {
            std::vector<uint8_t> digest(crypto_generichash_BYTES);
            crypto_generichash(digest.data(), digest.size(), data.data(), data.size(), nullptr, 0);
            return {true, digest, ""};
        }
        }

        return {false, {}, "Unsupported hash algorithm"};
    }

    inline Result hmac(Algorithm algo, const std::vector<uint8_t> &data, const std::vector<uint8_t> &key) {
        utils::ensure_sodium_init();

        switch (algo) {
        case Algorithm::SHA256: {
            std::vector<uint8_t> mac(crypto_auth_hmacsha256_BYTES);
            crypto_auth_hmacsha256_state state;
            crypto_auth_hmacsha256_init(&state, key.data(), key.size());
            crypto_auth_hmacsha256_update(&state, data.data(), data.size());
            crypto_auth_hmacsha256_final(&state, mac.data());
            return {true, mac, ""};
        }
        case Algorithm::SHA512: {
            std::vector<uint8_t> mac(crypto_auth_hmacsha512_BYTES);
            crypto_auth_hmacsha512_state state;
            crypto_auth_hmacsha512_init(&state, key.data(), key.size());
            crypto_auth_hmacsha512_update(&state, data.data(), data.size());
            crypto_auth_hmacsha512_final(&state, mac.data());
            return {true, mac, ""};
        }
        case Algorithm::BLAKE2b: {
            if (key.empty()) {
                return {false, {}, "BLAKE2b HMAC requires non-empty key"};
            }
            std::vector<uint8_t> mac(crypto_generichash_BYTES);
            crypto_generichash(mac.data(), mac.size(), data.data(), data.size(), key.data(), key.size());
            return {true, mac, ""};
        }
        }

        return {false, {}, "Unsupported hash algorithm"};
    }

    inline Result hkdf_extract(Algorithm algo, const std::vector<uint8_t> &ikm, const std::vector<uint8_t> &salt = {}) {
        utils::ensure_sodium_init();

        size_t hash_len = detail::hash_output_size(algo);
        if (hash_len == 0) {
            return {false, {}, "Unsupported hash algorithm for HKDF"};
        }

        // If salt is empty, use a zero-filled salt of hash_len bytes (RFC 5869)
        std::vector<uint8_t> effective_salt = salt;
        if (effective_salt.empty()) {
            effective_salt.resize(hash_len, 0);
        }

        // PRK = HMAC(salt, IKM)
        return hmac(algo, ikm, effective_salt);
    }

    inline Result hkdf_expand(Algorithm algo, const std::vector<uint8_t> &prk, const std::vector<uint8_t> &info,
                              size_t length) {
        utils::ensure_sodium_init();

        size_t hash_len = detail::hash_output_size(algo);
        if (hash_len == 0) {
            return {false, {}, "Unsupported hash algorithm for HKDF"};
        }

        // RFC 5869: L <= 255 * HashLen
        if (length > 255 * hash_len) {
            return {false, {}, "HKDF output length too large"};
        }

        if (prk.size() < hash_len) {
            return {false, {}, "PRK too short for HKDF-Expand"};
        }

        std::vector<uint8_t> okm;
        okm.reserve(length);

        std::vector<uint8_t> t_prev; // T(0) = empty string
        uint8_t counter = 1;

        while (okm.size() < length) {
            // T(i) = HMAC(PRK, T(i-1) || info || counter)
            std::vector<uint8_t> message;
            message.reserve(t_prev.size() + info.size() + 1);
            message.insert(message.end(), t_prev.begin(), t_prev.end());
            message.insert(message.end(), info.begin(), info.end());
            message.push_back(counter);

            auto t_result = hmac(algo, message, prk);
            if (!t_result.success) {
                return t_result;
            }

            t_prev = std::move(t_result.data);

            size_t to_copy = std::min(t_prev.size(), length - okm.size());
            okm.insert(okm.end(), t_prev.begin(), t_prev.begin() + static_cast<std::ptrdiff_t>(to_copy));

            counter++;
        }

        return {true, okm, ""};
    }

    inline Result hkdf(Algorithm algo, const std::vector<uint8_t> &ikm, const std::vector<uint8_t> &salt,
                       const std::vector<uint8_t> &info, size_t length) {
        auto prk_result = hkdf_extract(algo, ikm, salt);
        if (!prk_result.success) {
            return prk_result;
        }

        return hkdf_expand(algo, prk_result.data, info, length);
    }

} // namespace keylock::hash
