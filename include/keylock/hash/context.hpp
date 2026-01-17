#pragma once

// Unified hash interface using our implementations
#include <algorithm>
#include <cstdint>
#include <string>
#include <vector>

#include "keylock/hash/blake2b/blake2b.hpp"
#include "keylock/hash/hmac/hmac_sha256.hpp"
#include "keylock/hash/hmac/hmac_sha512.hpp"
#include "keylock/hash/sha256/sha256.hpp"
#include "keylock/hash/sha512/sha512.hpp"

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
                return 32;
            case Algorithm::SHA512:
                return 64;
            case Algorithm::BLAKE2b:
                return 32;
            }
            return 0;
        }
    } // namespace detail

    inline Result digest(Algorithm algo, const std::vector<uint8_t> &data) {
        switch (algo) {
        case Algorithm::SHA256: {
            std::vector<uint8_t> out(32);
            sha256::hash(out.data(), data.data(), data.size());
            return {true, out, ""};
        }
        case Algorithm::SHA512: {
            std::vector<uint8_t> out(64);
            sha512::hash(out.data(), data.data(), data.size());
            return {true, out, ""};
        }
        case Algorithm::BLAKE2b: {
            std::vector<uint8_t> out(32);
            blake2b::hash(out.data(), 32, data.data(), data.size());
            return {true, out, ""};
        }
        }
        return {false, {}, "Unsupported hash algorithm"};
    }

    inline Result hmac(Algorithm algo, const std::vector<uint8_t> &data, const std::vector<uint8_t> &key) {
        switch (algo) {
        case Algorithm::SHA256: {
            std::vector<uint8_t> mac(32);
            hmac_sha256::Context ctx;
            hmac_sha256::init(&ctx, key.data(), key.size());
            hmac_sha256::update(&ctx, data.data(), data.size());
            hmac_sha256::final(&ctx, mac.data());
            return {true, mac, ""};
        }
        case Algorithm::SHA512: {
            std::vector<uint8_t> mac(64);
            hmac_sha512::Context ctx;
            hmac_sha512::init(&ctx, key.data(), key.size());
            hmac_sha512::update(&ctx, data.data(), data.size());
            hmac_sha512::final(&ctx, mac.data());
            return {true, mac, ""};
        }
        case Algorithm::BLAKE2b: {
            if (key.empty()) {
                return {false, {}, "BLAKE2b keyed hash requires non-empty key"};
            }
            std::vector<uint8_t> mac(32);
            blake2b::keyed(mac.data(), 32, key.data(), key.size(), data.data(), data.size());
            return {true, mac, ""};
        }
        }
        return {false, {}, "Unsupported hash algorithm"};
    }

    inline Result hkdf_extract(Algorithm algo, const std::vector<uint8_t> &ikm, const std::vector<uint8_t> &salt = {}) {
        size_t hash_len = detail::hash_output_size(algo);
        if (hash_len == 0) {
            return {false, {}, "Unsupported hash algorithm for HKDF"};
        }

        std::vector<uint8_t> effective_salt = salt;
        if (effective_salt.empty()) {
            effective_salt.resize(hash_len, 0);
        }

        return hmac(algo, ikm, effective_salt);
    }

    inline Result hkdf_expand(Algorithm algo, const std::vector<uint8_t> &prk, const std::vector<uint8_t> &info,
                              size_t length) {
        size_t hash_len = detail::hash_output_size(algo);
        if (hash_len == 0) {
            return {false, {}, "Unsupported hash algorithm for HKDF"};
        }

        if (length > 255 * hash_len) {
            return {false, {}, "HKDF output length too large"};
        }

        if (prk.size() < hash_len) {
            return {false, {}, "PRK too short for HKDF-Expand"};
        }

        std::vector<uint8_t> okm;
        okm.reserve(length);

        std::vector<uint8_t> t_prev;
        uint8_t counter = 1;

        while (okm.size() < length) {
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
