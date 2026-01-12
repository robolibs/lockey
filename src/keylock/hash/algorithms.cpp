#include "keylock/hash/algorithms.hpp"

#include <sodium.h>

#include "keylock/utils/sodium_utils.hpp"

namespace keylock::hash {

    Result digest(Algorithm algo, const std::vector<uint8_t> &data) {
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

    Result hmac(Algorithm algo, const std::vector<uint8_t> &data, const std::vector<uint8_t> &key) {
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

} // namespace keylock::hash
