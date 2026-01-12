#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "keylock/crypto/context.hpp"

namespace keylock::io::key_exchange {

    using CryptoResult = crypto::Context::CryptoResult;

    CryptoResult create_envelope(const std::vector<uint8_t> &payload, const std::vector<uint8_t> &recipient_public_key,
                                 const std::vector<uint8_t> &associated_data = {});

    CryptoResult consume_envelope(const uint8_t *buffer, size_t size, const std::vector<uint8_t> &recipient_private_key,
                                  std::vector<uint8_t> *associated_data_out = nullptr);

    CryptoResult consume_envelope(const std::vector<uint8_t> &buffer, const std::vector<uint8_t> &recipient_private_key,
                                  std::vector<uint8_t> *associated_data_out = nullptr);

    CryptoResult write_envelope_to_file(const std::vector<uint8_t> &payload,
                                        const std::vector<uint8_t> &recipient_public_key, const std::string &path,
                                        const std::vector<uint8_t> &associated_data = {});

    CryptoResult read_envelope_from_file(const std::string &path, const std::vector<uint8_t> &recipient_private_key,
                                         std::vector<uint8_t> *associated_data_out = nullptr);

    CryptoResult write_envelope_to_memory(uint8_t *dest, size_t capacity, size_t &written,
                                          const std::vector<uint8_t> &payload,
                                          const std::vector<uint8_t> &recipient_public_key,
                                          const std::vector<uint8_t> &associated_data = {});

    CryptoResult read_envelope_from_memory(const uint8_t *src, size_t size,
                                           const std::vector<uint8_t> &recipient_private_key,
                                           std::vector<uint8_t> *associated_data_out = nullptr);

} // namespace keylock::io::key_exchange
