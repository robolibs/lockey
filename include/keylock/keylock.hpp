#pragma once

#include "keylock/crypto/context.hpp"

namespace keylock {

    using keylock = crypto::Context;
    using CryptoResult = crypto::Context::CryptoResult;
    using KeyPair = crypto::Context::KeyPair;
    using Algorithm = crypto::Context::Algorithm;
    using HashAlgorithm = crypto::Context::HashAlgorithm;
    using KeyType = crypto::Context::KeyType;

} // namespace keylock
