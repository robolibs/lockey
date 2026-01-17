#pragma once

#include <mutex>
#include <stdexcept>

#include <sodium.h>

namespace keylock::utils {

    inline void ensure_sodium_init() {
        static std::once_flag sodium_flag;
        static int status = -1;
        std::call_once(sodium_flag, []() { status = sodium_init(); });

        if (status < 0) {
            throw std::runtime_error("libsodium initialization failed");
        }
    }

} // namespace keylock::utils
