#include "keylock/keylock.hpp"
#include <iostream>
#include <vector>

int main() {
    try {
        keylock::keylock crypto(keylock::keylock::Algorithm::XChaCha20_Poly1305);
        std::cout << "✓ keylock construction successful" << std::endl;

        std::vector<uint8_t> data = {'H', 'e', 'l', 'l', 'o'};
        auto key = crypto.generate_symmetric_key().data;

        auto result = crypto.encrypt(data, key);
        if (result.success) {
            std::cout << "✓ XChaCha20-Poly1305 encryption works (" << result.data.size() << " bytes)\n";
            auto roundtrip = crypto.decrypt(result.data, key);
            std::cout << (roundtrip.success && roundtrip.data == data ? "✓ Round-trip succeeded\n"
                                                                       : "✗ Round-trip failed\n");
        } else {
            std::cout << "✗ Encryption failed: " << result.error_message << std::endl;
        }

        auto hash_result = crypto.hash(data);
        if (hash_result.success) {
            std::cout << "✓ SHA-256 digest size: " << hash_result.data.size() << " bytes" << std::endl;
        } else {
            std::cout << "✗ Hash failed: " << hash_result.error_message << std::endl;
        }

        auto hex = keylock::keylock::to_hex(data);
        std::cout << "✓ Hex conversion: " << hex << std::endl;

        std::cout << "All basic tests completed!" << std::endl;

    } catch (const std::exception &e) {
        std::cout << "✗ Exception: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
