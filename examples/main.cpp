#include <iostream>
#include <vector>
#include <string>
#include <cstdio>
#include "keylock/keylock.hpp"

void print_hex(const std::string& label, const std::vector<uint8_t>& data) {
    std::cout << label << ": ";
    for (uint8_t byte : data) {
        printf("%02x", byte);
    }
    std::cout << std::endl;
}

void test_symmetric_encryption() {
    std::cout << "\n=== Testing Symmetric Encryption (XChaCha20-Poly1305) ===" << std::endl;
    
    try {
        keylock::keylock crypto(keylock::keylock::Algorithm::XChaCha20_Poly1305, 
                             keylock::keylock::HashAlgorithm::SHA256);
        
        // Generate a symmetric key
        auto key_result = crypto.generate_symmetric_key(32);
        if (!key_result.success) {
            std::cout << "Failed to generate symmetric key: " << key_result.error_message << std::endl;
            return;
        }
        
        print_hex("Generated key", key_result.data);
        
        // Test data
        std::string plaintext_str = "Hello, keylock! This is a test message for encryption.";
        std::vector<uint8_t> plaintext(plaintext_str.begin(), plaintext_str.end());
        
        std::cout << "Original text: " << plaintext_str << std::endl;
        print_hex("Plaintext bytes", plaintext);
        
        // Encrypt the data
        auto encrypted = crypto.encrypt(plaintext, key_result.data);
        if (!encrypted.success) {
            std::cout << "Encryption failed: " << encrypted.error_message << std::endl;
            return;
        }
        
        print_hex("Encrypted data", encrypted.data);
        
        // Decrypt the data
        auto decrypted = crypto.decrypt(encrypted.data, key_result.data);
        if (!decrypted.success) {
            std::cout << "Decryption failed: " << decrypted.error_message << std::endl;
            return;
        }
        
        print_hex("Decrypted data", decrypted.data);
        
        std::string decrypted_str(decrypted.data.begin(), decrypted.data.end());
        std::cout << "Decrypted text: " << decrypted_str << std::endl;
        
        if (plaintext_str == decrypted_str) {
            std::cout << "✓ Symmetric encryption test PASSED!" << std::endl;
        } else {
            std::cout << "✗ Symmetric encryption test FAILED!" << std::endl;
        }
        
    } catch (const std::exception& e) {
        std::cout << "Exception in symmetric encryption test: " << e.what() << std::endl;
    }
}

void test_key_generation() {
    std::cout << "\n=== Testing Key Generation ===" << std::endl;
    
    try {
        keylock::keylock crypto(keylock::keylock::Algorithm::X25519_Box, 
                             keylock::keylock::HashAlgorithm::SHA256);
        
        auto keypair = crypto.generate_keypair();
        
        std::cout << "Algorithm: X25519 Box" << std::endl;
        print_hex("Public key", keypair.public_key);
        print_hex("Private key", keypair.private_key);
        
        std::cout << "✓ Key generation test PASSED!" << std::endl;
        
    } catch (const std::exception& e) {
        std::cout << "Exception in key generation test: " << e.what() << std::endl;
    }
}

void test_digital_signatures() {
    std::cout << "\n=== Testing Digital Signatures (Ed25519) ===" << std::endl;
    
    try {
        keylock::keylock crypto(keylock::keylock::Algorithm::Ed25519, 
                             keylock::keylock::HashAlgorithm::SHA256);
        
        // Generate a key pair
        auto keypair = crypto.generate_keypair();
        
        // Message to sign
        std::string message = "This is a message to be signed.";
        std::vector<uint8_t> message_bytes(message.begin(), message.end());
        
        std::cout << "Message: " << message << std::endl;
        print_hex("Message bytes", message_bytes);
        
        // Sign the message
        auto signature = crypto.sign(message_bytes, keypair.private_key);
        if (!signature.success) {
            std::cout << "Signing failed: " << signature.error_message << std::endl;
            return;
        }
        
        print_hex("Signature", signature.data);
        
        // Verify the signature
        auto verify_result = crypto.verify(message_bytes, signature.data, keypair.public_key);
        
        if (verify_result.success) {
            std::cout << "✓ Digital signature test PASSED!" << std::endl;
        } else {
            std::cout << "✗ Digital signature test FAILED: " << verify_result.error_message << std::endl;
        }
        
    } catch (const std::exception& e) {
        std::cout << "Exception in digital signature test: " << e.what() << std::endl;
    }
}

void test_hashing() {
    std::cout << "\n=== Testing Hash Functions ===" << std::endl;
    
    try {
        keylock::keylock crypto(keylock::keylock::Algorithm::XChaCha20_Poly1305, 
                             keylock::keylock::HashAlgorithm::SHA256);
        
        std::string test_data = "The quick brown fox jumps over the lazy dog";
        std::vector<uint8_t> data(test_data.begin(), test_data.end());
        
        std::cout << "Input: " << test_data << std::endl;
        
        // Test SHA-256
        auto hash_result = crypto.hash(data);
        if (!hash_result.success) {
            std::cout << "Hashing failed: " << hash_result.error_message << std::endl;
            return;
        }
        
        print_hex("SHA-256 hash", hash_result.data);
        
        std::cout << "✓ Hash function test PASSED!" << std::endl;
        
    } catch (const std::exception& e) {
        std::cout << "Exception in hash test: " << e.what() << std::endl;
    }
}

void test_utility_functions() {
    std::cout << "\n=== Testing Utility Functions ===" << std::endl;
    
    try {
        std::vector<uint8_t> test_data = {0x48, 0x65, 0x6c, 0x6c, 0x6f}; // "Hello"
        
        // Test hex conversion
        std::string hex = keylock::keylock::to_hex(test_data);
        std::cout << "Original data: ";
        for (uint8_t b : test_data) std::cout << static_cast<char>(b);
        std::cout << std::endl;
        std::cout << "Hex representation: " << hex << std::endl;
        
        auto converted_back = keylock::keylock::from_hex(hex);
        print_hex("Converted back", converted_back);
        
        if (test_data == converted_back) {
            std::cout << "✓ Utility functions test PASSED!" << std::endl;
        } else {
            std::cout << "✗ Utility functions test FAILED!" << std::endl;
        }
        
    } catch (const std::exception& e) {
        std::cout << "Exception in utility test: " << e.what() << std::endl;
    }
}

int main() {
    std::cout << "keylock Cryptographic Library - Test Suite" << std::endl;
    std::cout << "=========================================" << std::endl;
    
    test_symmetric_encryption();
    test_key_generation();
    test_digital_signatures();
    test_hashing();
    test_utility_functions();
    
    std::cout << "\n=========================================" << std::endl;
    std::cout << "Test suite completed!" << std::endl;
    
    return 0;
}
