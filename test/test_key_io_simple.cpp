#include "keylock/keylock.hpp"
#include <doctest/doctest.h>
#include <filesystem>
#include <fstream>

TEST_SUITE("Key I/O Operations") {
    const std::string test_dir = "/tmp/keylock_test_keys/";

    // Helper function to clean up test directory
    void cleanup_test_dir() {
        if (std::filesystem::exists(test_dir)) {
            std::filesystem::remove_all(test_dir);
        }
    }

    // Helper function to create test directory
    void setup_test_dir() {
        cleanup_test_dir();
        std::filesystem::create_directories(test_dir);
    }

    TEST_CASE("Save and load X25519 keypair") {
        setup_test_dir();

        keylock::keylock crypto(keylock::keylock::Algorithm::X25519_Box);

        auto keypair = crypto.generate_keypair();
        CHECK(keypair.algorithm == keylock::keylock::Algorithm::X25519_Box);

        std::string pub_file = test_dir + "test_public.bin";
        std::string priv_file = test_dir + "test_private.bin";

        bool save_success = crypto.save_keypair_to_files(keypair, pub_file, priv_file);
        CHECK(save_success);

        auto load_result = crypto.load_keypair_from_files(pub_file, priv_file);
        CHECK(load_result.success);
        CHECK(load_result.data == keypair.private_key);

        cleanup_test_dir();
    }

    TEST_CASE("Save individual key") {
        setup_test_dir();

        keylock::keylock crypto(keylock::keylock::Algorithm::X25519_Box);

        auto keypair = crypto.generate_keypair();
        std::string key_file = test_dir + "test_key.bin";

        bool save_success = crypto.save_key_to_file(keypair.public_key, key_file, keylock::keylock::KeyType::PUBLIC);
        CHECK(save_success);
        CHECK(std::filesystem::exists(key_file));

        auto load_result = crypto.load_key_from_file(key_file, keylock::keylock::KeyType::PUBLIC);
        CHECK(load_result.success);
        CHECK(load_result.data == keypair.public_key);

        cleanup_test_dir();
    }

    TEST_CASE("Load non-existent file should fail") {
        keylock::keylock crypto(keylock::keylock::Algorithm::X25519_Box);

        auto result = crypto.load_key_from_file("/non/existent/file.pem", keylock::keylock::KeyType::PUBLIC);
        CHECK_FALSE(result.success);
        CHECK_FALSE(result.error_message.empty());
    }
}
