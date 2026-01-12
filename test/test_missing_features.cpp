#include "keylock/keylock.hpp"
#include <doctest/doctest.h>

#include <filesystem>

TEST_SUITE("Missing Functionality Detection") {
    const std::vector<uint8_t> test_data = {'d', 'a', 't', 'a'};

    TEST_CASE("HMAC implementation available") {
        keylock::keylock crypto(keylock::keylock::Algorithm::XChaCha20_Poly1305,
                              keylock::keylock::HashAlgorithm::SHA256);
        std::vector<uint8_t> data = {0x74, 0x65, 0x73, 0x74};
        std::vector<uint8_t> key = {0x6b, 0x65, 0x79};

        auto result = crypto.hmac(data, key);
        CHECK(result.success);
        CHECK(result.data.size() == 32);
    }

    TEST_CASE("BLAKE2b hashing works") {
        keylock::keylock crypto(keylock::keylock::Algorithm::XChaCha20_Poly1305,
                              keylock::keylock::HashAlgorithm::BLAKE2b);
        auto result = crypto.hash({0x01, 0x02});
        CHECK(result.success);
        CHECK_FALSE(result.data.empty());
    }

    TEST_CASE("Ed25519 signatures available") {
        keylock::keylock crypto(keylock::keylock::Algorithm::Ed25519);
        auto keypair = crypto.generate_keypair();

        std::vector<uint8_t> message = {0x74, 0x65, 0x73, 0x74};
        auto signature = crypto.sign(message, keypair.private_key);
        REQUIRE(signature.success);

        auto verify = crypto.verify(message, signature.data, keypair.public_key);
        CHECK(verify.success);
    }

    TEST_CASE("X25519 asymmetric encryption available") {
        keylock::keylock crypto(keylock::keylock::Algorithm::X25519_Box);
        auto keypair = crypto.generate_keypair();

        auto encrypt_result = crypto.encrypt_asymmetric(test_data, keypair.public_key);
        REQUIRE(encrypt_result.success);

        auto decrypt_result = crypto.decrypt_asymmetric(encrypt_result.data, keypair.private_key);
        CHECK(decrypt_result.success);
        CHECK(decrypt_result.data == test_data);
    }

    TEST_CASE("Key I/O round trip") {
        keylock::keylock crypto(keylock::keylock::Algorithm::X25519_Box);
        auto keypair = crypto.generate_keypair();

        auto pub = std::filesystem::temp_directory_path() / "keylock_pub.bin";
        auto priv = std::filesystem::temp_directory_path() / "keylock_priv.bin";
        auto ok = crypto.save_keypair_to_files(keypair, pub, priv);
        CHECK(ok);

        auto load = crypto.load_keypair_from_files(pub, priv);
        CHECK(load.success);
        CHECK(load.data == keypair.private_key);

        std::filesystem::remove(pub);
        std::filesystem::remove(priv);
    }

    TEST_CASE("Implementation completeness summary") {
        std::vector<std::string> missing;

        {
            keylock::keylock crypto(keylock::keylock::Algorithm::XChaCha20_Poly1305);
            auto res = crypto.encrypt(test_data, {0x01, 0x02, 0x03});
            if (!res.success)
                missing.push_back("XChaCha20 encryption");
        }

        {
            keylock::keylock crypto(keylock::keylock::Algorithm::SecretBox_XSalsa20);
            auto res = crypto.encrypt(test_data, {0x01, 0x02, 0x03});
            if (!res.success)
                missing.push_back("SecretBox encryption");
        }

        {
            keylock::keylock crypto(keylock::keylock::Algorithm::X25519_Box);
            auto keypair = crypto.generate_keypair();
            auto enc = crypto.encrypt_asymmetric(test_data, keypair.public_key);
            if (!enc.success)
                missing.push_back("X25519 encryption");
        }

        {
            keylock::keylock crypto(keylock::keylock::Algorithm::Ed25519);
            auto keypair = crypto.generate_keypair();
            auto sig = crypto.sign(test_data, keypair.private_key);
            if (!sig.success)
                missing.push_back("Ed25519 signing");
        }

        CHECK(missing.empty());
    }
}
