#include "keylock/io/key_exchange.hpp"
#include "keylock/keylock.hpp"
#include <doctest/doctest.h>
#include <filesystem>
#include <fstream>

namespace {
const std::string test_dir = "/tmp/keylock_test_keys/";

void cleanup_test_dir() {
    if (std::filesystem::exists(test_dir)) {
        std::filesystem::remove_all(test_dir);
    }
}

void setup_test_dir() {
    cleanup_test_dir();
    std::filesystem::create_directories(test_dir);
}
} // namespace

TEST_SUITE("Key I/O Operations") {
    TEST_CASE("Save and load X25519 keypair") {
        setup_test_dir();

        keylock::keylock crypto(keylock::keylock::Algorithm::X25519_Box);
        auto keypair = crypto.generate_keypair();

        const std::string pub_file = test_dir + "x25519_public.bin";
        const std::string priv_file = test_dir + "x25519_private.bin";

        bool saved = crypto.save_keypair_to_files(keypair, pub_file, priv_file);
        REQUIRE(saved);
        REQUIRE(std::filesystem::exists(pub_file));
        REQUIRE(std::filesystem::exists(priv_file));

        auto loaded_priv = crypto.load_keypair_from_files(pub_file, priv_file);
        CHECK(loaded_priv.success);
        CHECK(loaded_priv.data == keypair.private_key);

        auto loaded_pub = crypto.load_key_from_file(pub_file, keylock::keylock::KeyType::PUBLIC);
        REQUIRE(loaded_pub.success);

        std::vector<uint8_t> roundtrip_msg = {'f', 'i', 'l', 'e'};
        auto ciphertext = crypto.encrypt_asymmetric(roundtrip_msg, loaded_pub.data);
        REQUIRE(ciphertext.success);
        auto plaintext = crypto.decrypt_asymmetric(ciphertext.data, loaded_priv.data);
        CHECK(plaintext.success);
        CHECK(plaintext.data == roundtrip_msg);

        cleanup_test_dir();
    }

    TEST_CASE("Save and reuse Ed25519 signing keys") {
        setup_test_dir();

        keylock::keylock crypto(keylock::keylock::Algorithm::Ed25519);
        auto keypair = crypto.generate_keypair();

        const std::string pub_file = test_dir + "ed25519_public.bin";
        const std::string priv_file = test_dir + "ed25519_private.bin";
        REQUIRE(crypto.save_keypair_to_files(keypair, pub_file, priv_file));

        auto loaded_priv = crypto.load_key_from_file(priv_file, keylock::keylock::KeyType::PRIVATE);
        REQUIRE(loaded_priv.success);
        CHECK(loaded_priv.data == keypair.private_key);

        auto loaded_pub = crypto.load_key_from_file(pub_file, keylock::keylock::KeyType::PUBLIC);
        REQUIRE(loaded_pub.success);
        CHECK(loaded_pub.data == keypair.public_key);

        std::vector<uint8_t> message = {'l', 'i', 'b', 's', 'o', 'd', 'i', 'u', 'm'};
        auto signature = crypto.sign(message, loaded_priv.data);
        REQUIRE(signature.success);
        auto verify = crypto.verify(message, signature.data, loaded_pub.data);
        CHECK(verify.success);

        cleanup_test_dir();
    }

    TEST_CASE("Save individual key") {
        setup_test_dir();

        keylock::keylock crypto(keylock::keylock::Algorithm::X25519_Box);
        auto keypair = crypto.generate_keypair();

        const std::string key_file = test_dir + "public.bin";
        bool save_success = crypto.save_key_to_file(keypair.public_key, key_file, keylock::keylock::KeyType::PUBLIC);
        CHECK(save_success);

        auto load_result = crypto.load_key_from_file(key_file, keylock::keylock::KeyType::PUBLIC);
        CHECK(load_result.success);
        CHECK(load_result.data == keypair.public_key);

        cleanup_test_dir();
    }

    TEST_CASE("Load non-existent file should fail") {
        keylock::keylock crypto(keylock::keylock::Algorithm::X25519_Box);
        auto result = crypto.load_key_from_file("/non/existent/file.bin", keylock::keylock::KeyType::PUBLIC);
        CHECK_FALSE(result.success);
        CHECK_FALSE(result.error_message.empty());
    }

    TEST_CASE("Save to invalid path should fail") {
        keylock::keylock crypto(keylock::keylock::Algorithm::X25519_Box);
        auto keypair = crypto.generate_keypair();

        bool save_success =
            crypto.save_key_to_file(keypair.public_key, "/invalid/path/key.bin", keylock::keylock::KeyType::PUBLIC);
        CHECK_FALSE(save_success);
    }

    TEST_CASE("Round-trip Ed25519 signature using saved keys") {
        setup_test_dir();

        keylock::keylock crypto(keylock::keylock::Algorithm::Ed25519);
        auto original = crypto.generate_keypair();

        const std::string pub_file = test_dir + "round_public.bin";
        const std::string priv_file = test_dir + "round_private.bin";
        REQUIRE(crypto.save_keypair_to_files(original, pub_file, priv_file));

        auto loaded_priv = crypto.load_keypair_from_files(pub_file, priv_file);
        REQUIRE(loaded_priv.success);

        auto loaded_pub = crypto.load_key_from_file(pub_file, keylock::keylock::KeyType::PUBLIC);
        REQUIRE(loaded_pub.success);

        std::vector<uint8_t> payload = {'t', 'e', 's', 't'};
        auto signature = crypto.sign(payload, loaded_priv.data);
        REQUIRE(signature.success);
        auto verify = crypto.verify(payload, signature.data, loaded_pub.data);
        CHECK(verify.success);

        cleanup_test_dir();
    }

    TEST_CASE("Corrupted key files are rejected") {
        setup_test_dir();

        keylock::keylock crypto(keylock::keylock::Algorithm::X25519_Box);
        auto keypair = crypto.generate_keypair();

        const std::string pub_file = test_dir + "corrupted_public.bin";
        const std::string priv_file = test_dir + "corrupted_private.bin";
        REQUIRE(crypto.save_keypair_to_files(keypair, pub_file, priv_file));

        // Truncate private key file deliberately
        {
            std::ofstream priv(priv_file, std::ios::binary | std::ios::trunc);
            priv.write(reinterpret_cast<const char *>(keypair.private_key.data()), 8);
        }

        auto load_priv = crypto.load_key_from_file(priv_file, keylock::keylock::KeyType::PRIVATE);
        CHECK_FALSE(load_priv.success);
        CHECK(load_priv.error_message.find("Unexpected key size") != std::string::npos);

        cleanup_test_dir();
    }

    TEST_CASE("Key exchange file envelope round trip") {
        setup_test_dir();

        keylock::keylock crypto(keylock::keylock::Algorithm::X25519_Box);
        auto recipient = crypto.generate_keypair();

        std::vector<uint8_t> payload = {'s', 'e', 'c', 'r', 'e', 't'};
        std::vector<uint8_t> aad = {'f', 'i', 'l', 'e'};
        auto path = test_dir + "envelope.bin";

        auto write =
            keylock::io::key_exchange::write_envelope_to_file(payload, recipient.public_key, path, aad);
        REQUIRE(write.success);

        std::vector<uint8_t> recovered_aad;
        auto read =
            keylock::io::key_exchange::read_envelope_from_file(path, recipient.private_key, &recovered_aad);
        REQUIRE(read.success);
        CHECK(read.data == payload);
        CHECK(recovered_aad == aad);

        cleanup_test_dir();
    }

    TEST_CASE("Key exchange shared memory helpers") {
        keylock::keylock crypto(keylock::keylock::Algorithm::X25519_Box);
        auto recipient = crypto.generate_keypair();
        std::vector<uint8_t> payload = {'m', 'e', 'm'};
        std::vector<uint8_t> aad = {'s', 'h', 'm'};

        auto env = keylock::io::key_exchange::create_envelope(payload, recipient.public_key, aad);
        REQUIRE(env.success);

        std::vector<uint8_t> recovered_aad;
        auto opened =
            keylock::io::key_exchange::consume_envelope(env.data, recipient.private_key, &recovered_aad);
        REQUIRE(opened.success);
        CHECK(opened.data == payload);
        CHECK(recovered_aad == aad);

        // Direct memory helpers
        std::vector<uint8_t> buffer(env.data.size());
        size_t written = 0;
        auto written_result = keylock::io::key_exchange::write_envelope_to_memory(
            buffer.data(), buffer.size(), written, payload, recipient.public_key, aad);
        REQUIRE(written_result.success);
        CHECK(written == buffer.size());

        auto mem_read = keylock::io::key_exchange::read_envelope_from_memory(
            buffer.data(), buffer.size(), recipient.private_key, &recovered_aad);
        REQUIRE(mem_read.success);
        CHECK(mem_read.data == payload);
        CHECK(recovered_aad == aad);
    }

    TEST_CASE("Key exchange invalid envelope detection") {
        keylock::keylock crypto(keylock::keylock::Algorithm::X25519_Box);
        auto recipient = crypto.generate_keypair();

        std::vector<uint8_t> bogus = {'i', 'n', 'v', 'a', 'l', 'i', 'd'};
        auto result = keylock::io::key_exchange::consume_envelope(bogus, recipient.private_key, nullptr);
        CHECK_FALSE(result.success);
    }
}
