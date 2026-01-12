#include <doctest/doctest.h>
#include <filesystem>
#include <string>

#include <keylock/crypto/context.hpp>

namespace {
    const std::string test_dir = "/tmp/keylock_test_pkcs8/";
    void setup_dir() {
        if (std::filesystem::exists(test_dir))
            std::filesystem::remove_all(test_dir);
        std::filesystem::create_directories(test_dir);
    }
} // namespace

TEST_SUITE("PKCS8 Keys") {
    TEST_CASE("Save and load Ed25519 private key as PKCS#8 PEM") {
        using keylock::crypto::Context;
        setup_dir();

        Context ctx(Context::Algorithm::Ed25519);
        auto kp = ctx.generate_keypair();
        auto path = test_dir + "ed25519_pkcs8.pem";

        CHECK(ctx.save_key_to_file(kp.private_key, path, Context::KeyType::PRIVATE, keylock::utils::KeyFormat::PKCS8));

        auto loaded = ctx.load_key_from_file(path, Context::KeyType::PRIVATE);
        REQUIRE(loaded.success);
        CHECK(loaded.data == kp.private_key);
    }
}
