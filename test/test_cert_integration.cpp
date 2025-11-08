#include <doctest/doctest.h>

#include "cert_test_helpers.hpp"

#include <filesystem>
#include <fstream>

#include <lockey/cert/crl_builder.hpp>
#include <lockey/cert/csr_builder.hpp>
#include <lockey/cert/pem.hpp>
#include <lockey/cert/trust_store.hpp>

using namespace lockey::cert;

namespace {

void write_file(const std::filesystem::path &path, const std::string &content) {
    std::ofstream os(path, std::ios::binary);
    REQUIRE(os.good());
    os << content;
}

bool has_openssl() {
    return std::system("openssl version > /dev/null 2>&1") == 0;
}

} // namespace

TEST_SUITE("cert/integration") {
    TEST_CASE("parse real-world certificate") {
        static const char *kIsrgRoot =
            "-----BEGIN CERTIFICATE-----\n"
            "MIIFazCCA1OgAwIBAgIRAIIQz7DSQONZRGPgu2OCiwAwDQYJKoZIhvcNAQELBQAw\n"
            "TzELMAkGA1UEBhMCVVMxKTAnBgNVBAoTIEludGVybmV0IFNlY3VyaXR5IFJlc2Vh\n"
            "cmNoIEdyb3VwMRUwEwYDVQQDEwxJU1JHIFJvb3QgWDEwHhcNMTUwNjA0MTEwNDM4\n"
            "WhcNMzUwNjA0MTEwNDM4WjBPMQswCQYDVQQGEwJVUzEpMCcGA1UEChMgSW50ZXJu\n"
            "ZXQgU2VjdXJpdHkgUmVzZWFyY2ggR3JvdXAxFTATBgNVBAMTDElTUkcgUm9vdCBY\n"
            "MTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAK3oJHP0FDfzm54rVygc\n"
            "h77ct984kIxuPOZXoHj3dcKi/vVqbvYATyjb3miGbESTtrFj/RQSa78f0uoxmyF+\n"
            "0TM8ukj13Xnfs7j/EvEhmkvBioZxaUpmZmyPfjxwv60pIeVEPnHt0hZRaEarthsL\n"
            "TnCt/gg5DiPZ9mUaELMOarZJw7d3t8QQfZBAeFSN5M9wRPQ+smfGsMSdW6r1blfY\n"
            "rsjB+f4vpp4mGZq1xN39uYwl/0d0mH5W+gT1kCbFvQTkw3+rNwWh05rq6Arzk40F\n"
            "Fk6U9wYQDLEDuPi7t/vyTH7Vc2wtFhF99w73aZkL6J9ovXQO4JUK6n6Ec/0wcgaF\n"
            "O8ogm6IQ5Xn8AnT/GcetHF0/aDtcZr1Ef5Dzf8mKVD4Q0Z2xV7d0D7YhZ7Yc8RZT\n"
            "ntgAXPoJ2OtNy0R19BjqlUE1Lc6wT2PFs+Rg2k2qLSnDAJW3JMhjIWj+4vNw8AbN\n"
            "8r3C/TWgCdW5y3Vq8/hf4Ad8wHl0AjF1aMQWr7s2Oo8SPdDTo8lFEfLE7BVcHTid\n"
            "8SruQskF3enGl4Xn4JQ4hf/ISZQz7Y1uHaOzduzxJcS64p0s7AVMtN0qf5AQCEM/\n"
            "4N9cYxBfLaDX6fHShL8XlK6PwQVR+AF8EUqZ4kpsF4B0dwooBoK5e8wGZj4U4une\n"
            "FkVIuvcvz21cTa1T6FBLKz0YNwkhAgMBAAGjQjBAMA4GA1UdDwEB/wQEAwIBBjAP\n"
            "BgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBR5tFnme7HVcgE/c/0hO4u0kb1gVDAN\n"
            "BgkqhkiG9w0BAQsFAAOCAgEAQkeyPQCprym143VW4Zzt3yieQp7CAbx9SEt4SyLg\n"
            "wrQSjb1kot8Y9MLS9XfFU6KOzDdn33ueZ+I4WE7/qabQa6RKh9vPf4bF2tQEltHb\n"
            "Dx1BEMgUQ49/pPacAFNdQen1uFbAU7qUCd5Fd2foca9+T+8VNawmeAsii+GhxiJg\n"
            "A5hhoN1p9nL/SOtixc7yumxy3Kkk1Q4KlwAgp2TqZk9LAbXOhC0I9maT3GO2Ne7t\n"
            "S9WYQeAmmCZwWZJL2FkC0OEMAWXLBkuSKvaDxx8btiXnuZbGT/lcrUzSWh4c8X9Q\n"
            "e8Z0iJQNB0RUIJTAql8ZGZXt7Zx5dpm7cZqt/m72OGsyh9TTuqvfLrPZ19u9MTm+/n\n"
            "-----END CERTIFICATE-----\n";

        auto decoded = pem_decode(kIsrgRoot, "CERTIFICATE");
        REQUIRE(decoded.success);
        auto parsed = parse_x509_cert(ByteSpan(decoded.block.data.data(), decoded.block.data.size()));
        REQUIRE(parsed.success);
        CHECK(parsed.value.subject.to_string().find("ISRG Root X1") != std::string::npos);
    }

    TEST_CASE("OpenSSL interoperability") {
        if (!has_openssl()) {
            WARN("openssl not available; skipping");
            return;
        }
        namespace fs = std::filesystem;
        auto temp_dir = fs::temp_directory_path() / "lockey_openssl";
        fs::create_directories(temp_dir);
        auto key_path = temp_dir / "key.pem";
        auto csr_path = temp_dir / "cert.pem";
        std::string cmd = "openssl req -x509 -newkey ed25519 -keyout " + key_path.string() +
                          " -out " + csr_path.string() + " -days 1 -nodes -subj /CN=InteropTest >/dev/null 2>&1";
        REQUIRE(std::system(cmd.c_str()) == 0);
        auto csr = load_csr(csr_path.string());
        REQUIRE(csr.success);
        CHECK(csr.value.info.subject.to_string().find("InteropTest") != std::string::npos);
    }

    TEST_CASE("Certificate chain from PEM files") {
        lockey::crypto::Lockey::KeyPair root_key, intermediate_key, leaf_key;
        auto [root_cert, intermediate_cert, leaf_cert] = cert_test::make_chain(root_key, intermediate_key, leaf_key);

        namespace fs = std::filesystem;
        auto dir = fs::temp_directory_path() / "lockey_chain";
        fs::create_directories(dir);
        auto root_pem = dir / "root.pem";
        auto intermediate_pem = dir / "intermediate.pem";
        write_file(root_pem, root_cert.to_pem());
        write_file(intermediate_pem, intermediate_cert.to_pem());

        TrustStore store;
        auto root_store = TrustStore::load_from_file(root_pem.string());
        REQUIRE(root_store.success);
        store = root_store.value;

        auto parsed_intermediate = Certificate::load(intermediate_pem.string());
        REQUIRE(parsed_intermediate.success);

        auto result = leaf_cert.validate_chain(parsed_intermediate.value, store);
        CHECK(result.success);
        CHECK(result.value);
    }

    TEST_CASE("Expired and revoked certificates") {
        lockey::crypto::Lockey::KeyPair key;
        auto now = std::chrono::system_clock::now();
        CertificateBuilder builder;
        auto dn = cert_test::dn_from_string("CN=Expired");
        builder.set_serial(999)
            .set_subject(dn)
            .set_issuer(dn)
            .set_validity(now - std::chrono::hours(48), now - std::chrono::hours(24))
            .set_subject_public_key_ed25519(lockey::cert::generate_ed25519_keypair().public_key)
            .set_basic_constraints(false, std::nullopt, false);
        auto csr = builder.build_ed25519(key, true);
        REQUIRE(csr.success);
        CHECK_FALSE(csr.value.check_validity());

        CrlBuilder crl_builder;
        crl_builder.set_issuer(dn)
            .set_this_update(now)
            .add_revoked(csr.value.tbs().serial_number, now, CrlReason::Superseded);
        auto crl = crl_builder.build_ed25519(key);
        REQUIRE(crl.success);
        CHECK(csr.value.is_revoked(crl.value));
    }
}
