#include <chrono>
#include <fstream>
#include <iostream>
#include <string>

#include "lockey/cert/csr_builder.hpp"
#include "lockey/cert/key_utils.hpp"
#include "lockey/cert/pem.hpp"

int main() {
    using lockey::cert::CsrBuilder;

    const auto subject_key = lockey::cert::generate_ed25519_keypair();

    CsrBuilder builder;
    builder.set_subject_from_string("CN=Lockey Client,O=Lockey")
        .set_subject_public_key_ed25519(subject_key.public_key);

    auto csr = builder.build_ed25519(subject_key);
    if (!csr.success) {
        std::cerr << "Failed to build CSR: " << csr.error << "\n";
        return 1;
    }

    const std::string path = "client_request.csr.pem";
    std::ofstream out(path, std::ios::binary);
    const auto pem =
        lockey::cert::pem_encode(lockey::cert::ByteSpan(csr.value.der.data(), csr.value.der.size()),
                                 "CERTIFICATE REQUEST");
    out << pem;
    if (!out.good()) {
        std::cerr << "Unable to write CSR file\n";
        return 1;
    }

    std::cout << "CSR saved to " << path << "\n";
    return 0;
}
