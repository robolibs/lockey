#include <chrono>
#include <fstream>
#include <iostream>
#include <string>

#include "keylock/cert/csr_builder.hpp"
#include "keylock/cert/key_utils.hpp"
#include "keylock/cert/pem.hpp"

int main() {
    using keylock::cert::CsrBuilder;

    const auto subject_key = keylock::cert::generate_ed25519_keypair();

    CsrBuilder builder;
    builder.set_subject_from_string("CN=keylock Client,O=keylock")
        .set_subject_public_key_ed25519(subject_key.public_key);

    auto csr = builder.build_ed25519(subject_key);
    if (!csr.success) {
        std::cerr << "Failed to build CSR: " << csr.error << "\n";
        return 1;
    }

    const std::string path = "client_request.csr.pem";
    std::ofstream out(path, std::ios::binary);
    const auto pem =
        keylock::cert::pem_encode(keylock::cert::ByteSpan(csr.value.der.data(), csr.value.der.size()),
                                 "CERTIFICATE REQUEST");
    out << pem;
    if (!out.good()) {
        std::cerr << "Unable to write CSR file\n";
        return 1;
    }

    std::cout << "CSR saved to " << path << "\n";
    return 0;
}
