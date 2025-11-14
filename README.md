<img align="right" width="26%" src="./misc/logo.png">

# Lockey

**A lightweight C++20 libsodium wrapper with a complete Ed25519-focused X.509 toolkit**

[![Build Status](https://img.shields.io/badge/build-passing-brightgreen)](https://github.com/yourusername/lockey)
[![Language](https://img.shields.io/badge/language-C%2B%2B20-blue)](https://en.cppreference.com/w/cpp/20)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

## Overview

Lockey wraps the battle-tested **libsodium** library in a clean C++20 API. Only modern, authenticated primitives: XChaCha20-Poly1305, X25519 sealed boxes, Ed25519 signatures, and SHA-256/SHA-512/BLAKE2b. No RSA, no ECDSA, no legacy baggage.

**Key Features:**
- **Static library** - Links as `liblockey.a` with clean public API
- **Modern crypto** - XChaCha20-Poly1305 AEAD, X25519 boxes, Ed25519 signatures
- **Complete X.509 stack** - DER/PEM parsing, certificate builder, CSR/CRL support
- **Trust store** - System integration, chain validation, hostname verification
- **Verification protocol** - Optional gRPC-based OCSP alternative (requires `LOCKEY_HAS_VERIFY=ON`)
- **Type-safe** - Result types for error handling, no exceptions by default
- **Enterprise PKI** - Policy extensions, name constraints, extended key usage

## Quick Start

```cpp
#include "lockey/lockey.hpp"

int main() {
    lockey::Lockey crypto(lockey::Lockey::Algorithm::XChaCha20_Poly1305);
    
    auto key = crypto.generate_symmetric_key();
    auto ciphertext = crypto.encrypt({'H','e','l','l','o'}, key.data);
    auto plaintext = crypto.decrypt(ciphertext.data, key.data);
}
```

## Core Primitives

| Primitive | Purpose | Algorithm |
|-----------|---------|-----------|
| `XChaCha20_Poly1305` | Symmetric AEAD encryption | 256-bit key, 192-bit nonce |
| `SecretBox_XSalsa20` | Symmetric secretbox | XSalsa20-Poly1305 |
| `X25519_Box` | Public-key sealed boxes | Curve25519 |
| `Ed25519` | Digital signatures | EdDSA on Curve25519 |
| `SHA256/SHA512/BLAKE2b` | Hashing & HMAC | Multiple hash algorithms |

## Usage Examples

### Cryptography

```cpp
// Symmetric encryption
auto key = crypto.generate_symmetric_key();
auto ciphertext = crypto.encrypt(plaintext, key.data, /*aad=*/{});
auto decrypted = crypto.decrypt(ciphertext.data, key);

// X25519 sealed boxes
lockey::Lockey box(lockey::Lockey::Algorithm::X25519_Box);
auto recipient = box.generate_keypair();
auto sealed = box.encrypt_asymmetric(data, recipient.public_key);
auto plain = box.decrypt_asymmetric(sealed.data, recipient.private_key);

// Ed25519 signatures
lockey::Lockey signer(lockey::Lockey::Algorithm::Ed25519);
auto keypair = signer.generate_keypair();
auto signature = signer.sign(data, keypair.private_key);
auto verified = signer.verify(data, signature.data, keypair.public_key);

// Hashing & HMAC
auto digest = crypto.hash(data);
auto mac = crypto.hmac(data, key_material);
```

### X.509 Certificates

```cpp
#include "lockey/cert/builder.hpp"

// Generate certificate
auto keys = lockey::cert::generate_ed25519_keypair();
lockey::cert::CertificateBuilder builder;
builder.set_subject_from_string("CN=Example,O=Org")
       .set_subject_public_key_ed25519(keys.public_key)
       .set_validity(now, now + std::chrono::hours(24*365))
       .set_basic_constraints(false, std::nullopt);
auto cert = builder.build_ed25519(keys, /*self_signed=*/true);

// Validate chain
auto trust = lockey::cert::TrustStore::load_from_system();
auto valid = cert.validate_chain(intermediates, trust.value);

// Generate CSR
lockey::cert::CsrBuilder csr;
auto csr_doc = csr.set_subject_from_string("CN=Client")
                  .set_subject_public_key_ed25519(keys.public_key)
                  .build_ed25519(keys);
```

### Certificate Verification Protocol

Optional gRPC-based OCSP alternative (`LOCKEY_HAS_VERIFY=ON`):

```cpp
#include <lockey/verify/client.hpp>
#include <lockey/verify/server.hpp>

// Client
lockey::verify::Client client("localhost:50051");
auto response = client.verify_chain(certificate_chain);

// Server with custom handler
class MyHandler : public lockey::verify::VerificationHandler {
    wire::VerifyResponse verify_chain(const std::vector<cert::Certificate> &chain,
                                     std::chrono::system_clock::time_point validation_time) override {
        return response; // Custom verification logic
    }
};

lockey::verify::Server server(std::make_shared<MyHandler>(), config);
server.start();
```

See [`docs/VERIFY_PROTOCOL.md`](docs/VERIFY_PROTOCOL.md) for details.

## Building

```bash
# Makefile targets
make config   # Configure with tests/examples
make          # Build everything
make test     # Run test suite

# Or use CMake directly
cmake -S . -B build -DLOCKEY_BUILD_EXAMPLES=ON -DLOCKEY_ENABLE_TESTS=ON
cmake --build build
cd build && ctest --output-on-failure

# Enable verification protocol
cmake -S . -B build -DLOCKEY_HAS_VERIFY=ON
```

**Requirements:**
- C++20 compiler (GCC 10+, Clang 11+, MSVC 2019+)
- libsodium 1.0.18+
- CMake 3.14+
- Optional: gRPC (for verification protocol)

## Examples

See [`examples/`](examples/) for complete working examples:

**Cryptography:** `main.cpp`, `test_comprehensive.cpp`  
**Certificates:** `cert_generate_*.cpp`, `csr_generate.cpp`, `cert_verify_chain.cpp`  
**Verification:** `simple_verify_client.cpp`, `simple_verify_server.cpp`  
**Enterprise PKI:** `enterprise.cpp`, `trust_store_usage.cpp`

## Documentation

- **X.509 User Guide**: [`docs/X509_USER_GUIDE.md`](docs/X509_USER_GUIDE.md) - Complete certificate API reference
- **Verification Protocol**: [`docs/VERIFY_PROTOCOL.md`](docs/VERIFY_PROTOCOL.md) - gRPC verification protocol spec

## License

Licensed under the [MIT License](LICENSE).

---

Lockey keeps the fast libsodium internals and leaves the legacy interfaces behind. If you need modern crypto primitives without a heavyweight dependency graph, this is it.
