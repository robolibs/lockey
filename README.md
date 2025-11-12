<img align="right" width="26%" src="./misc/logo.png">

# Lockey

**A tiny, header-only C++20 libsodium facade with an Ed25519-focused X.509 toolkit**

[![Build Status](https://img.shields.io/badge/build-passing-brightgreen)](https://github.com/yourusername/lockey)
[![Language](https://img.shields.io/badge/language-C%2B%2B20-blue)](https://en.cppreference.com/w/cpp/20)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Header Only](https://img.shields.io/badge/header--only-yes-orange)](https://github.com/yourusername/lockey)

## Overview

Lockey wraps the battle-tested **libsodium** toolbox in a clean, zero-dependency C++20 API. Only modern, authenticated primitives make the cut: XChaCha20-Poly1305, SecretBox (XSalsa20-Poly1305), X25519 sealed boxes, Ed25519 signatures, and SHA-256/SHA-512/BLAKE2b (plus HMAC). No RSA, no ECDSA, no legacy baggage - just high-level helpers around the safe defaults you actually want.

### Design Philosophy

- **Security First**: Uses only modern, authenticated encryption modes and safe elliptic curves
- **Zero Dependencies**: Header-only library with only libsodium as runtime dependency
- **Type Safety**: Strong typing with result types for error handling instead of exceptions
- **Performance**: Leverages libsodium's optimized implementations with constant-time operations
- **Simplicity**: Fluent APIs that make the right thing easy and the wrong thing hard

### Key Features

#### Core Cryptography
- **libsodium-only backend** - every operation delegates to libsodium and calls `sodium_init()` exactly once
- **Header-only** - include `lockey/lockey.hpp` and go, no compilation required
- **Modern AEAD encryption** - XChaCha20-Poly1305 and SecretBox XSalsa20-Poly1305 for symmetric encryption with authenticated additional data (AAD)
- **Curve25519 cryptography** - X25519 sealed boxes for public-key encryption and Ed25519 for deterministic signatures
- **Multiple hash algorithms** - SHA-256, SHA-512, and BLAKE2b with HMAC support via libsodium
- **Secure key generation** - Ed25519/X25519 keypair generation with cryptographically secure randomness
- **Key file management** - Save/load keys in RAW format with format extensibility
- **Constant-time operations** - Secure comparison and memory clearing to prevent timing attacks

#### X.509 Certificate Management
- **Full DER/PEM X.509 stack** - Complete ASN.1 parser and writer for certificates without external dependencies
- **Certificate builder** - Fluent API for creating self-signed, CA, and leaf certificates
- **CSR support** - Generate and parse Certificate Signing Requests (PKCS#10)
- **CRL management** - Build and parse Certificate Revocation Lists with multiple revocation reasons
- **Trust store** - Load from system, PEM, DER files with issuer discovery and chain validation
- **Certificate validation** - Full chain verification with path length constraints and validity checks
- **Extension support** - Parse and create Basic Constraints, Key Usage, Extended Key Usage, Subject/Issuer Alternative Names
- **Enterprise extensions** - Policy Mappings, Policy Constraints, Inhibit Any-Policy for complex PKI hierarchies
- **Ed25519 focused** - Native Ed25519 certificate support with SPKI encoding/decoding
- **Hostname verification** - Match certificates against hostnames with wildcard support
- **Fingerprinting** - Generate certificate fingerprints using any supported hash algorithm

#### Advanced Features
- **Key exchange envelopes** - Secure payload wrapping for files or shared memory with integrity checks and AAD
- **Wire format serialization** - Binary envelope format with magic bytes, version headers, and checksums
- **Memory-safe operations** - Shared memory key exchange with capacity checking
- **XOR operations** - Byte-level XOR for custom protocol implementations
- **PKCS#7 padding** - Block cipher padding/unpadding utilities
- **Hex encoding** - Fast bidirectional hex conversion for debugging and display
- **Random byte generation** - Cryptographically secure random data via libsodium

#### Certificate Verification Protocol (Optional)
- **gRPC-based verification** - Modern OCSP alternative built on gRPC/HTTP2 (requires `LOCKEY_HAS_VERIFY=ON`)
- **Custom wire protocol** - Efficient binary format optimized for Ed25519 certificates
- **Batch verification** - Verify multiple certificate chains in a single request
- **Replay protection** - Nonce-based protection against replay attacks
- **Health checks** - Built-in server health monitoring
- **TLS support** - Optional mutual TLS authentication for client/server communication
- **Revocation handler** - In-memory revocation list management with reason tracking
- **Response signatures** - Ed25519 signed responses with responder certificate validation

#### Utilities
- **Modular namespaces** - Clean separation: `lockey::crypto`, `lockey::hash`, `lockey::io`, `lockey::utils`, `lockey::cert`, `lockey::verify`
- **OID registry** - Comprehensive Object Identifier support for X.509 extensions and algorithms
- **Time formatting** - UTC and GeneralizedTime formatting for certificates
- **ASN.1 primitives** - Complete set of DER encoding/decoding functions
- **Result types** - Consistent error handling with success/failure results throughout the API

## Module Architecture

### `lockey::crypto` - Cryptographic Operations
- Unified context for all libsodium operations
- Symmetric encryption (XChaCha20-Poly1305, SecretBox XSalsa20-Poly1305)
- Asymmetric encryption (X25519 sealed boxes)
- Digital signatures (Ed25519 deterministic signing)
- Key generation and management
- Algorithm selection and configuration

### `lockey::hash` - Hashing and MAC
- SHA-256, SHA-512, BLAKE2b implementations
- HMAC support for all hash algorithms
- Consistent API across different algorithms
- Direct libsodium integration for performance

### `lockey::cert` - X.509 Certificate Stack
- Complete ASN.1 DER parser and encoder
- Certificate, CSR, and CRL builders with fluent APIs
- Trust store management with system integration
- Extension handling (standard and enterprise)
- Ed25519 SPKI encoding/decoding
- OID registry for all standard identifiers
- Chain validation with path constraints

### `lockey::io` - Input/Output Operations
- Secure key exchange envelopes
- File-based envelope persistence
- Shared memory envelope operations
- Binary I/O with error handling
- Wire format serialization

### `lockey::utils` - Common Utilities
- Cryptographically secure random generation
- Hex encoding/decoding
- PKCS#7 padding operations
- Constant-time comparison
- Secure memory clearing
- XOR operations
- Algorithm constants and sizes

### `lockey::verify` - Certificate Verification Protocol (Optional)
- gRPC-based client/server implementation
- Custom binary wire format
- Batch verification support
- Revocation list management
- Response signature validation

## Feature Details

### X.509 Certificate Toolkit

```cpp
#include "lockey/cert/certificate.hpp"
#include "lockey/cert/trust_store.hpp"

using lockey::cert::Certificate;
using lockey::cert::TrustStore;

auto chain = Certificate::load("certs/leaf_and_issuer.pem");
auto trust = TrustStore::load_from_system();
if (chain.success && trust.success) {
    const auto &leaf = chain.value.front();
    std::vector<Certificate> intermediates(chain.value.begin() + 1, chain.value.end());
    auto verdict = leaf.validate_chain(intermediates, trust.value);
    if (verdict.success && verdict.value) {
        std::cout << "Chain ok, fingerprint: "
                  << lockey::utils::to_hex(leaf.fingerprint(lockey::hash::Algorithm::SHA256)) << "\n";
    }
}
```

### Certificate and CSR Generation

```cpp
#include "lockey/cert/builder.hpp"
#include "lockey/cert/csr_builder.hpp"
#include "lockey/cert/key_utils.hpp"

auto issuer = lockey::cert::generate_ed25519_keypair();
auto subject = lockey::cert::generate_ed25519_keypair();

lockey::cert::CertificateBuilder builder;
builder.set_subject_from_string("CN=Lockey Dev,O=Lockey")
       .set_subject_public_key_ed25519(subject.public_key)
       .set_validity(std::chrono::system_clock::now(),
                     std::chrono::system_clock::now() + std::chrono::hours(24 * 365))
       .set_basic_constraints(false, std::nullopt)
       .set_key_usage(lockey::cert::KeyUsageExtension::DigitalSignature);
auto cert = builder.build_ed25519(issuer, /*self_signed=*/true);

lockey::cert::CsrBuilder csr;
auto csr_doc = csr.set_subject_from_string("CN=Lockey Client,O=Lockey")
                  .set_subject_public_key_ed25519(subject.public_key)
                  .build_ed25519(subject);
```

### Certificate Revocation Lists (CRL)

```cpp
#include "lockey/cert/crl_builder.hpp"

lockey::cert::CrlBuilder crl;
crl.set_issuer_from_string("CN=Lockey CA")
   .set_this_update(std::chrono::system_clock::now())
   .add_revoked(cert.value.tbs().serial_number,
                std::chrono::system_clock::now(),
                lockey::cert::CrlReason::KeyCompromise);
auto crl_doc = crl.build_ed25519(issuer);
bool revoked = cert.value.is_revoked(crl_doc.value);
```

### Advanced X.509 Features

- **Enterprise PKI Extensions**: Support for Issuer Alternative Name, Policy Mappings, Policy Constraints, and Inhibit Any-Policy extensions
- **Extended Key Usage**: Full support for serverAuth, clientAuth, codeSigning, emailProtection, timeStamping, and OCSPSigning
- **Certificate Extensions API**: Programmatic access to all standard and custom X.509v3 extensions
- **ASN.1 Encoding/Decoding**: Complete DER encoder/decoder for all ASN.1 types (SEQUENCE, SET, INTEGER, BIT STRING, OCTET STRING, OID, UTF8String, PrintableString, IA5String, UTCTime, GeneralizedTime)
- **Subject Alternative Names**: Support for DNS names, email addresses, IP addresses, and URIs
- **Distinguished Name Builder**: Fluent API for constructing complex DNs with all standard attributes

See [`docs/X509_USER_GUIDE.md`](docs/X509_USER_GUIDE.md) for detailed certificate API documentation.

## Quick Start

```cpp
#include "lockey/lockey.hpp"
#include <iostream>

int main() {
    lockey::Lockey crypto(lockey::Lockey::Algorithm::XChaCha20_Poly1305);

    auto key = crypto.generate_symmetric_key();               // 32 random bytes
    std::vector<uint8_t> message = {'H', 'e', 'l', 'l', 'o'};

    auto ciphertext = crypto.encrypt(message, key.data);      // nonce || ciphertext
    auto plaintext  = crypto.decrypt(ciphertext.data, key.data);

    std::cout << "Round-trip success: " << std::boolalpha
              << (plaintext.success && plaintext.data == message) << "\n";
}
```

## Cryptographic Primitives

| Primitive                       | Purpose                     | libsodium call                                  |
|---------------------------------|-----------------------------|-------------------------------------------------|
| `XChaCha20_Poly1305`            | Symmetric AEAD              | `crypto_aead_xchacha20poly1305_ietf_*`          |
| `SecretBox_XSalsa20`            | Symmetric secretbox         | `crypto_secretbox_easy/open_easy`               |
| `X25519_Box`                    | Public-key sealed boxes     | `crypto_box_keypair`, `crypto_box_seal(_open)`  |
| `Ed25519`                       | Deterministic signatures    | `crypto_sign_ed25519_*`                         |
| `SHA256`, `SHA512`, `BLAKE2b`   | Hashing/HMAC                | `crypto_hash_*`, `crypto_generichash`, `crypto_auth_*` |

## Usage Guide

### Symmetric Encryption (XChaCha20-Poly1305)

```cpp
lockey::Lockey crypto(lockey::Lockey::Algorithm::XChaCha20_Poly1305);
auto key = crypto.generate_symmetric_key().data;

auto ciphertext = crypto.encrypt(plaintext, key, /*aad=*/{});
auto decrypted  = crypto.decrypt(ciphertext.data, key);
```

### SecretBox (XSalsa20-Poly1305)

```cpp
lockey::Lockey secretbox(lockey::Lockey::Algorithm::SecretBox_XSalsa20);
auto key = secretbox.generate_symmetric_key(lockey::utils::Common::SECRETBOX_KEY_SIZE).data;
auto cipher = secretbox.encrypt(data, key);
auto plain  = secretbox.decrypt(cipher.data, key);
```

### X25519 Sealed Boxes

```cpp
lockey::Lockey box(lockey::Lockey::Algorithm::X25519_Box);
auto recipient = box.generate_keypair();

auto sealed = box.encrypt_asymmetric(data, recipient.public_key);
auto plain  = box.decrypt_asymmetric(sealed.data, recipient.private_key);
```

### Ed25519 Signatures

```cpp
lockey::Lockey signer(lockey::Lockey::Algorithm::Ed25519);
auto keypair = signer.generate_keypair();

auto signature = signer.sign(data, keypair.private_key);
auto verified  = signer.verify(data, signature.data, keypair.public_key);
```

### Hashing & HMAC

```cpp
lockey::Lockey sha512(lockey::Lockey::Algorithm::XChaCha20_Poly1305,
                      lockey::Lockey::HashAlgorithm::SHA512);
auto digest = sha512.hash(data);

auto mac = sha512.hmac(data, key_material);
```

### Utility Functions

```cpp
// Hex encoding/decoding
auto hex = lockey::Lockey::to_hex(bytes);
auto raw = lockey::Lockey::from_hex(hex);

// Key file I/O
lockey::Lockey crypto(lockey::Lockey::Algorithm::X25519_Box);
auto keypair = crypto.generate_keypair();
crypto.save_keypair_to_files(keypair, "pub.bin", "priv.bin");
auto priv = crypto.load_key_from_file("priv.bin", lockey::Lockey::KeyType::PRIVATE);

// Secure operations
auto random = lockey::utils::Common::generate_random_bytes(32);
bool equal = lockey::utils::Common::secure_compare(data1, data2, size);
lockey::utils::Common::secure_clear(sensitive_data, size);

// PKCS#7 padding
auto padded = lockey::utils::Common::pkcs7_pad(data, 16);
auto unpadded = lockey::utils::Common::pkcs7_unpad(padded);

// XOR operations
auto result = lockey::utils::Common::xor_bytes(vec1, vec2);
```

### Secure Key Exchange Envelopes

Lockey provides a complete envelope system for securely exchanging data through files or shared memory:

```cpp
#include "lockey/io/key_exchange.hpp"

lockey::Lockey box(lockey::Lockey::Algorithm::X25519_Box);
auto recipient = box.generate_keypair();

std::vector<uint8_t> payload = {'s', 'e', 'c', 'r', 'e', 't'};
std::vector<uint8_t> aad = {'f', 'i', 'l', 'e'};

lockey::io::key_exchange::write_envelope_to_file(payload, recipient.public_key,
                                             "/tmp/lockey.envelope", aad);

std::vector<uint8_t> recovered_aad;
auto decrypted = lockey::io::key_exchange::read_envelope_from_file("/tmp/lockey.envelope",
                                                               recipient.private_key,
                                                               &recovered_aad);
```

Shared-memory flows use the same envelope bytes with additional safety features:

```cpp
// Create envelope in memory
std::vector<uint8_t> envelope =
    lockey::io::key_exchange::create_envelope(payload, recipient.public_key, aad).data;
auto opened = lockey::io::key_exchange::consume_envelope(envelope, recipient.private_key);

// Direct memory buffer operations with capacity checking
uint8_t buffer[4096];
size_t written;
lockey::io::key_exchange::write_envelope_to_memory(buffer, sizeof(buffer), written,
                                                   payload, recipient.public_key, aad);
                                                   
auto result = lockey::io::key_exchange::read_envelope_from_memory(buffer, written,
                                                                 recipient.private_key);
```

## Certificate Verification Protocol (LVP)

When compiled with `LOCKEY_HAS_VERIFY=ON`, Lockey includes a modern certificate revocation checking system:

```cpp
#include <lockey/verify/client.hpp>
#include <lockey/verify/server.hpp>

// Client-side verification
lockey::verify::Client client("localhost:50051");
auto response = client.verify_chain(certificate_chain);
if (response.success && response.value.valid) {
    std::cout << "Certificate is valid\n";
}

// Server-side handler
class MyHandler : public lockey::verify::VerificationHandler {
    wire::VerifyResponse verify_chain(const std::vector<cert::Certificate> &chain,
                                     std::chrono::system_clock::time_point validation_time) override {
        // Custom verification logic
        return response;
    }
};

// Start verification server
lockey::verify::ServerConfig config;
config.address = "0.0.0.0:50051";
auto handler = std::make_shared<MyHandler>();
lockey::verify::Server server(handler, config);
server.start();
```

Features:
- gRPC/HTTP2 transport with optional TLS
- Custom binary wire format optimized for Ed25519
- Batch verification support for efficiency  
- Nonce-based replay protection
- Ed25519 signed responses
- Built-in health checks
- In-memory revocation list management

See [`docs/VERIFY_PROTOCOL.md`](docs/VERIFY_PROTOCOL.md) for protocol specification.

## Building & Testing

```bash
# CMake-only workflow
cmake -S . -B build -DLOCKEY_BUILD_EXAMPLES=ON -DLOCKEY_ENABLE_TESTS=ON
cmake --build build
cd build && ctest --output-on-failure

# Or use the convenience targets
make config   # configures with tests/examples enabled
make          # builds everything under ./build
make test     # wraps ctest
```

### Test Coverage

Comprehensive test suite with 20+ test files covering:
- **Cryptography**: Symmetric/asymmetric encryption, signatures, hashing, HMAC
- **Certificates**: Parsing, generation, validation, chain verification
- **Extensions**: Basic Constraints, Key Usage, Extended Key Usage, Alternative Names
- **Enterprise PKI**: Policy extensions, CRL handling, trust store operations
- **ASN.1**: DER encoding/decoding for all supported types
- **Key Management**: Generation, I/O, format conversions
- **Envelopes**: File and memory-based secure exchange
- **Utilities**: Padding, hex encoding, secure comparisons

Each test file becomes its own executable when `LOCKEY_ENABLE_TESTS=ON`, allowing focused testing.

### Requirements

- C++20 compatible compiler (GCC 10+, Clang 11+, MSVC 2019+)
- libsodium 1.0.18+ installed
- CMake 3.14+ for building
- Optional: gRPC for verification protocol (`LOCKEY_HAS_VERIFY=ON`)

## Enterprise PKI Features

Lockey includes advanced PKI features typically found in enterprise certificate management:

### Policy Extensions
- **Policy Mappings**: Map issuer domain policies to subject domain policies
- **Policy Constraints**: Control policy requirements down the certificate chain
- **Inhibit Any-Policy**: Restrict the use of anyPolicy OID in certificate chains

### Advanced Extensions
- **Issuer Alternative Name**: Multiple identities for certificate issuers
- **Name Constraints**: Restrict the namespace for sub-CAs
- **CRL Distribution Points**: Specify where to obtain revocation information
- **Authority Information Access**: OCSP and CA issuer URLs

### Enterprise Use Cases
- Multi-level CA hierarchies with constrained delegation
- Cross-certification between organizations
- Policy-aware certificate validation
- Complex trust models with bridge CAs

## Examples

All examples live in [`examples/`](examples/) and demonstrate real-world usage:

### Basic Cryptography
- `main.cpp` - Complete walkthrough of symmetric encryption, hashing, signing
- `test_comprehensive.cpp` - Exercises every libsodium primitive end-to-end
- `test_lockey.cpp` - Minimal smoke test for quick verification

### Certificate Operations
- `cert_generate_self_signed.cpp` - Build self-signed Ed25519 certificates
- `cert_generate_ca.cpp` - Create CA certificates with proper constraints
- `csr_generate.cpp` - Generate PKCS#10 Certificate Signing Requests
- `cert_sign_csr.cpp` - Issue certificates from CSRs
- `cert_verify_chain.cpp` - Complete chain validation example
- `cert_parse_and_print.cpp` - Parse and inspect certificate details
- `trust_store_usage.cpp` - Programmatic trust store management

### Advanced Features
- `enterprise.cpp` - Enterprise PKI extensions demonstration
- `simple_verify_client.cpp` - Certificate verification protocol client
- `simple_verify_server.cpp` - Certificate verification protocol server
- `verify_grpc.cpp` - gRPC-based verification implementation

## API Quick Reference

### Core Types
```cpp
lockey::Lockey                    // Main crypto context
lockey::CryptoResult              // Result<vector<uint8_t>, string>
lockey::KeyPair                   // Public + private key pair
lockey::cert::Certificate         // X.509 certificate
lockey::cert::CertificateBuilder  // Fluent certificate builder
lockey::cert::CsrBuilder          // CSR builder
lockey::cert::CrlBuilder          // CRL builder
lockey::cert::TrustStore          // Certificate trust store
lockey::cert::DistinguishedName   // X.500 DN
lockey::verify::Client            // Verification client
lockey::verify::Server            // Verification server
```

### Common Operations
```cpp
// Encryption
crypto.encrypt(plaintext, key, aad)
crypto.decrypt(ciphertext, key, aad)

// Signatures
crypto.sign(data, private_key)
crypto.verify(data, signature, public_key)

// Certificates
Certificate::load(path)
Certificate::save(path)
certificate.validate_chain(intermediates, trust_store)
certificate.match_hostname(hostname)

// Key Management
crypto.generate_keypair()
crypto.generate_symmetric_key()
crypto.save_keypair_to_files(keypair, pub_file, priv_file)
```

## License

Licensed under the [MIT License](LICENSE).

---

Lockey keeps the fast libsodium internals and leaves the legacy interfaces behind. If you need modern crypto primitives without a heavyweight dependency graph, this is it.
