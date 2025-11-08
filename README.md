<img align="right" width="26%" src="./misc/logo.png">

# Lockey

**A tiny, header-only C++20 libsodium facade with an Ed25519-focused X.509 toolkit**

[![Build Status](https://img.shields.io/badge/build-passing-brightgreen)](https://github.com/yourusername/lockey)
[![Language](https://img.shields.io/badge/language-C%2B%2B20-blue)](https://en.cppreference.com/w/cpp/20)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Header Only](https://img.shields.io/badge/header--only-yes-orange)](https://github.com/yourusername/lockey)

## Overview

Lockey wraps the battle-tested **libsodium** toolbox in a clean, zero-dependency C++20 API. Only modern, authenticated primitives make the cut: XChaCha20-Poly1305, SecretBox (XSalsa20-Poly1305), X25519 sealed boxes, Ed25519 signatures, and SHA-256/SHA-512/BLAKE2b (plus HMAC). No RSA, no ECDSA, no legacy baggage - just high-level helpers around the safe defaults you actually want.

### 🚀 Key Features

- **libsodium-only backend** - every operation delegates to libsodium and calls `sodium_init()` exactly once.
- **Header-only** - include `lockey/lockey.hpp` and go.
- **Modern AEAD options** - XChaCha20-Poly1305 and SecretBox XSalsa20-Poly1305 for symmetric encryption.
- **Curve25519 everywhere** - X25519 sealed boxes for public-key encryption and Ed25519 for signatures.
- **Hashing & HMAC** - SHA-256, SHA-512, and BLAKE2b via libsodium.
- **Full DER/PEM X.509 stack** - strict ASN.1 parsers, builders, CSRs, CRLs, and trust stores all live under `lockey::cert`.
- **Key utilities** - raw key generation, simple file I/O helpers, and hex conversion helpers for debugging.
- **Robust exchange envelopes** - serialize/libsodium-seal payloads for files or shared memory with integrity checks.
- **Modular namespaces** - `lockey::crypto`, `lockey::hash`, `lockey::io`, `lockey::utils`, and `lockey::cert` mirror the on-disk layout for easier integration.

## Modules at a Glance

- `lockey::crypto` - symmetric/asymmetric crypto context that wraps libsodium (XChaCha20-Poly1305, SecretBox, X25519 sealed boxes, Ed25519 signing).
- `lockey::hash` - stateless hashing/HMAC helpers that expose SHA-256/SHA-512/BLAKE2b via a consistent API.
- `lockey::utils` - common helpers (random bytes, hex, PKCS#7, constant-time comparisons, hex encoding).
- `lockey::io` - binary I/O helpers plus the key-exchange envelope helpers for files/shared memory.
- `lockey::cert` - DER/PEM aware X.509 stack: ASN.1 readers/writers, certificate/CSR/CRL builders, parsers, trust store loader, Ed25519 SPKI helpers, and OID registry.

## X.509 Toolkit Highlights

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

### Build Ed25519 leaf or CA certs (and CSRs) in pure C++

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

### Capture revocations and integrate custom trust stores

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

## Supported Primitives

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

### Hex Helpers & Key Files

```cpp
auto hex = lockey::Lockey::to_hex(bytes);
auto raw = lockey::Lockey::from_hex(hex);

lockey::Lockey crypto(lockey::Lockey::Algorithm::X25519_Box);
auto keypair = crypto.generate_keypair();
crypto.save_keypair_to_files(keypair, "pub.bin", "priv.bin");
auto priv = crypto.load_key_from_file("priv.bin", lockey::Lockey::KeyType::PRIVATE);
```

### Key Exchange Envelopes (files or shared memory)

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

Shared-memory flows use the same envelope bytes:

```cpp
std::vector<uint8_t> envelope =
    lockey::io::key_exchange::create_envelope(payload, recipient.public_key, aad).data;
auto opened = lockey::io::key_exchange::consume_envelope(envelope, recipient.private_key);
```

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

- All tests live in [`test/`](test/) and are Doctest executables (`test_cert_parser.cpp`, `test_cert_crl.cpp`, `test_cert_generation.cpp`, etc.) covering ASN.1 parsing, certificate/CSR/CRL builders, trust stores, key exchange envelopes, and the crypto facade.
- `LOCKEY_ENABLE_TESTS` turns each file into its own binary so you can run focused suites (e.g., `./build/test_cert_chain`).
- `LOCKEY_BUILD_EXAMPLES` exposes the snippets in [`examples/`](examples/) - handy for stepping through debugger sessions.
- You only need libsodium on your system; everything else is header-only.

## Examples

All examples live in [`examples/`](examples/) and mirror the API described above:

- `main.cpp` - walk-through of symmetric encryption, hashing, signing, and POJO utilities.
- `test_comprehensive.cpp` - exercises every libsodium-backed primitive end-to-end.
- `test_lockey.cpp` - smallest possible smoke test.

## License

Licensed under the [MIT License](LICENSE).

---

Lockey keeps the fast libsodium internals and leaves the legacy interfaces behind. If you need modern crypto primitives without a heavyweight dependency graph, this is it.
