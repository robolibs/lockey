<img align="right" width="26%" src="./misc/logo.png">

# keylock

A lightweight C++20 libsodium wrapper with a complete Ed25519-focused X.509 certificate toolkit.

## Development Status

See [TODO.md](./TODO.md) for the complete development plan and current progress.

## Overview

keylock wraps the battle-tested **libsodium** cryptography library in a clean, modern C++20 API. It provides only modern, authenticated primitives: XChaCha20-Poly1305 for symmetric encryption, X25519 sealed boxes for public-key encryption, Ed25519 for digital signatures, and SHA-256/SHA-512/BLAKE2b for hashing. No RSA, no ECDSA, no legacy baggage.

Beyond cryptographic primitives, keylock includes a complete X.509 certificate toolkit built entirely in pure C++. The library implements its own ASN.1 DER parser and encoder without any external dependencies like OpenSSL or Boost. This enables full certificate parsing, generation, validation, and chain verification using modern Ed25519 signatures throughout.

The design philosophy prioritizes safety and simplicity. All fallible operations return result types instead of throwing exceptions. Builder patterns provide fluent APIs for constructing certificates, CSRs, and CRLs. An optional verification protocol offers a lightweight OCSP alternative using netpipe transport, adding zero overhead when disabled.

### Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              keylock LIBRARY                                 │
├───────────────┬───────────────┬───────────────┬───────────────┬─────────────┤
│    CRYPTO     │     CERT      │     HASH      │      IO       │   VERIFY    │
│               │               │               │               │  (optional) │
│  ┌─────────┐  │  ┌─────────┐  │  ┌─────────┐  │  ┌─────────┐  │  ┌───────┐  │
│  │XChaCha20│  │  │ Parser  │  │  │ SHA-256 │  │  │  Files  │  │  │Client │  │
│  │Poly1305 │  │  │ Builder │  │  │ SHA-512 │  │  │Envelope │  │  │Server │  │
│  │ X25519  │  │  │  CSR    │  │  │ BLAKE2b │  │  │  Keys   │  │  │Handler│  │
│  │ Ed25519 │  │  │  CRL    │  │  │  HMAC   │  │  └─────────┘  │  └───────┘  │
│  └─────────┘  │  │ Trust   │  │  └─────────┘  │               │      │      │
│       │       │  └─────────┘  │       │       │               │      │      │
└───────┼───────┴───────┼───────┴───────┼───────┴───────────────┴──────┼──────┘
        │               │               │                              │
        └───────────────┴───────────────┴──────────────────────────────┘
                                    │
                        ┌───────────▼───────────┐
                        │      libsodium        │
                        │  (crypto primitives)  │
                        └───────────────────────┘
```

**Module Responsibilities:**

```
CRYPTO ─────► Symmetric/asymmetric encryption, signatures, key generation
CERT ───────► X.509 parsing, building, validation, trust stores, CSR/CRL
HASH ───────► Cryptographic hashing (SHA-256, SHA-512, BLAKE2b) and HMAC
IO ─────────► Binary file I/O, X25519 sealed envelope operations
VERIFY ─────► Optional netpipe-based certificate verification protocol
```

## Installation

### Quick Start (CMake FetchContent)

```cmake
include(FetchContent)
FetchContent_Declare(
  keylock
  GIT_REPOSITORY https://github.com/robolibs/lockey
  GIT_TAG main
)
FetchContent_MakeAvailable(keylock)

target_link_libraries(your_target PRIVATE keylock)
```

### Recommended: XMake

[XMake](https://xmake.io/) is a modern, fast, and cross-platform build system.

**Install XMake:**
```bash
curl -fsSL https://xmake.io/shget.text | bash
```

**Add to your xmake.lua:**
```lua
add_requires("keylock")

target("your_target")
    set_kind("binary")
    add_packages("keylock")
    add_files("src/*.cpp")
```

**Build:**
```bash
xmake
xmake run
```

### Complete Development Environment (Nix + Direnv + Devbox)

For the ultimate reproducible development environment:

**1. Install Nix (package manager from NixOS):**
```bash
curl --proto '=https' --tlsv1.2 -sSf -L https://install.determinate.systems/nix | sh -s -- install
```
[Nix](https://nixos.org/) - Reproducible, declarative package management

**2. Install direnv (automatic environment switching):**
```bash
sudo apt install direnv

# Add to your shell (~/.bashrc or ~/.zshrc):
eval "$(direnv hook bash)"  # or zsh
```
[direnv](https://direnv.net/) - Load environment variables based on directory

**3. Install Devbox (Nix-powered development environments):**
```bash
curl -fsSL https://get.jetpack.io/devbox | bash
```
[Devbox](https://www.jetpack.io/devbox/) - Portable, isolated dev environments

**4. Use the environment:**
```bash
cd keylock
direnv allow  # Allow .envrc (one-time)
# Environment automatically loaded! All dependencies available.

xmake        # or cmake, make, etc.
```

## Usage

### Basic Usage

```cpp
#include <keylock/keylock.hpp>

int main() {
    // Symmetric encryption with XChaCha20-Poly1305
    keylock::crypto::Context crypto(keylock::crypto::Context::Algorithm::XChaCha20_Poly1305);

    auto key = crypto.generate_symmetric_key();
    std::vector<uint8_t> message = {'H', 'e', 'l', 'l', 'o'};

    auto ciphertext = crypto.encrypt(message, key.data);
    auto plaintext = crypto.decrypt(ciphertext.data, key.data);
    // plaintext.data == message

    // Digital signatures with Ed25519
    keylock::crypto::Context signer(keylock::crypto::Context::Algorithm::Ed25519);
    auto keypair = signer.generate_keypair();

    auto signature = signer.sign(message, keypair.private_key);
    auto verified = signer.verify(message, signature.data, keypair.public_key);
    // verified.success == true
}
```

### Advanced Usage

```cpp
#include <keylock/keylock.hpp>
#include <keylock/cert/builder.hpp>
#include <keylock/cert/trust_store.hpp>

int main() {
    using namespace keylock::cert;

    // Generate Ed25519 keypair for certificate
    keylock::crypto::Context ctx(keylock::crypto::Context::Algorithm::Ed25519);
    auto ca_keys = ctx.generate_keypair();

    // Build a self-signed CA certificate
    auto dn = DistinguishedName::from_string("CN=My CA,O=Example Corp,C=US");

    auto now = std::chrono::system_clock::now();
    auto one_year = std::chrono::hours(24 * 365);

    CertificateBuilder builder;
    builder.set_version(3)
           .set_serial(1)
           .set_subject(dn.value)
           .set_issuer(dn.value)
           .set_validity(now, now + one_year)
           .set_subject_public_key_ed25519(ca_keys.public_key)
           .set_basic_constraints(true, 0, true)  // CA=true, pathLen=0
           .set_key_usage(KeyUsageExtension::KeyCertSign | KeyUsageExtension::CRLSign);

    auto ca_cert = builder.build_ed25519(ca_keys, /*self_signed=*/true);

    // Load system trust store and validate a certificate chain
    auto trust = TrustStore::load_from_system();
    if (trust.success) {
        std::vector<Certificate> chain = {end_entity_cert, intermediate_cert};
        auto validation = end_entity_cert.validate_chain(chain, trust.value);

        if (validation.success) {
            // Chain is valid and trusted
        }
    }

    // Check hostname against certificate SANs
    if (ca_cert.value.match_hostname("example.com")) {
        // Certificate is valid for this hostname
    }
}
```

## Features

- **Modern Cryptography Only** - XChaCha20-Poly1305 AEAD encryption with 256-bit keys and 192-bit nonces, X25519 sealed boxes for public-key encryption, Ed25519 signatures. No RSA, no ECDSA, no legacy algorithms.
  ```cpp
  keylock::crypto::Context box(keylock::crypto::Context::Algorithm::X25519_Box);
  auto recipient = box.generate_keypair();
  auto sealed = box.encrypt_asymmetric(data, recipient.public_key);
  auto opened = box.decrypt_asymmetric(sealed.data, recipient.private_key);
  ```

- **Pure C++ ASN.1 Codec** - Complete DER parser and encoder with no external dependencies. Parses integers, bit strings, OIDs, sequences, sets, UTC/generalized time, and directory strings.

- **X.509 Certificate Builder** - Fluent API for creating certificates with all standard extensions: Basic Constraints, Key Usage, Extended Key Usage, Subject Alt Names, Authority/Subject Key Identifiers.
  ```cpp
  CertificateBuilder builder;
  builder.set_subject(dn)
         .set_subject_public_key_ed25519(keys.public_key)
         .set_subject_alt_name({{GeneralNameType::DNSName, "*.example.com"},
                                {GeneralNameType::IPAddress, "192.168.1.1"}})
         .set_extended_key_usage({oid::ServerAuth, oid::ClientAuth});
  auto cert = builder.build_ed25519(keys, true);
  ```

- **Complete PKI Workflow** - Certificate Signing Requests (CSR/PKCS#10), Certificate Revocation Lists (CRL v1/v2), chain validation against trust stores, hostname verification with wildcard support.
  ```cpp
  CsrBuilder csr;
  csr.set_subject(dn).set_subject_public_key_ed25519(keys.public_key);
  auto request = csr.build_ed25519(keys);
  request.value.save("request.pem", /*pem=*/true);
  ```

- **Enterprise PKI Extensions** - Full RFC 5280 compliance including Policy Mappings, Policy Constraints, Inhibit Any Policy, and Name Constraints for complex PKI deployments.

- **Trust Store Integration** - Load certificates from system CA bundles (Debian, RHEL, FreeBSD), explicit file paths, or environment variables (`SSL_CERT_FILE`, `SSL_CERT_DIR`).
  ```cpp
  auto trust = TrustStore::load_from_system();  // Auto-detects OS CA bundle
  auto trust = TrustStore::load_from_file("/custom/ca-bundle.crt");
  ```

- **Cryptographic Hashing** - SHA-256, SHA-512, and BLAKE2b with HMAC support for all algorithms.
  ```cpp
  auto digest = keylock::hash::digest(keylock::hash::Algorithm::SHA256, data);
  auto mac = keylock::hash::hmac(keylock::hash::Algorithm::BLAKE2b, data, key);
  ```

- **Secure Key Exchange** - X25519 sealed box envelopes with optional Associated Authenticated Data (AAD) for secure file encryption and key transport.
  ```cpp
  auto envelope = keylock::io::create_envelope(payload, recipient_public_key, aad);
  keylock::io::write_envelope_to_file(envelope.data, "encrypted.bin");
  ```

- **Verification Protocol** - Lightweight netpipe-based OCSP alternative with Ed25519-signed responses and replay protection.
  ```cpp
  // Client
  keylock::verify::Client client("localhost:50051");
  auto result = client.verify_chain(certificate_chain);

  // Server with custom handler
  auto handler = std::make_shared<keylock::verify::SimpleRevocationHandler>();
  handler->add_revoked_certificate(serial, "Key compromise");
  keylock::verify::Server server(handler, config);
  server.start_async();
  ```

- **Type-Safe Error Handling** - All operations return result types with `{success, data, error}` instead of throwing exceptions. Enables clean error handling without try-catch overhead.

- **Efficient Memory Usage** - Lazy DER encoding and extension parsing. Certificate data parsed on-demand. Constant-time secure memory comparison and zeroing.

## Performance

**Cryptographic Operations (typical values):**
- XChaCha20-Poly1305: ~500 MB/s throughput, ~2 µs latency (1KB messages)
- Ed25519 sign: ~80K ops/s, Ed25519 verify: ~150K ops/s
- SHA-256: ~800 MB/s, BLAKE2b: ~600 MB/s

**Certificate Operations:**
- Parse X.509 certificate: ~50 µs
- Build self-signed cert: ~100 µs (Ed25519 signing dominates)
- Validate 3-certificate chain: ~200 µs

**Memory Footprint:**
- Library binary: ~150 KB stripped (static lib)
- Runtime overhead: ~5 KB per Context instance
- Certificate object: ~2 KB + DER data size

## Security Best Practices

**Key Management:**
- Never hardcode keys - load from secure storage at runtime
- Use secure file permissions (0600 on Unix for private keys)
- Implement key rotation in your PKI workflow
- Separate signing and encryption keys

```cpp
// Good: Load from secure storage
auto key_result = ctx.load_key_from_file("/secure/private.key", keylock::crypto::Context::KeyType::PRIVATE);
```

**Certificate Lifecycle:**
- Use short validity periods (90-365 days for end-entity certs)
- Always set path length constraints on intermediate CAs
- Implement revocation checking via CRL or LVP verification
- Always verify certificate hostname matches expected value

**Error Handling:**
- Always check the `success` flag on result types
- Log errors without leaking sensitive data (no private keys in logs)
- Fail closed on validation failures
- Implement rate limiting for verification services

**Random Number Generation:**
- Always use libsodium's RNG (never std::rand or similar)
- Generate fresh nonces for each encryption operation
- Use constant-time comparisons for secret data

```cpp
// Good: Use libsodium RNG
auto keypair = ctx.generate_keypair();
std::vector<uint8_t> nonce(24);
randombytes_buf(nonce.data(), nonce.size());
```

## Building

```bash
# Using Make (recommended)
make config   # Configure with tests and examples
make          # Build library
make test     # Run 34-test suite

# Using CMake directly
cmake -S . -B build \
    -Dkeylock_BUILD_EXAMPLES=ON \
    -Dkeylock_ENABLE_TESTS=ON
cmake --build build
ctest --test-dir build --output-on-failure

# Using XMake
xmake config --tests=y --examples=y
xmake build
xmake test
```

**Requirements:**
- C++20 compiler (GCC 10+, Clang 11+)
- libsodium 1.0.18+
- CMake 3.14+ or XMake 2.5+

**Build Options:**
| Option | Default | Description |
|--------|---------|-------------|
| `keylock_BUILD_EXAMPLES` | OFF | Build 14 example programs |
| `keylock_ENABLE_TESTS` | OFF | Build test suite |
| `keylock_ENABLE_SIMD` | ON | Enable SIMD optimizations (AVX2/NEON) |

## Documentation

- **X.509 User Guide**: [misc/X509_USER_GUIDE.md](./misc/X509_USER_GUIDE.md) - Complete certificate API reference with examples
- **Verification Protocol**: [misc/VERIFY_PROTOCOL.md](./misc/VERIFY_PROTOCOL.md) - Wire format specification and security considerations

## Examples

Working examples in [`examples/`](./examples/):

| Category | Files |
|----------|-------|
| **Cryptography** | `main.cpp`, `test_keylock.cpp`, `test_comprehensive.cpp` |
| **Certificates** | `cert_generate_self_signed.cpp`, `cert_generate_ca.cpp`, `cert_parse_and_print.cpp`, `cert_sign_csr.cpp`, `cert_verify_chain.cpp`, `csr_generate.cpp` |
| **Trust Store** | `trust_store_usage.cpp` |
| **Enterprise PKI** | `enterprise.cpp` (policy constraints, name constraints) |
| **Verification** | `simple_verify_server.cpp`, `simple_verify_client.cpp`, `verify_netpipe.cpp` |

## License

MIT License - see [LICENSE](./LICENSE) for details.

## Acknowledgments

Made possible thanks to [these amazing projects](./ACKNOWLEDGMENTS.md).

**Core Dependencies:**
- [libsodium](https://github.com/jedisct1/libsodium) - Modern, portable cryptography library
- [netpipe](https://github.com/robolibs/netpipe) - Lightweight network protocol transport
- [datapod](https://github.com/robolibs/datapod) - POD-compatible containers for robotics
- [doctest](https://github.com/doctest/doctest) - Fast C++ testing framework
