# Changelog

## [0.0.11] - 2026-01-17

### <!-- 0 -->⛰️  Features

- Add a comprehensive set of cryptographic primitives

### <!-- 6 -->🧪 Testing

- Add comprehensive test coverage for cryptographic primitives

## [0.0.10] - 2026-01-17

### <!-- 0 -->⛰️  Features

- Refactor X25519 and Ed25519 implementations
- Relocate verification and utility headers
- Replaced libsodium with internal crypto implementations

### <!-- 7 -->⚙️ Miscellaneous Tasks

- Add ACKNOWLEDGMENTS.md file

## [0.0.8] - 2026-01-17

### <!-- 0 -->⛰️  Features

- Migrate to header-only implementation

## [0.0.7] - 2026-01-17

### <!-- 0 -->⛰️  Features

- Refactor verification protocol for transport-agnostic design

## [0.0.6] - 2026-01-17

### <!-- 0 -->⛰️  Features

- Add support for AES-GCM, ChaCha20-Poly1305, and HKDF

## [0.0.5] - 2026-01-13

### <!-- 7 -->⚙️ Miscellaneous Tasks

- Update documentation and examples

## [0.0.4] - 2026-01-12

### <!-- 2 -->🚜 Refactor

- Rename `lockey` project to `keylock`

## [0.0.3] - 2026-01-11

### <!-- 0 -->⛰️  Features

- Remove optionality of verification protocol

### <!-- 3 -->📚 Documentation

- Revise and expand README to improve clarity
- Move protocol and X509 guides to misc directory

## [0.0.2] - 2026-01-11

### <!-- 2 -->🚜 Refactor

- Remove Protobuf definition for verification service

### <!-- 3 -->📚 Documentation

- Cleanup gitignore for devbox and build artifacts
- Refactor documentation and project structure
- Update docs and remove unused dev dependency

### <!-- 7 -->⚙️ Miscellaneous Tasks

- Refactor build system for modularity and compiler choice

## [0.3.0] - 2025-11-12

### <!-- 0 -->⛰️  Features

- Add keylock Verification Protocol (LVP) support
- Implement gRPC certificate verification service
- Feat: Add gRPC verification server with revocation and signing
- Implement synchronous generic gRPC stub with callbacks
- Add gRPC-based certificate revocation verification
- Feat: Add Extended Key Usage (EKU) X.509 certificate extension
- Add enterprise PKI extension examples
- Implement X.509 enterprise certificate extensions parsing
- Add certificate chain and vector generation helpers
- Implement comprehensive CRL parsing and validation
- Implement comprehensive X.509 certificate management
- Feat: Add X.509 certificate and ASN.1 DER support
- Switched to using libsodium as backend

### <!-- 1 -->🐛 Bug Fixes

- Refactor gRPC verification for Abseil logging and simplicity
- Certificate and CRL builders for error handling

### <!-- 2 -->🚜 Refactor

- Upgrade certificate version to 3 across examples and tests
- Modularize keylock codebase with namespaces

### <!-- 3 -->📚 Documentation

- Add C++ keylock Verification Protocol server and docs
- Add comprehensive X.509 certificate management examples
- Feat: Add X.509 toolkit and certificate integration tests

### <!-- 6 -->🧪 Testing

- Add comprehensive certificate and ASN.1 test suite

### <!-- 7 -->⚙️ Miscellaneous Tasks

- Enable gRPC support and update dependencies

## [0.2.0] - 2025-06-12

### <!-- 0 -->⛰️  Features

- Migrate keylock to libsodium-only primitives (XChaCha20, SecretBox, X25519, Ed25519, SHA-256/SHA-512/BLAKE2b)
- Remove legacy RSA/ECDSA/AES engines along with every OpenSSL comparison helper
- Add authenticated key-exchange envelopes for file/shared-memory transport
- Split the library into `keylock::crypto`, `keylock::hash`, `keylock::io`, and `keylock::utils` namespaces with matching src/include layout
- Add examples comparing keylock with OpenSSL chains
- Implement support for elliptic curve cryptography
- Feat: Add BLAKE2b hash and improve crypto tests
- Refine and standardize deterministic cryptography functions
- Add asymmetric encryption key persistence
- Add unit tests
- Of build system or dependencies.
- Reinit
- Reinit
- Add cryptographic algorithms and demos
- Implement common cryptographic hashing algorithms
- Add key I/O example
- Feat: Add universal cryptographic support to keylock
- Feat(crypto): Implement RSA encryption and signing
- Init
- Init

### <!-- 2 -->🚜 Refactor

- Remove unused simple RSA implementation usage
- Refactor crypto implementation details
- Replace internal crypto header
- Consolidate keylock and simplify testing examples

### <!-- 3 -->📚 Documentation

- Rewrite README to describe the libsodium-only surface and updated examples
- Document the new envelope-based key exchange helpers
- Update README with comprehensive library documentation
- Add comprehensive README documentation

### <!-- 7 -->⚙️ Miscellaneous Tasks

- Ignore unused files created during testing

### Build

- Set up build system infrastructure
