# Lockey X.509 User Guide

## Conceptual Overview

- An X.509 certificate is composed of a TBSCertificate (subject, issuer, validity, subject public key info, extensions), an AlgorithmIdentifier, and a signature. Lockey mirrors this structure through `lockey::cert::Certificate`, `Validity`, `SubjectPublicKeyInfo`, and `RawExtension`.
- Lockey focuses on modern curves (Ed25519 for signatures, Curve25519 for key exchange). The certificate builder hardens this choice by exposing fluent helpers that only emit safe defaults.
- ASN.1 DER and PEM support are first-class: every parser operates on DER (`ByteSpan`) and higher-level helpers convert between PEM and DER without third-party dependencies.
- Extension data is preserved in `RawExtension` so you can inspect Key Usage, Basic Constraints, Subject Alt Names, and more without reparsing raw DER.

## Generating Certificates

1. **Self-signed identity**  
   - Use `CertificateBuilder` with `.set_subject_from_string(...)`, `.set_subject_public_key_ed25519(...)`, `.set_basic_constraints(false, std::nullopt)`, and `.set_key_usage(...)`.
   - Call `.build_ed25519(subject_keypair, /*self_signed=*/true)` to obtain a `Certificate` with DER/PEM accessors.
   - See `examples/cert_generate_self_signed.cpp`.

2. **Issuing/CA certificates**  
   - Create a dedicated Ed25519 key pair via `generate_ed25519_keypair()`.
   - Apply `set_basic_constraints(true, path_length)` and CA-focused key usage bits (`KeyCertSign | CRLSign`).
   - Save the resulting PEM via `Certificate::save(path)`.
   - See `examples/cert_generate_ca.cpp`.

3. **CSRs and issuance**  
   - Generate CSRs with `CsrBuilder`, supplying the subject DN and subject public key info.
   - Parse CSRs using `load_csr()` (or directly consume the `CertificateRequest` returned by the builder) to pull `info.subject` and `info.subject_public_key_info`.
   - Feed those fields back into `CertificateBuilder`, set the issuer to your CA DN, and call `.build_ed25519(ca_keypair, false)` to sign.
   - See `examples/csr_generate.cpp` and `examples/cert_sign_csr.cpp`.

## Validating Certificates

- Build chains using `Certificate::validate_chain(intermediates, trust_store)`. The vector should contain intermediate certificates ordered from child to parent.
- Construct a `TrustStore`, populate it with anchor certificates via `add()` or from disk (`load_from_pem`, `load_from_der`, or `load_from_system`).
- Each certificate exposes helpers such as `match_hostname`, `basic_constraints_ca`, `key_usage_bits`, and `subject_alt_names()` to implement custom checks before or after structural validation.
- See `examples/cert_verify_chain.cpp` for programmatic chain creation and verification.

## Managing Trust Stores

- `TrustStore` is a thin container over `std::vector<Certificate>` that understands subjects. Use `add()` to register anchors, `remove_by_subject()` to delete them, and `find_issuer()` to discover potential issuers for a leaf certificate.
- The convenience loaders (`load_from_pem`, `load_from_der`, `load_from_file`, `load_from_system`) simplify pulling in OS CA bundles during development.
- See `examples/trust_store_usage.cpp` for a self-contained workflow.

## Security Best Practices

- Keep private keys in secure storage. The examples generate keys in-memory for clarity, but real deployments should load keys from encrypted disk or HSMs.
- Limit certificate lifetimes (`set_validity`) and use path length constraints for intermediates to avoid unbounded delegation.
- Always verify results from `build_ed25519`, `load()`, and `validate_chain` and fail closed when operations return `success == false`.
- Persist PEM/DER files with restrictive permissions (e.g., `0600` on Unix) when writing keys or certificates.
- Prefer libsodium-backed randomness (`generate_ed25519_keypair`, `Lockey::generate_symmetric_key`) over ad-hoc RNGs.

## Additional Resources

- Examples directory: `examples/` (CMake builds them automatically when `LOCKEY_BUILD_EXAMPLES=ON`).
- Tests exercise every builder/parser path under `test/`; they are a good reference for edge cases.
- For more background on ASN.1 and X.509, consult RFC 5280 alongside the upstream reference implementation noted in `TODO.md`.
