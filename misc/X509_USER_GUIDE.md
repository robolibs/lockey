# keylock X.509 User Guide

## Conceptual Overview

- An X.509 certificate is composed of a TBSCertificate (subject, issuer, validity, subject public key info, extensions), an AlgorithmIdentifier, and a signature. keylock mirrors this structure through `keylock::cert::Certificate`, `Validity`, `SubjectPublicKeyInfo`, and `RawExtension`.
- keylock focuses on modern curves (Ed25519 for signatures, Curve25519 for key exchange). The certificate builder hardens this choice by exposing fluent helpers that only emit safe defaults.
- ASN.1 DER and PEM support are first-class: every parser operates on DER (`ByteSpan`) and higher-level helpers convert between PEM and DER without third-party dependencies.
- Extension data is preserved in `RawExtension` so you can inspect Key Usage, Basic Constraints, Subject Alt Names, and more without reparsing raw DER.

## Certificate Structure

```
┌─────────────────────────────────────────────────────────────┐
│                      X.509 Certificate                        │
├─────────────────────────────────────────────────────────────┤
│  1. TBSCertificate (To Be Signed Certificate)                 │
│     ├─ Version                                              │
│     ├─ Serial Number                                        │
│     ├─ Signature Algorithm Identifier                         │
│     ├─ Issuer Distinguished Name                             │
│     ├─ Validity (Not Before / Not After)                     │
│     ├─ Subject Distinguished Name                            │
│     ├─ Subject Public Key Info (Ed25519)                    │
│     └─ Extensions (Basic Constraints, Key Usage, SAN, etc.) │
│  2. Signature Algorithm Identifier                            │
│  3. Signature (Ed25519 signature over TBSCertificate)       │
└─────────────────────────────────────────────────────────────┘
```

## Generating Certificates

### 1. Self-Signed Identity Certificate

Generate a self-signed certificate for testing or internal use:

```cpp
#include <keylock/cert/builder.hpp>
#include <keylock/cert/key_utils.hpp>

using namespace std::chrono_literals;
using keylock::cert::CertificateBuilder;

// Generate Ed25519 keypair
const auto subject_key = keylock::cert::generate_ed25519_keypair();

// Build certificate
CertificateBuilder builder;
const auto now = std::chrono::system_clock::now();

builder.set_subject_from_string("CN=keylock Self-Signed,O=keylock,C=US")
       .set_subject_public_key_ed25519(subject_key.public_key)
       .set_validity(now - 1h, now + 365 * 24h)
       .set_basic_constraints(false, std::nullopt)
       .set_key_usage(keylock::cert::KeyUsageExtension::DigitalSignature);

// Build (self-signed)
auto certificate = builder.build_ed25519(subject_key, /*self_signed=*/true);
if (!certificate.success) {
    std::cerr << "Failed: " << certificate.error << "\n";
    return 1;
}

// Save to PEM file
certificate.value.save("self_signed.pem");
```

**Key Points:**
- `set_basic_constraints(false, std::nullopt)` - Not a CA certificate
- `set_key_usage(DigitalSignature)` - Allow signing operations
- `build_ed25519(keys, true)` - `true` means self-signed

See `examples/cert_generate_self_signed.cpp` for complete example.

### 2. Certificate Authority (CA) Certificate

Create a CA that can issue other certificates:

```cpp
// Generate dedicated CA keypair
auto ca_keys = keylock::cert::generate_ed25519_keypair();

CertificateBuilder builder;
auto now = std::chrono::system_clock::now();

builder.set_subject_from_string("CN=My CA,O=Example Corp,C=US")
       .set_issuer_from_string("CN=My CA,O=Example Corp,C=US")  // Self-signed
       .set_subject_public_key_ed25519(ca_keys.public_key)
       .set_validity(now, now + std::chrono::hours(24 * 365 * 5))  // 5 years
       .set_basic_constraints(true, 0, true)  // CA=true, pathLen=0
       .set_key_usage(keylock::cert::KeyUsageExtension::KeyCertSign |
                      keylock::cert::KeyUsageExtension::CRLSign);

auto ca_cert = builder.build_ed25519(ca_keys, /*self_signed=*/true);
ca_cert.value.save("ca_certificate.pem");
```

**Key Points:**
- `set_basic_constraints(true, 0, true)` - This is a CA with path length 0
- `KeyCertSign | CRLSign` - CA can sign certificates and CRLs
- Long validity period (5 years) for CA certificates

See `examples/cert_generate_ca.cpp` for complete example.

### 3. End-Entity Certificate Issued by CA

Issue a certificate signed by your CA:

```cpp
// Generate end-entity keypair
auto ee_keys = keylock::cert::generate_ed25519_keypair();

// Load CA certificate and key
auto ca_cert = keylock::cert::load_from_file("ca_certificate.pem");
auto ca_keys = load_ca_keypair();  // Your function to load CA keys

CertificateBuilder builder;
auto now = std::chrono::system_clock::now();

builder.set_subject_from_string("CN=server.example.com,O=Example Corp,C=US")
       .set_issuer(ca_cert.value.subject())
       .set_subject_public_key_ed25519(ee_keys.public_key)
       .set_validity(now, now + std::chrono::hours(24 * 365))  // 1 year
       .set_basic_constraints(false, std::nullopt)
       .set_key_usage(keylock::cert::KeyUsageExtension::DigitalSignature |
                      keylock::cert::KeyUsageExtension::KeyEncipherment)
       .set_extended_key_usage({keylock::cert::oid::ServerAuth,
                                keylock::cert::oid::ClientAuth})
       .set_subject_alt_name({{keylock::cert::GeneralNameType::DNSName, "server.example.com"},
                              {keylock::cert::GeneralNameType::DNSName, "*.example.com"}});

// Sign with CA key
auto cert = builder.build_ed25519(ca_keys, /*self_signed=*/false);
```

**Key Points:**
- `set_issuer()` - Points to CA's subject DN
- `set_subject_alt_name()` - Critical for HTTPS/TLS
- `ServerAuth` - For TLS server authentication

### 4. Certificate Signing Requests (CSR)

Generate a CSR and have it signed by a CA:

```cpp
#include <keylock/cert/csr_builder.hpp>
#include <keylock/cert/csr.hpp>

// Generate CSR (client side)
keylock::cert::CsrBuilder csr_builder;
auto keys = keylock::cert::generate_ed25519_keypair();

csr_builder.set_subject_from_string("CN=user.example.com,O=Example Corp,C=US")
           .set_subject_public_key_ed25519(keys.public_key)
           .set_attribute({keylock::cert::AttributeType::ChallengePassword,
                           "my-secret-password"});

auto csr_result = csr_builder.build_ed25519(keys);
if (!csr_result.success) {
    std::cerr << "Failed: " << csr_result.error << "\n";
    return 1;
}

// Save CSR
csr_result.value.save("request.csr");

// Load and sign CSR (CA side)
auto csr = keylock::cert::load_csr("request.csr");
if (!csr.success) {
    std::cerr << "Failed to load CSR\n";
    return 1;
}

// Build certificate from CSR data
keylock::cert::CertificateBuilder cert_builder;
cert_builder.set_subject(csr.value.info().subject)
             .set_subject_public_key_ed25519(csr.value.info().subject_public_key_info)
             .set_issuer(ca_cert.value.subject())
             .set_validity(now, now + std::chrono::hours(24 * 365))
             .set_basic_constraints(false, std::nullopt);

auto cert = cert_builder.build_ed25519(ca_keys, /*self_signed=*/false);
```

**Key Points:**
- CSR contains subject DN and public key info
- CA extracts info from CSR and builds certificate
- CSR can include attributes like challenge password

See `examples/csr_generate.cpp` and `examples/cert_sign_csr.cpp` for complete examples.

## Validating Certificates

### Basic Chain Validation

Validate a certificate chain against a trust store:

```cpp
#include <keylock/cert/trust_store.hpp>

// Load certificates
auto leaf_cert = keylock::cert::load_from_file("leaf.pem");
auto intermediate_cert = keylock::cert::load_from_file("intermediate.pem");

// Load trust store (system CAs)
auto trust_store = keylock::cert::TrustStore::load_from_system();
if (!trust_store.success) {
    std::cerr << "Failed to load trust store\n";
    return 1;
}

// Build chain: leaf -> intermediate -> (anchor in trust store)
std::vector<keylock::cert::Certificate> chain = {
    leaf_cert.value,
    intermediate_cert.value
};

// Validate
auto validation = leaf_cert.value.validate_chain(chain, trust_store.value);
if (!validation.success) {
    std::cerr << "Validation failed: " << validation.error << "\n";
    return 1;
}

std::cout << "Certificate chain is valid!\n";
```

**Key Points:**
- Chain ordered from leaf to parent
- Anchor certificate must be in trust store
- Validation checks: signatures, validity, CA flag, path length

### Hostname Verification

Verify that a certificate matches an expected hostname:

```cpp
auto cert = keylock::cert::load_from_file("server.pem");

// Check hostname
std::string expected_hostname = "server.example.com";

if (!cert.value.match_hostname(expected_hostname)) {
    std::cerr << "Certificate does not match hostname!\n";
    return 1;
}

// Check IP address (if present)
if (!cert.value.match_hostname("192.168.1.100")) {
    std::cerr << "Certificate does not match IP address!\n";
    return 1;
}
```

**Key Points:**
- Checks Subject Alt Names (DNS and IP)
- Falls back to Common Name (deprecated but supported)
- Supports wildcard certificates (`*.example.com`)
- RFC 6125 compliant

### Custom Validation Checks

Implement custom validation logic:

```cpp
auto cert = keylock::cert::load_from_file("server.pem");

// Check if it's a CA certificate
if (cert.value.basic_constraints_ca().value_or(false)) {
    std::cerr << "Expected end-entity certificate, not CA!\n";
    return 1;
}

// Check key usage
auto key_usage = cert.value.key_usage_bits();
if (!key_usage) {
    std::cerr << "Key Usage extension missing!\n";
    return 1;
}

if (!(*key_usage & keylock::cert::KeyUsageExtension::DigitalSignature)) {
    std::cerr << "Certificate cannot be used for signing!\n";
    return 1;
}

// Check extended key usage for TLS
auto eku = cert.value.extended_key_usage();
if (eku) {
    bool server_auth = std::find(eku->begin(), eku->end(),
                                 keylock::cert::oid::ServerAuth) != eku->end();
    if (!server_auth) {
        std::cerr << "Certificate not authorized for TLS server!\n";
        return 1;
    }
}

// Check validity period
auto now = std::chrono::system_clock::now();
if (cert.value.not_valid_before() > now) {
    std::cerr << "Certificate not yet valid!\n";
    return 1;
}
if (cert.value.not_valid_after() < now) {
    std::cerr << "Certificate expired!\n";
    return 1;
}
```

See `examples/cert_verify_chain.cpp` for complete example.

## Managing Trust Stores

### Load from System

Load operating system's trusted CA certificates:

```cpp
// Auto-detect and load system CA bundle
auto trust = keylock::cert::TrustStore::load_from_system();
if (!trust.success) {
    std::cerr << "Failed to load system trust store: " << trust.error << "\n";
    return 1;
}

std::cout << "Loaded " << trust.value.size() << " trusted certificates\n";

// Find issuer for a certificate
auto cert = keylock::cert::load_from_file("leaf.pem");
auto issuer = trust.value.find_issuer(cert.value);
if (issuer) {
    std::cout << "Found issuer: " << issuer->subject().to_string() << "\n";
}
```

**Supported Platforms:**
- Debian/Ubuntu: `/etc/ssl/certs/ca-certificates.crt`
- RHEL/CentOS: `/etc/pki/tls/certs/ca-bundle.crt`
- FreeBSD: `/etc/ssl/cert.pem`
- Environment: `SSL_CERT_FILE`, `SSL_CERT_DIR`

### Load from File

Load custom CA bundle:

```cpp
// Load from PEM file
auto trust = keylock::cert::TrustStore::load_from_file("/custom/ca-bundle.crt");
if (!trust.success) {
    std::cerr << "Failed: " << trust.error << "\n";
    return 1;
}

// Load from DER file
auto trust_der = keylock::cert::TrustStore::load_from_der("/custom/bundle.der");
```

### Build Custom Trust Store

Create a trust store from specific certificates:

```cpp
keylock::cert::TrustStore trust;

// Add individual certificates
auto ca1 = keylock::cert::load_from_file("ca1.pem");
auto ca2 = keylock::cert::load_from_file("ca2.pem");

trust.add(ca1.value);
trust.add(ca2.value);

std::cout << "Trust store size: " << trust.size() << "\n";

// Remove by subject
trust.remove_by_subject(ca1.value.subject());

// Check if certificate is in trust store
bool is_trusted = trust.find_issuer(some_cert).has_value();
```

See `examples/trust_store_usage.cpp` for complete example.

## Certificate Revocation Lists (CRL)

### Create CRL

Generate a Certificate Revocation List:

```cpp
#include <keylock/cert/crl_builder.hpp>

// Load CA certificate and key
auto ca_cert = keylock::cert::load_from_file("ca.pem");
auto ca_keys = load_ca_keypair();

// Build CRL
keylock::cert::CrlBuilder builder;
auto now = std::chrono::system_clock::now();

builder.set_issuer(ca_cert.value.subject())
       .set_this_update(now)
       .set_next_update(now + std::chrono::hours(24 * 7))  // 7 days
       .add_revoked_certificate(serial_number1, "Key compromise",
                                now - std::chrono::hours(24))
       .add_revoked_certificate(serial_number2, "CA compromise",
                                now - std::chrono::hours(48));

auto crl = builder.build_ed25519(ca_keys);
crl.value.save("revocation_list.crl");
```

### Parse CRL

Load and parse a CRL:

```cpp
auto crl = keylock::cert::load_crl("revocation_list.crl");
if (!crl.success) {
    std::cerr << "Failed to load CRL\n";
    return 1;
}

// Check if certificate is revoked
auto cert_serial = cert.value.serial_number();
auto revoked = crl.value.find_revoked(cert_serial);

if (revoked) {
    std::cout << "Certificate revoked!\n";
    std::cout << "Reason: " << revoked->reason << "\n";
    std::cout << "Date: " << revoked->revocation_date << "\n";
}
```

## Enterprise PKI Extensions

### Name Constraints

Restrict which names a CA can issue certificates for:

```cpp
// Build CA with name constraints
builder.set_name_constraints(
    {
        {keylock::cert::GeneralNameType::DNSName, ".example.com"},
        {keylock::cert::GeneralNameType::DNSName, ".internal.example.com"}
    },
    {
        {keylock::cert::GeneralNameType::DNSName, "forbidden.example.com"}
    }
);
```

### Policy Constraints

Require explicit policy in issued certificates:

```cpp
builder.set_policy_constraints(
    2,  // Require explicit policy (depth)
    std::nullopt  // No inhibit policy mapping
);
```

### Inhibit Any Policy

Prevent acceptance of "anyPolicy":

```cpp
builder.set_inhibit_any_policy(3);  // Depth 3
```

See `examples/enterprise.cpp` for complete enterprise PKI examples.

## Security Best Practices

### Key Management

- **Never hardcode keys** - Always load from secure storage
- **Use secure file permissions** - `chmod 0600 private.key`
- **Implement key rotation** - Rotate CA keys periodically
- **Separate key pairs** - Use different keys for signing and encryption

### Certificate Lifecycle

- **Short validity periods** - 90-365 days for end-entity certificates
- **Path length constraints** - Always set on intermediate CAs
- **Revocation checking** - Implement CRL or LVP verification
- **Monitor expiration** - Alert before certificates expire

### Validation

- **Always validate chains** - Don't trust single certificates
- **Check hostname** - Verify certificate matches expected hostname
- **Verify key usage** - Ensure certificate can be used for intended purpose
- **Check revocation status** - Verify against CRL or verification service

### Storage

- **Restrict file permissions** - `0600` for private keys, `0644` for certs
- **Encrypt at rest** - Use encrypted storage for CA keys
- **Secure deletion** - Securely delete old keys and certificates
- **Backup strategy** - Securely backup CA keys in multiple locations

## Additional Resources

- **Examples directory**: `examples/` - All code examples
- **Test directory**: `test/` - Comprehensive test coverage
- **RFC 5280**: X.509 certificate and CRL profile
- **RFC 5280**: Internet X.509 PKI Certificate and CRL Profile
- **RFC 6125**: Representation and Verification of Domain-Based Application Service Identity
