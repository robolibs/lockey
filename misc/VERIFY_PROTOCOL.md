# keylock Verification Protocol (LVP)

## Overview

The keylock Verification Protocol (LVP) is a modern certificate revocation checking system with a custom binary wire format. It provides an efficient, secure alternative to OCSP for Ed25519 certificates. The protocol is transport-agnostic—it can work in-process, over TCP, Unix sockets, shared memory, or any custom transport layer.

## Design Goals

- **Transport-Agnostic**: Works in-process or over any transport mechanism
- **Efficient**: Custom binary protocol optimized for Ed25519 certificates
- **Secure**: Ed25519 signatures, nonce-based replay protection
- **Minimal**: No networking dependencies in the core library

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                      LVP Protocol Flow                            │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   ┌─────────────┐                 ┌──────────────────┐          │
│   │   Client    │                 │ RequestProcessor │          │
│   │  (keylock)  │   Transport     │    (keylock)     │          │
│   │             │◄───────────────►│                  │          │
│   │ Wire Format │  Binary Protocol │   Wire Format   │          │
│   └─────────────┘                 └──────────────────┘          │
│         │                                │                      │
│         │ 1. Verify Request             │                      │
│         │   (Chain + Nonce)              │                      │
│         │──────────────────────────────►│                      │
│         │                                │                      │
│         │                        2. Check Revocation           │
│         │                        (CRL / DB / LDAP)            │
│         │                                │                      │
│         │◄───────────────────────────────│ 3. Verify Response    │
│         │   (Status + Signature + Nonce)  │   (Signed by Ed25519) │
│         │                                │                      │
│         │ 4. Verify Signature            │                      │
│         │    & Nonce Match               │                      │
└─────────────────────────────────────────────────────────────────┘
```

**Component Overview:**
```
┌─────────────────────────────────────────────────────────────┐
│                    LVP Client API                            │
│  - Certificate chain validation                            │
│  - Signature verification                                   │
│  - Replay attack prevention                                 │
│  - Batch verification support                              │
└─────────────────────────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│                   Transport Interface                        │
│  - DirectTransport (in-process, no networking)              │
│  - Custom transports (TCP, Unix sockets, shared memory)    │
└─────────────────────────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│                  RequestProcessor API                        │
│  - Wire format request handling                             │
│  - Revocation checking                                      │
│  - Response signing (Ed25519)                                │
│  - Health monitoring                                         │
└─────────────────────────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│              Verification Handler Interface                  │
│  - SimpleRevocationHandler (in-memory)                     │
│  - Custom handlers (DB, CRL, LDAP, etc.)                  │
└─────────────────────────────────────────────────────────────┘
```

## Wire Format Specification

### Protocol Header

All messages start with a common header for protocol identification:

```
Offset | Size | Description
-------|------|------------------------------------------------
0      | 4    | Magic bytes: 'L', 'K', 'E', 'Y'
4      | 1    | Protocol version: 0x01
5      | 1    | Message type (see below)
```

**Total header size: 6 bytes**

### Message Types

```cpp
enum class MessageType : uint8_t {
    VERIFY_REQUEST  = 0x01,  // Single certificate chain verification
    VERIFY_RESPONSE = 0x02,  // Response to verify request
    BATCH_REQUEST   = 0x03,  // Multiple certificate verifications
    BATCH_RESPONSE  = 0x04,  // Response to batch request
    HEALTH_CHECK    = 0x05,  // Server health check request
    HEALTH_RESPONSE = 0x06   // Health check response
};
```

### Verify Request

Single certificate chain verification request.

**Wire Format:**
```
Offset | Size | Description
-------|------|------------------------------------------------
0      | 6    | Header (magic, version, type)
6      | 2    | Chain count (uint16, big-endian)
8      | Var  | Certificates (repeated for each):
       |      |   - 4 bytes: DER size (uint32, big-endian)
       |      |   - N bytes: DER-encoded certificate
8+X    | 8    | Validation timestamp (Unix seconds, uint64, BE)
16+X   | 1    | Flags (RequestFlags bitmask)
17+X   | 4    | Nonce size (uint32, always 32)
21+X   | 32   | Random nonce for replay protection
```

**Total size:** ~53 + N bytes per certificate

**Request Flags:**
```cpp
enum class RequestFlags : uint8_t {
    NONE                   = 0x00,  // No special flags
    INCLUDE_RESPONDER_CERT = 0x01   // Include responder cert in response
};
```

### Verify Response

Response for single certificate verification.

**Wire Format:**
```
Offset | Size | Description
-------|------|------------------------------------------------
0      | 6    | Header (magic, version, type)
6      | 1    | Status (VerifyStatus)
7      | 2    | Reason string length (uint16, big-endian)
9      | N    | Reason string (UTF-8)
9+N    | 8    | Revocation time (Unix seconds, uint64, BE)
17+N   | 8    | This update time (Unix seconds, uint64, BE)
25+N   | 8    | Next update time (Unix seconds, uint64, BE)
33+N   | 4    | Signature size (uint32, always 64 for Ed25519)
37+N   | 64   | Ed25519 signature
101+N  | 4    | Nonce size (uint32, always 32)
105+N  | 32   | Echo of request nonce
137+N  | 4    | Responder cert size (uint32, 0 if not included)
141+N  | N    | Responder certificate DER (optional)
```

**Total size:** ~137 + N bytes (without responder cert)

**Verify Status:**
```cpp
enum class VerifyStatus : uint8_t {
    GOOD    = 0x00,  // Certificate is valid and not revoked
    REVOKED = 0x01,  // Certificate is revoked
    UNKNOWN = 0x02   // Certificate status unknown to server
};
```

**Revocation Reasons (UTF-8 strings):**
- `"Key compromise"` - Private key was compromised
- `"CA compromise"` - CA private key was compromised
- `"Affiliation changed"` - Subject name changed
- `"Superseded"` - Certificate replaced by new one
- `"Cessation of operation"` - Entity stopped operating
- `"Certificate hold"` - Temporary revocation
- `"Remove from CRL"` - Certificate no longer revoked

### Batch Request

Multiple certificate chain verifications in a single request.

**Wire Format:**
```
Offset | Size | Description
-------|------|------------------------------------------------
0      | 6    | Header (magic, version, type)
6      | 2    | Request count (uint16, big-endian)
8      | Var  | Individual requests (without headers, repeated)
```

Each individual request has the same format as Verify Request (minus header).

### Batch Response

**Wire Format:**
```
Offset | Size | Description
-------|------|------------------------------------------------
0      | 6    | Header (magic, version, type)
6      | 2    | Response count (uint16, big-endian)
8      | Var  | Individual responses (without headers, repeated)
```

Each individual response has the same format as Verify Response (minus header).

### Health Check

Simple health check for monitoring systems.

**Request:**
```
Offset | Size | Description
-------|------|------------------------------------------------
0      | 6    | Header (magic, version, type)
       |      | No payload
```

**Response:**
```
Offset | Size | Description
-------|------|------------------------------------------------
0      | 6    | Header (magic, version, type)
6      | 1    | Serving status
```

**Serving Status:**
```cpp
enum class ServingStatus : uint8_t {
    UNKNOWN     = 0x00,  // Status unknown (should not happen)
    SERVING     = 0x01,  // Server is accepting requests
    NOT_SERVING = 0x02   // Server is not accepting requests
};
```

## Method IDs

The protocol uses method IDs to identify request types:

```cpp
namespace keylock::verify::methods {
    constexpr uint32_t CHECK_CERTIFICATE = 1;  // Single certificate verification
    constexpr uint32_t CHECK_BATCH = 2;        // Batch verification
    constexpr uint32_t HEALTH_CHECK = 3;       // Health check
}
```

Each method receives the wire-format message as payload and returns a wire-format response. The `Transport` interface abstracts the actual communication mechanism.

## Security Considerations

### Replay Protection

Every request includes a 32-byte random nonce generated using libsodium's cryptographically secure RNG. The server echoes this nonce in the response. Clients MUST verify that the response nonce matches the request nonce to prevent replay attacks.

```cpp
#include <sodium.h>

// Generate nonce (client side)
std::vector<uint8_t> nonce(32);
randombytes_buf(nonce.data(), nonce.size());

// ... send request ...

// Verify nonce in response
if (response.nonce != request.nonce) {
    // Possible replay attack!
    log_error("Nonce mismatch in verification response");
    return VerificationError::ReplayAttack;
}
```

**Why 32 bytes?**
- Provides 256 bits of entropy
- Extremely unlikely to collide even with billions of requests
- Matches Ed25519 signature size for consistency

### Response Signing

All responses are signed with the server's Ed25519 private key. Clients SHOULD verify the signature using the server's public key (provided via responder certificate).

**Signature Input (concatenated bytes):**
```
status (1 byte) ||
reason (UTF-8 string) ||
revocation_time (8 bytes, big-endian) ||
this_update (8 bytes, big-endian) ||
next_update (8 bytes, big-endian) ||
nonce (32 bytes)
```

**Verification:**
```cpp
#include <keylock/verify/direct_transport.hpp>

// Simple in-process verification using Verifier
keylock::verify::Verifier verifier;

// Load and set responder certificate for signature verification
auto responder_cert = keylock::cert::load_from_file("responder.pem");
verifier.set_responder_certificate(responder_cert.value);

// Verify certificate chain
auto result = verifier.verify_chain(cert_chain);
// Signature is automatically verified if responder cert is set
if (!result.success) {
    // Signature verification failed
    std::cerr << "Verification failed: " << result.error << "\n";
}
```

**Signature Properties:**
- **Algorithm**: Ed25519 (twisted Edwards curve)
- **Key size**: 32 bytes private, 32 bytes public
- **Signature size**: 64 bytes
- **Security level**: 128-bit security (equivalent to 3072-bit RSA)

### Transport Security

The LVP protocol is transport-agnostic. For in-process verification using `DirectTransport`, no network security is needed. For remote verification with custom transports, consider:

1. **In-process**: Use `DirectTransport` or `Verifier` class—no network exposure
2. **TLS termination proxy**: Run custom transport server behind nginx, HAProxy, or similar
3. **VPN or encrypted tunnel**: Use WireGuard, OpenVPN, or SSH tunneling
4. **Private network**: Deploy on a trusted isolated network segment
5. **Mutual authentication**: Add application-layer authentication if needed

The protocol-level Ed25519 signatures ensure response authenticity regardless of transport encryption, but transport encryption provides additional protection against:

- Eavesdropping on certificate chains (privacy concern)
- Man-in-the-middle attacks on the protocol itself
- Traffic analysis (timing and size)

**Recommended setup for in-process verification:**
```
Application → Verifier → RequestProcessor → VerificationHandler
                 (no network overhead)
```

**Recommended setup for remote verification:**
```
Application → Client → CustomTransport → RequestProcessor → Handler
```

### Server Key Management

**Key Rotation:**
- Rotate server signing keys periodically (e.g., every 90 days)
- Maintain key history for signature verification of old responses
- Announce key rotation in advance to clients

**Key Storage:**
- Store private keys in hardware security modules (HSM) if available
- Use encrypted storage with strong access controls
- Never expose private keys in logs or error messages

## Usage Examples

### Basic Verification (In-Process)

Verify a single certificate chain using the `Verifier` class:

```cpp
#include <keylock/verify/direct_transport.hpp>
#include <keylock/cert/certificate.hpp>

int main() {
    // Load certificate chain
    auto leaf_cert = keylock::cert::load_from_file("leaf.pem");
    auto intermediate = keylock::cert::load_from_file("intermediate.pem");

    std::vector<keylock::cert::Certificate> chain = {
        leaf_cert.value,
        intermediate.value
    };

    // Create verifier (in-process, no networking)
    keylock::verify::Verifier verifier;

    // Optional: Add revoked certificates
    verifier.as_revocation_handler()->add_revoked_certificate(
        {0x01, 0x02, 0x03}, "Key compromise");

    // Verify certificate chain
    auto result = verifier.verify_chain(chain);

    if (!result.success) {
        std::cerr << "Verification failed: " << result.error << "\n";
        return 1;
    }

    auto& response = result.value;

    switch (response.status) {
        case keylock::verify::wire::VerifyStatus::GOOD:
            std::cout << "Certificate is valid and not revoked\n";
            break;

        case keylock::verify::wire::VerifyStatus::REVOKED:
            std::cout << "Certificate is revoked!\n";
            std::cout << "Reason: " << response.reason << "\n";
            break;

        case keylock::verify::wire::VerifyStatus::UNKNOWN:
            std::cout << "Certificate status unknown\n";
            break;
    }

    return 0;
}
```

### Batch Verification

Verify multiple certificate chains efficiently:

```cpp
#include <keylock/verify/direct_transport.hpp>

int main() {
    keylock::verify::Verifier verifier;

    // Prepare multiple certificate chains
    std::vector<std::vector<keylock::cert::Certificate>> chains;

    // Add chain 1
    auto chain1 = load_chain("chain1/");
    chains.push_back(chain1);

    // Add chain 2
    auto chain2 = load_chain("chain2/");
    chains.push_back(chain2);

    // Verify all chains in a single request
    auto result = verifier.verify_batch(chains);

    if (!result.success) {
        std::cerr << "Batch verification failed: " << result.error << "\n";
        return 1;
    }

    // Process results
    for (size_t i = 0; i < result.value.size(); ++i) {
        const auto& resp = result.value[i];

        std::cout << "Chain " << i << ": ";
        switch (resp.status) {
            case keylock::verify::wire::VerifyStatus::GOOD:
                std::cout << "Valid\n";
                break;
            case keylock::verify::wire::VerifyStatus::REVOKED:
                std::cout << "Revoked - " << resp.reason << "\n";
                break;
            case keylock::verify::wire::VerifyStatus::UNKNOWN:
                std::cout << "Unknown status\n";
                break;
        }
    }

    return 0;
}
```

### Health Check

Check verification service health:

```cpp
#include <keylock/verify/direct_transport.hpp>

int main() {
    keylock::verify::Verifier verifier;

    auto health = verifier.health_check();

    if (!health.success) {
        std::cerr << "Health check failed: " << health.error << "\n";
        return 1;
    }

    if (health.value) {
        std::cout << "Verification service is healthy\n";
    } else {
        std::cout << "Verification service is not healthy\n";
    }

    return 0;
}
```

## Performance Characteristics

### Latency

Target performance on modern hardware (typical values):

| Operation | p50 latency | p95 latency | p99 latency |
|-----------|-------------|-------------|-------------|
| Single verification | ~20 ms | ~40 ms | ~60 ms |
| Batch verification (10 certs) | ~30 ms | ~50 ms | ~80 ms |
| Health check | ~5 ms | ~10 ms | ~15 ms |

**Factors affecting latency:**
- Network round-trip time
- Server load and thread pool size
- Database query time (if using custom handler)
- Certificate chain size

### Throughput

| Configuration | Requests/sec | Certificates/sec |
|---------------|--------------|------------------|
| Single verification | ~50 | 50 |
| Batch (10 certs) | ~40 | 400 |
| Batch (100 certs) | ~10 | 1000 |

**Optimization tips:**
- Use batch verification for multiple certificates
- Configure appropriate thread pool size (default: 4)
- Use in-memory revocation list for best performance
- Cache server responses with short TTLs

### Message Sizes

Typical message sizes for Ed25519 certificates:

| Message Type | Size |
|--------------|------|
| Verify Request (1 cert) | ~1 KB |
| Verify Request (3 certs) | ~3 KB |
| Verify Response | ~150 bytes |
| Batch Request (10 certs) | ~10 KB |
| Batch Response (10 certs) | ~1.5 KB |
| Health Check Request | 6 bytes |
| Health Check Response | 7 bytes |

### Comparison with OCSP

| Feature | LVP | OCSP |
|---------|-----|------|
| Wire format | Custom binary | ASN.1/DER |
| Signing | Ed25519 | RSA/ECDSA |
| Hashing | SHA-256 | SHA-1 (legacy) |
| Signature size | 64 bytes | 256-512 bytes (RSA), 64-71 bytes (ECDSA) |
| Transport | Transport-agnostic | HTTP/1.1 |
| Batch support | Native | Optional extension |
| Dependencies | libsodium, datapod | OpenSSL |
| Message size | ~150 bytes response | ~300-500 bytes response |
| Latency | ~20-40 ms | ~30-60 ms (includes HTTP overhead) |

**Key advantages of LVP:**
- Simpler wire format (no ASN.1 parsing overhead)
- Smaller message sizes
- Faster signing/verification (Ed25519 vs RSA)
- Native batch support
- Lower dependencies

## RequestProcessor Implementation

The verification logic is handled by `RequestProcessor`, which processes wire-format requests and returns wire-format responses. This design allows you to build custom transport layers on top.

### Basic RequestProcessor Setup

```cpp
#include <keylock/verify/server.hpp>

int main() {
    // Create a verification handler with in-memory revocation list
    auto handler = std::make_shared<keylock::verify::SimpleRevocationHandler>();

    // Add revoked certificates
    handler->add_revoked_certificate(
        {0x01, 0x02, 0x03, 0x04, 0x05},  // Serial number
        "Key compromise",                 // Reason
        std::chrono::system_clock::now() // Revocation time
    );

    // Add more revoked certificates...
    handler->add_revoked_certificate(
        {0xDE, 0xAD, 0xBE, 0xEF},
        "Superseded",
        std::chrono::system_clock::now()
    );

    // Create request processor
    keylock::verify::RequestProcessor processor(handler);

    // Set Ed25519 signing key for response signatures
    std::vector<uint8_t> sk(crypto_sign_SECRETKEYBYTES);
    std::vector<uint8_t> pk(crypto_sign_PUBLICKEYBYTES);
    crypto_sign_keypair(pk.data(), sk.data());
    processor.set_signing_key(sk);

    // Optional: Set responder certificate
    auto responder_cert = keylock::cert::load_from_file("responder.pem");
    processor.set_responder_certificate(responder_cert.value);

    // Process requests (wire format in, wire format out)
    std::vector<uint8_t> request_data = /* receive from your transport */;
    auto response_data = processor.process(keylock::verify::methods::CHECK_CERTIFICATE, request_data);
    // Send response_data via your transport

    return 0;
}
```

### Using the Verifier Convenience Class

For simple in-process verification, use the `Verifier` class which combines all components:

```cpp
#include <keylock/verify/direct_transport.hpp>

int main() {
    // Create verifier with default SimpleRevocationHandler
    keylock::verify::Verifier verifier;

    // Add revoked certificates
    verifier.as_revocation_handler()->add_revoked_certificate(
        {0x01, 0x02, 0x03, 0x04, 0x05},
        "Key compromise",
        std::chrono::system_clock::now()
    );

    // Optional: Set signing key for signed responses
    std::vector<uint8_t> pk(crypto_sign_PUBLICKEYBYTES);
    std::vector<uint8_t> sk(crypto_sign_SECRETKEYBYTES);
    crypto_sign_keypair(pk.data(), sk.data());
    verifier.set_signing_key(sk);

    // Verify certificates directly
    std::vector<keylock::cert::Certificate> chain = load_chain("certs/");
    auto result = verifier.verify_chain(chain);

    if (result.success && result.value.status == keylock::verify::wire::VerifyStatus::GOOD) {
        std::cout << "Certificate is valid!\n";
    }

    return 0;
}
```

### Custom Verification Handlers

Implement your own verification logic by inheriting from `VerificationHandler`:

```cpp
#include <keylock/verify/server.hpp>
#include <keylock/verify/wire_format.hpp>
#include <pqxx/pqxx>  // PostgreSQL client library

class DatabaseRevocationHandler : public keylock::verify::VerificationHandler {
public:
    DatabaseRevocationHandler(const std::string& conn_string)
        : conn_(conn_string) {}

    keylock::verify::wire::VerifyResponse verify_chain(
        const std::vector<keylock::cert::Certificate>& chain,
        std::chrono::system_clock::time_point validation_time) override {

        keylock::verify::wire::VerifyResponse response;
        response.this_update = std::chrono::system_clock::now();
        response.next_update = response.this_update + std::chrono::hours(1);

        if (chain.empty()) {
            response.status = keylock::verify::wire::VerifyStatus::UNKNOWN;
            response.reason = "Empty certificate chain";
            return response;
        }

        // Get serial number from leaf certificate
        auto serial = chain[0].tbs().serial_number;

        try {
            pqxx::work txn(conn_);

            // Query database for revocation status
            pqxx::result r = txn.exec_params(
                "SELECT status, reason, revoked_at FROM revoked_certs WHERE serial_number = $1",
                pqxx::binarystring(serial)
            );

            if (r.empty()) {
                // Certificate not found in revocation table
                response.status = keylock::verify::wire::VerifyStatus::GOOD;
                response.reason = "Certificate not in revocation list";
            } else {
                // Certificate is revoked
                response.status = keylock::verify::wire::VerifyStatus::REVOKED;
                response.reason = r[0]["reason"].as<std::string>();

                // Parse revocation time
                std::string revoked_str = r[0]["revoked_at"].as<std::string>();
                response.revocation_time = parse_timestamp(revoked_str);
            }

            txn.commit();

        } catch (const std::exception& e) {
            // Database error
            response.status = keylock::verify::wire::VerifyStatus::UNKNOWN;
            response.reason = std::string("Database error: ") + e.what();
        }

        return response;
    }

    bool is_healthy() const override {
        try {
            pqxx::work txn(conn_);
            txn.exec("SELECT 1");
            txn.commit();
            return true;
        } catch (...) {
            return false;
        }
    }

private:
    mutable pqxx::connection conn_;

    std::chrono::system_clock::time_point parse_timestamp(const std::string& ts) {
        // Parse timestamp string (implement as needed)
        // ...
    }
};

int main() {
    // Create custom handler
    auto handler = std::make_shared<DatabaseRevocationHandler>(
        "dbname=revocation user=revoker password=secret"
    );

    // Create verifier with custom handler
    keylock::verify::Verifier verifier(handler);

    // Or use RequestProcessor directly for custom transports
    keylock::verify::RequestProcessor processor(handler);

    // Generate and set signing key
    std::vector<uint8_t> pk(crypto_sign_PUBLICKEYBYTES);
    std::vector<uint8_t> sk(crypto_sign_SECRETKEYBYTES);
    crypto_sign_keypair(pk.data(), sk.data());
    processor.set_signing_key(sk);

    // Process requests from your custom transport
    // processor.process(method_id, request_data);

    return 0;
}
```

**Key Handler Features:**
- **In-memory revocation list** (`SimpleRevocationHandler`) - Fast, ephemeral storage
- **Custom handler interface** - Connect to any backend (DB, CRL, LDAP, etc.)
- **Health monitoring** - `is_healthy()` for health checks
- **Thread safety** - Handlers must be thread-safe if using from multiple threads

## Protocol Versioning

Current version: **0x01**

### Version Negotiation

Clients should check the version byte in all responses:

```cpp
if (response.version != PROTOCOL_VERSION_0x01) {
    log_error("Unsupported protocol version: 0x%02x", response.version);
    return VerificationError::UnsupportedVersion;
}
```

### Backward Compatibility

Future versions will maintain backward compatibility or increment the version byte. Breaking changes will:
1. Increment the protocol version byte
2. Be announced in advance
3. Support a deprecation period

Potential future additions:
- Additional request/response flags
- New message types
- Extended status codes
- Additional signature algorithms

## Error Handling

### Result Types

All verification operations return result types with `{success, value, error}` fields:

### Client Error Handling

```cpp
#include <keylock/verify/direct_transport.hpp>

keylock::verify::Verifier verifier;
auto result = verifier.verify_chain(chain);

if (!result.success) {
    // Verification request failed
    std::cerr << "Error: " << result.error << "\n";
    return 1;
} else {
    // Check certificate status
    auto& response = result.value;

    switch (response.status) {
        case keylock::verify::wire::VerifyStatus::GOOD:
            // Certificate is valid
            break;

        case keylock::verify::wire::VerifyStatus::REVOKED:
            // Certificate is revoked
            std::cout << "Revoked: " << response.reason << "\n";
            break;

        case keylock::verify::wire::VerifyStatus::UNKNOWN:
            // Certificate status unknown
            // Could be valid or not in revocation database
            break;
    }
}
```

### Handler Error Handling

Custom handlers should handle errors gracefully:

```cpp
class MyHandler : public keylock::verify::VerificationHandler {
public:
    keylock::verify::wire::VerifyResponse verify_chain(
        const std::vector<keylock::cert::Certificate>& chain,
        std::chrono::system_clock::time_point validation_time) override {

        try {
            // Your verification logic
            // ...

        } catch (const std::exception& e) {
            // Return UNKNOWN status on errors
            keylock::verify::wire::VerifyResponse response;
            response.status = keylock::verify::wire::VerifyStatus::UNKNOWN;
            response.reason = std::string("Handler error: ") + e.what();
            response.this_update = std::chrono::system_clock::now();
            response.next_update = response.this_update + std::chrono::minutes(5);
            return response;
        }
    }
};
```

