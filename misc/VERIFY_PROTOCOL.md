# keylock Verification Protocol (LVP)

## Overview

The keylock Verification Protocol (LVP) is a modern certificate revocation checking system built on netpipe with a custom binary wire format. It provides an efficient, secure alternative to OCSP for Ed25519 certificates.

## Design Goals

- **Modern**: Built on netpipe for lightweight TCP networking
- **Efficient**: Custom binary protocol optimized for Ed25519 certificates
- **Secure**: Ed25519 signatures, nonce-based replay protection
- **Minimal**: No external dependencies beyond netpipe/datapod

## Architecture

```
┌─────────────┐                  ┌─────────────┐
│   Client    │                  │   Server    │
│  (keylock)   │   netpipe/TCP    │  (keylock)   │
│             │◄────────────────►│             │
│ Custom Wire │                  │ Custom Wire │
│   Format    │                  │   Format    │
└─────────────┘                  └─────────────┘
       │                                │
       │                                │
       ▼                                ▼
  Certificate                    VerificationHandler
     Chain                       (SimpleRevocationHandler
                                  or custom implementation)
```

## Wire Format Specification

### Protocol Header

All messages start with a common header:

```
[4 bytes]  Magic bytes: 'L', 'K', 'E', 'Y'
[1 byte]   Protocol version: 0x01
[1 byte]   Message type
```

### Message Types

```cpp
enum class MessageType : uint8_t {
    VERIFY_REQUEST  = 0x01,
    VERIFY_RESPONSE = 0x02,
    BATCH_REQUEST   = 0x03,
    BATCH_RESPONSE  = 0x04,
    HEALTH_CHECK    = 0x05,
    HEALTH_RESPONSE = 0x06
};
```

### Verify Request

Single certificate chain verification request.

**Wire Format:**
```
[Header: 6 bytes]
[2 bytes]  Chain count (uint16, big-endian)
[Variable] Certificates (repeated):
    [4 bytes]  DER size (uint32, big-endian)
    [N bytes]  DER-encoded certificate
[8 bytes]  Validation timestamp (Unix seconds, uint64, big-endian)
[1 byte]   Flags (RequestFlags bitmask)
[4 bytes]  Nonce size (uint32, always 32)
[32 bytes] Random nonce for replay protection
```

**Request Flags:**
```cpp
enum class RequestFlags : uint8_t {
    NONE                   = 0x00,
    INCLUDE_RESPONDER_CERT = 0x01
};
```

### Verify Response

Response for single certificate verification.

**Wire Format:**
```
[Header: 6 bytes]
[1 byte]   Status (VerifyStatus)
[2 bytes]  Reason string length (uint16, big-endian)
[N bytes]  Reason string (UTF-8)
[8 bytes]  Revocation time (Unix seconds, uint64, big-endian)
[8 bytes]  This update time (Unix seconds, uint64, big-endian)
[8 bytes]  Next update time (Unix seconds, uint64, big-endian)
[4 bytes]  Signature size (uint32, always 64 for Ed25519)
[64 bytes] Ed25519 signature
[4 bytes]  Nonce size (uint32, always 32)
[32 bytes] Echo of request nonce
[4 bytes]  Responder cert size (uint32, 0 if not included)
[N bytes]  Responder certificate DER (optional)
```

**Verify Status:**
```cpp
enum class VerifyStatus : uint8_t {
    GOOD    = 0x00,  // Certificate is valid
    REVOKED = 0x01,  // Certificate is revoked
    UNKNOWN = 0x02   // Certificate status unknown
};
```

### Batch Request

Multiple certificate chain verifications in a single request.

**Wire Format:**
```
[Header: 6 bytes]
[2 bytes]  Request count (uint16, big-endian)
[Variable] Individual requests (without headers)
```

### Batch Response

**Wire Format:**
```
[Header: 6 bytes]
[2 bytes]  Response count (uint16, big-endian)
[Variable] Individual responses (without headers)
```

### Health Check

**Request:**
```
[Header: 6 bytes]
(No payload)
```

**Response:**
```
[Header: 6 bytes]
[1 byte]   Serving status
```

**Serving Status:**
```cpp
enum class ServingStatus : uint8_t {
    UNKNOWN     = 0x00,
    SERVING     = 0x01,
    NOT_SERVING = 0x02
};
```

## Netpipe RPC Methods

The protocol uses netpipe's Remote RPC with method IDs:

```cpp
namespace methods {
    constexpr uint32_t CHECK_CERTIFICATE = 1;  // Single certificate verification
    constexpr uint32_t CHECK_BATCH = 2;        // Batch verification
    constexpr uint32_t HEALTH_CHECK = 3;       // Health check
}
```

Each method receives the wire-format message as payload and returns a wire-format response.

## Security Considerations

### Replay Protection

Every request includes a 32-byte random nonce. The server echoes this nonce in the response. Clients MUST verify that the response nonce matches the request nonce.

```cpp
// Generate nonce
std::vector<uint8_t> nonce(32);
randombytes_buf(nonce.data(), nonce.size());

// ... send request ...

// Verify nonce in response
if (response.nonce != request.nonce) {
    // Possible replay attack!
    return error;
}
```

### Response Signing

All responses are signed with the server's Ed25519 private key. Clients SHOULD verify the signature using the server's public key (provided via responder certificate).

**Signature Input:**
```
status (1 byte) ||
reason (UTF-8 string) ||
revocation_time (8 bytes) ||
this_update (8 bytes) ||
next_update (8 bytes) ||
nonce (32 bytes)
```

**Verification:**
```cpp
client.set_responder_cert(server_cert);
auto result = client.verify_chain(chain);
// Signature automatically verified if responder cert is set
```

### Transport Security

The netpipe transport uses plain TCP. For production deployments requiring encryption, consider:

1. Running behind a TLS termination proxy (nginx, HAProxy)
2. Using a VPN or encrypted tunnel
3. Deploying on a trusted private network

The protocol-level Ed25519 signatures ensure response authenticity regardless of transport encryption.

## Usage Examples

### Basic Verification

```cpp
#include <keylock/verify/client.hpp>

// Create client
keylock::verify::ClientConfig config;
config.timeout = std::chrono::seconds(10);
config.max_retry_attempts = 3;

keylock::verify::Client client("192.168.1.100:50051", config);

// Set responder certificate for signature verification
client.set_responder_cert(responder_cert);

// Verify certificate chain
auto result = client.verify_chain(cert_chain);
if (result.success && result.value.status == keylock::verify::wire::VerifyStatus::GOOD) {
    std::cout << "Certificate is valid and not revoked\n";
} else if (result.success && result.value.status == keylock::verify::wire::VerifyStatus::REVOKED) {
    std::cout << "Certificate is revoked: " << result.value.reason << "\n";
} else {
    std::cerr << "Verification failed: " << result.error << "\n";
}
```

### Batch Verification

```cpp
std::vector<std::vector<keylock::cert::Certificate>> chains;
// ... populate chains ...

auto result = client.verify_batch(chains);
if (result.success) {
    for (size_t i = 0; i < result.value.size(); ++i) {
        const auto& resp = result.value[i];
        if (resp.status == keylock::verify::wire::VerifyStatus::GOOD) {
            std::cout << "Chain " << i << ": Valid\n";
        } else {
            std::cout << "Chain " << i << ": Revoked - " << resp.reason << "\n";
        }
    }
}
```

### Health Check

```cpp
auto health = client.health_check();
if (health.success && health.value) {
    std::cout << "Server is healthy\n";
} else {
    std::cerr << "Server is not responding\n";
}
```

## Performance Characteristics

### Latency

- **Single verification**: <50ms p95 (target)
- **Batch verification**: ~5ms per certificate (amortized)
- **Health check**: <10ms

### Message Sizes

Typical message sizes for Ed25519 certificates:

- **Request** (single cert): ~1KB (certificate + metadata)
- **Response**: ~150 bytes (without responder cert)
- **Batch overhead**: Minimal (~6 bytes per additional request)

### Comparison with OCSP

| Feature | LVP | OCSP |
|---------|-----|------|
| Wire format | Custom binary | ASN.1/DER |
| Signing | Ed25519 | RSA/ECDSA |
| Hashing | SHA-256 | SHA-1 (legacy) |
| Transport | netpipe/TCP | HTTP/1.1 |
| Batch support | Native | Extension |
| Dependencies | netpipe, datapod | OpenSSL |

## Build Configuration

### CMake Integration

```cmake
find_package(keylock REQUIRED)
target_link_libraries(your_target keylock::keylock)
```

The verify module is always included and uses the lightweight netpipe transport.

## Server Implementation

The verification server is included in the keylock library. Both C++ client and server APIs are provided.

### Server API

```cpp
#include <keylock/verify/server.hpp>

// Create a verification handler
auto handler = std::make_shared<keylock::verify::SimpleRevocationHandler>();

// Add revoked certificates
handler->add_revoked_certificate(
    {0x01, 0x02, 0x03, 0x04, 0x05},  // Serial number
    "Key compromise",                 // Reason
    std::chrono::system_clock::now() // Revocation time
);

// Configure server
keylock::verify::ServerConfig config;
config.host = "0.0.0.0";
config.port = 50051;
config.max_threads = 4;

// Create and start server
keylock::verify::Server server(handler, config);

// Optional: Set Ed25519 signing key
std::vector<uint8_t> sk(crypto_sign_SECRETKEYBYTES);
std::vector<uint8_t> pk(crypto_sign_PUBLICKEYBYTES);
crypto_sign_keypair(pk.data(), sk.data());
server.set_signing_key(sk);

// Optional: Set responder certificate
server.set_responder_certificate(responder_cert);

// Start server (blocks)
server.start();

// Or start asynchronously
server.start_async();
// ... do other work ...
server.wait();
```

### Custom Verification Handlers

Implement your own verification logic by inheriting from `VerificationHandler`:

```cpp
class MyCustomHandler : public keylock::verify::VerificationHandler {
public:
    keylock::verify::wire::VerifyResponse verify_chain(
        const std::vector<keylock::cert::Certificate>& chain,
        std::chrono::system_clock::time_point validation_time) override {

        keylock::verify::wire::VerifyResponse response;

        // Your custom verification logic here
        // - Check against database
        // - Query CRL
        // - Check LDAP
        // - etc.

        response.status = keylock::verify::wire::VerifyStatus::GOOD;
        response.this_update = std::chrono::system_clock::now();
        response.next_update = response.this_update + std::chrono::hours(24);

        return response;
    }

    // Optional: Optimize batch operations
    std::vector<keylock::verify::wire::VerifyResponse> verify_batch(
        const std::vector<std::vector<keylock::cert::Certificate>>& chains) override {
        // Batch optimization here
        return VerificationHandler::verify_batch(chains);
    }

    bool is_healthy() const override {
        // Health check logic
        return true;
    }
};
```

**Key Features:**
- In-memory revocation list (`SimpleRevocationHandler`)
- Custom handler interface for any backend (DB, CRL, LDAP, etc.)
- Ed25519 response signing
- Multi-threaded request handling via netpipe
- Thread-safe statistics
- Graceful shutdown
- Health monitoring

## Protocol Versioning

Current version: **0x01**

Future versions will maintain backward compatibility or increment the version byte. Clients MUST check the version byte in responses and reject unsupported versions.

## Error Handling

### Connection Errors

Netpipe returns `dp::Res<T>` result types. Common error conditions:

- **Connection refused**: Server not running or wrong address
- **Timeout**: Server not responding within configured timeout
- **Connection reset**: Server closed connection unexpectedly

### Client Error Handling

```cpp
auto result = client.verify_chain(chain);
if (!result.success) {
    // Network error, timeout, or server error
    std::cerr << "Error: " << result.error << "\n";
} else {
    // Check certificate status
    if (result.value.status == wire::VerifyStatus::REVOKED) {
        // Certificate is revoked
    } else if (result.value.status == wire::VerifyStatus::GOOD) {
        // Certificate is valid
    } else {
        // Unknown status (server doesn't know about this cert)
    }
}
```

## Future Extensions

Potential future additions:

1. **OCSP Stapling**: Embed LVP responses in TLS handshakes
2. **Certificate Transparency**: CT log integration
3. **Offline Verification**: Cached responses with short TTLs
4. **Multi-Issuer Support**: Verify chains from multiple CAs
