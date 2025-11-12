# Lockey Verification Protocol (LVP)

## Overview

The Lockey Verification Protocol (LVP) is a modern certificate revocation checking system built on gRPC with a custom binary wire format. It provides an efficient, secure alternative to OCSP for Ed25519 certificates.

## Design Goals

- **Modern**: Built on gRPC/HTTP2 for modern networking features
- **Efficient**: Custom binary protocol optimized for Ed25519 certificates
- **Secure**: Ed25519 signatures, nonce-based replay protection
- **Minimal**: No Protobuf dependency, ~15MB binary size impact
- **Optional**: Zero overhead when `LOCKEY_HAS_VERIFY=OFF`

## Architecture

```
┌─────────────┐                  ┌─────────────┐
│   Client    │                  │   Server    │
│  (Lockey)   │    gRPC/HTTP2    │  (Lockey)   │
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

## gRPC Service Definition

The protocol uses gRPC generic calls with custom binary serialization:

```
Service: lockey.verify.VerifyService

Methods:
- /lockey.verify.VerifyService/CheckCertificate
  Request:  VerifyRequest (binary)
  Response: VerifyResponse (binary)

- /lockey.verify.VerifyService/CheckBatch
  Request:  BatchVerifyRequest (binary)
  Response: BatchVerifyResponse (binary)

- /lockey.verify.VerifyService/HealthCheck
  Request:  HealthCheckRequest (binary)
  Response: HealthCheckResponse (binary)
```

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

Clients SHOULD use TLS for transport security:

```cpp
ClientConfig config;
config.ca_cert_path = "/path/to/ca-cert.pem";
Client client("verify.example.com:50051", config);
```

For development/testing, insecure channels are supported but NOT recommended for production.

## Usage Examples

### Basic Verification

```cpp
#ifdef LOCKEY_HAS_VERIFY
#include <lockey/verify/client.hpp>

// Create client
lockey::verify::ClientConfig config;
config.timeout = std::chrono::seconds(10);
config.max_retry_attempts = 3;

lockey::verify::Client client("verify.example.com:50051", config);

// Set responder certificate for signature verification
client.set_responder_cert(responder_cert);

// Verify certificate chain
auto result = client.verify_chain(cert_chain);
if (result.success && result.value.valid) {
    std::cout << "Certificate is valid and not revoked\n";
} else if (result.success && !result.value.valid) {
    std::cout << "Certificate is revoked: " << result.value.reason << "\n";
} else {
    std::cerr << "Verification failed: " << result.error << "\n";
}
#endif
```

### Batch Verification

```cpp
std::vector<std::vector<lockey::cert::Certificate>> chains;
// ... populate chains ...

auto result = client.verify_batch(chains);
if (result.success) {
    for (size_t i = 0; i < result.value.size(); ++i) {
        const auto& resp = result.value[i];
        if (resp.valid) {
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
| Transport | gRPC/HTTP2 | HTTP/1.1 |
| Batch support | Native | Extension |
| Binary size | ~15MB | N/A (OpenSSL) |

## Build Configuration

### Enabling Verification Support

```bash
# Build with verify module
cmake -B build -DLOCKEY_HAS_VERIFY=ON
cmake --build build

# Build without (default, minimal)
cmake -B build
cmake --build build
```

### CMake Integration

```cmake
find_package(lockey REQUIRED)
target_link_libraries(your_target lockey::lockey)

# Conditional usage
target_compile_definitions(your_target PRIVATE LOCKEY_HAS_VERIFY)
```

## Binary Size Impact

- **Core library (without verify)**: ~2.1MB
- **With verify module**: +15MB (gRPC)
- **Comparison**: Protobuf would add +22MB (saved 7MB)

The verify module is completely optional and adds zero overhead when disabled.

## Server Implementation

The verification server is now included in the lockey library itself! Both C++ client and server APIs are provided.

### Server API

```cpp
#ifdef LOCKEY_HAS_VERIFY
#include <lockey/verify/server.hpp>

// Create a verification handler
auto handler = std::make_shared<lockey::verify::SimpleRevocationHandler>();

// Add revoked certificates
handler->add_revoked_certificate(
    {0x01, 0x02, 0x03, 0x04, 0x05},  // Serial number
    "Key compromise",                 // Reason
    std::chrono::system_clock::now() // Revocation time
);

// Configure server
lockey::verify::ServerConfig config;
config.address = "0.0.0.0:50051";
config.max_threads = 4;
config.enable_compression = true;

// Create and start server
lockey::verify::Server server(handler, config);

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
#endif
```

### Custom Verification Handlers

Implement your own verification logic by inheriting from `VerificationHandler`:

```cpp
class MyCustomHandler : public lockey::verify::VerificationHandler {
public:
    lockey::verify::wire::VerifyResponse verify_chain(
        const std::vector<lockey::cert::Certificate>& chain,
        std::chrono::system_clock::time_point validation_time) override {
        
        lockey::verify::wire::VerifyResponse response;
        
        // Your custom verification logic here
        // - Check against database
        // - Query CRL
        // - Check LDAP
        // - etc.
        
        response.status = lockey::verify::wire::VerifyStatus::GOOD;
        response.this_update = std::chrono::system_clock::now();
        response.next_update = response.this_update + std::chrono::hours(24);
        
        return response;
    }
    
    // Optional: Optimize batch operations
    std::vector<lockey::verify::wire::VerifyResponse> verify_batch(
        const std::vector<std::vector<lockey::cert::Certificate>>& chains) override {
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
- gRPC async request handling
- Thread-safe statistics
- Graceful shutdown
- Health monitoring

## Protocol Versioning

Current version: **0x01**

Future versions will maintain backward compatibility or increment the version byte. Clients MUST check the version byte in responses and reject unsupported versions.

## Error Handling

### gRPC Status Codes

- `OK`: Success
- `INVALID_ARGUMENT`: Malformed request/response
- `UNAVAILABLE`: Server unreachable
- `DEADLINE_EXCEEDED`: Timeout
- `INTERNAL`: Server error

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

---

**Last Updated**: 2025-11-12  
**Version**: 0.1.0  
**Maintainer**: Lockey Project
