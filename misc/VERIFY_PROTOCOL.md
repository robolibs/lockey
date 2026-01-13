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
┌─────────────────────────────────────────────────────────────────┐
│                      LVP Protocol Flow                            │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   ┌─────────────┐                 ┌─────────────┐               │
│   │   Client    │                 │   Server    │               │
│   │  (keylock)  │   netpipe/TCP   │  (keylock)  │               │
│   │             │◄───────────────►│             │               │
│   │ Wire Format │  Binary Protocol │ Wire Format│               │
│   └─────────────┘                 └─────────────┘               │
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
│                  LVP Server API                              │
│  - Request handling (netpipe)                                │
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
#include <keylock/verify/client.hpp>

// Create client and set responder certificate
keylock::verify::Client client("192.168.1.100:50051", config);

// Load and set responder certificate for signature verification
auto responder_cert = keylock::cert::load_from_file("responder.pem");
client.set_responder_cert(responder_cert.value);

// Verify certificate chain
auto result = client.verify_chain(cert_chain);
// Signature is automatically verified if responder cert is set
if (!result.success) {
    // Signature verification failed or network error
    std::cerr << "Verification failed: " << result.error << "\n";
}
```

**Signature Properties:**
- **Algorithm**: Ed25519 (twisted Edwards curve)
- **Key size**: 32 bytes private, 32 bytes public
- **Signature size**: 64 bytes
- **Security level**: 128-bit security (equivalent to 3072-bit RSA)

### Transport Security

The netpipe transport uses plain TCP by default. For production deployments requiring encryption, consider:

1. **TLS termination proxy**: Run the LVP server behind nginx, HAProxy, or similar
2. **VPN or encrypted tunnel**: Use WireGuard, OpenVPN, or SSH tunneling
3. **Private network**: Deploy on a trusted isolated network segment
4. **Mutual authentication**: Add application-layer authentication if needed

The protocol-level Ed25519 signatures ensure response authenticity regardless of transport encryption, but transport encryption provides additional protection against:

- Eavesdropping on certificate chains (privacy concern)
- Man-in-the-middle attacks on the protocol itself
- Traffic analysis (timing and size)

**Recommended setup for production:**
```
Internet → TLS Termination (nginx) → LVP Server (localhost)
                      ↓
                Client verifies TLS certificate + LVP response signature
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

### Basic Verification

Verify a single certificate chain:

```cpp
#include <keylock/verify/client.hpp>
#include <keylock/cert/certificate.hpp>

int main() {
    // Load certificate chain
    auto leaf_cert = keylock::cert::load_from_file("leaf.pem");
    auto intermediate = keylock::cert::load_from_file("intermediate.pem");

    std::vector<keylock::cert::Certificate> chain = {
        leaf_cert.value,
        intermediate.value
    };

    // Create client with configuration
    keylock::verify::ClientConfig config;
    config.timeout = std::chrono::seconds(10);
    config.max_retry_attempts = 3;
    config.connect_timeout = std::chrono::seconds(5);

    keylock::verify::Client client("192.168.1.100:50051", config);

    // Set responder certificate for signature verification
    auto responder_cert = keylock::cert::load_from_file("responder.pem");
    client.set_responder_cert(responder_cert.value);

    // Verify certificate chain
    auto result = client.verify_chain(chain);

    if (!result.success) {
        std::cerr << "Verification request failed: " << result.error << "\n";
        return 1;
    }

    auto& response = result.value;

    switch (response.status) {
        case keylock::verify::wire::VerifyStatus::GOOD:
            std::cout << "Certificate is valid and not revoked\n";
            std::cout << "Valid from: " << response.this_update << "\n";
            std::cout << "Valid until: " << response.next_update << "\n";
            break;

        case keylock::verify::wire::VerifyStatus::REVOKED:
            std::cout << "Certificate is revoked!\n";
            std::cout << "Reason: " << response.reason << "\n";
            std::cout << "Revoked at: " << response.revocation_time << "\n";
            break;

        case keylock::verify::wire::VerifyStatus::UNKNOWN:
            std::cout << "Certificate status unknown to server\n";
            break;
    }

    return 0;
}
```

### Batch Verification

Verify multiple certificate chains efficiently:

```cpp
#include <keylock/verify/client.hpp>

int main() {
    keylock::verify::Client client("192.168.1.100:50051");

    // Prepare multiple certificate chains
    std::vector<std::vector<keylock::cert::Certificate>> chains;

    // Add chain 1
    auto chain1 = load_chain("chain1/");
    chains.push_back(chain1);

    // Add chain 2
    auto chain2 = load_chain("chain2/");
    chains.push_back(chain2);

    // Verify all chains in a single request
    auto result = client.verify_batch(chains);

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

Monitor server health:

```cpp
#include <keylock/verify/client.hpp>

int main() {
    keylock::verify::Client client("192.168.1.100:50051");

    auto health = client.health_check();

    if (!health.success) {
        std::cerr << "Health check failed: " << health.error << "\n";
        return 1;
    }

    switch (health.value) {
        case keylock::verify::wire::ServingStatus::SERVING:
            std::cout << "Server is healthy and accepting requests\n";
            break;

        case keylock::verify::wire::ServingStatus::NOT_SERVING:
            std::cout << "Server is not accepting requests\n";
            break;

        default:
            std::cout << "Unknown server status\n";
            break;
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
| Transport | netpipe/TCP | HTTP/1.1 |
| Batch support | Native | Optional extension |
| Dependencies | netpipe, datapod | OpenSSL |
| Message size | ~150 bytes response | ~300-500 bytes response |
| Latency | ~20-40 ms | ~30-60 ms (includes HTTP overhead) |

**Key advantages of LVP:**
- Simpler wire format (no ASN.1 parsing overhead)
- Smaller message sizes
- Faster signing/verification (Ed25519 vs RSA)
- Native batch support
- Lower dependencies

## Server Implementation

The verification server is included in the keylock library. Both C++ client and server APIs are provided.

### Basic Server Setup

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

    // Configure server
    keylock::verify::ServerConfig config;
    config.host = "0.0.0.0";
    config.port = 50051;
    config.max_threads = 4;
    config.max_connections = 1000;
    config.idle_timeout = std::chrono::seconds(300);

    // Create and start server
    keylock::verify::Server server(handler, config);

    // Set Ed25519 signing key
    std::vector<uint8_t> sk(crypto_sign_SECRETKEYBYTES);
    std::vector<uint8_t> pk(crypto_sign_PUBLICKEYBYTES);
    crypto_sign_keypair(pk.data(), sk.data());
    server.set_signing_key(sk);

    // Optional: Set responder certificate (sent to clients on request)
    auto responder_cert = keylock::cert::load_from_file("responder.pem");
    server.set_responder_certificate(responder_cert.value);

    // Start server (blocking)
    std::cout << "Starting verification server on " << config.host << ":" << config.port << "\n";
    server.start();

    return 0;
}
```

### Asynchronous Server

Run server alongside other tasks:

```cpp
#include <keylock/verify/server.hpp>
#include <signal.h>
#include <atomic>

std::atomic<bool> shutdown_flag(false);

void signal_handler(int) {
    shutdown_flag = true;
}

int main() {
    // Setup signal handler for graceful shutdown
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    // Create handler and server
    auto handler = std::make_shared<keylock::verify::SimpleRevocationHandler>();
    keylock::verify::ServerConfig config;
    config.host = "0.0.0.0";
    config.port = 50051;

    keylock::verify::Server server(handler, config);

    // Set signing key
    auto keypair = generate_server_keypair();
    server.set_signing_key(keypair.private_key);

    // Start server asynchronously
    server.start_async();
    std::cout << "Server started\n";

    // Wait for shutdown signal
    while (!shutdown_flag) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }

    // Graceful shutdown
    std::cout << "Shutting down server...\n";
    server.shutdown();
    server.wait();

    std::cout << "Server stopped\n";
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
        auto serial = chain[0].serial_number();

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

    // Optimize batch operations with a single query
    std::vector<keylock::verify::wire::VerifyResponse> verify_batch(
        const std::vector<std::vector<keylock::cert::Certificate>>& chains) override {

        std::vector<keylock::verify::wire::VerifyResponse> responses;
        responses.reserve(chains.size());

        auto now = std::chrono::system_clock::now();

        // Collect all serial numbers
        std::vector<std::vector<uint8_t>> serials;
        for (const auto& chain : chains) {
            if (!chain.empty()) {
                serials.push_back(chain[0].serial_number());
            }
        }

        try {
            pqxx::work txn(conn_);

            // Batch query (PostgreSQL supports IN clause with arrays)
            std::string query = "SELECT serial_number, status, reason, revoked_at FROM revoked_certs WHERE serial_number = ANY($1)";
            pqxx::result r = txn.exec_params(query, serials);

            // Build lookup map
            std::map<std::vector<uint8_t>, pqxx::row> revocation_map;
            for (const auto& row : r) {
                pqxx::binarystring serial(row["serial_number"]);
                revocation_map[std::vector<uint8_t>(serial.begin(), serial.end())] = row;
            }

            // Generate responses
            for (const auto& chain : chains) {
                keylock::verify::wire::VerifyResponse response;
                response.this_update = now;
                response.next_update = now + std::chrono::hours(1);

                if (chain.empty()) {
                    response.status = keylock::verify::wire::VerifyStatus::UNKNOWN;
                    response.reason = "Empty certificate chain";
                } else {
                    auto serial = chain[0].serial_number();
                    auto it = revocation_map.find(serial);

                    if (it == revocation_map.end()) {
                        response.status = keylock::verify::wire::VerifyStatus::GOOD;
                        response.reason = "Certificate not in revocation list";
                    } else {
                        response.status = keylock::verify::wire::VerifyStatus::REVOKED;
                        response.reason = it->second["reason"].as<std::string>();
                        std::string revoked_str = it->second["revoked_at"].as<std::string>();
                        response.revocation_time = parse_timestamp(revoked_str);
                    }
                }

                responses.push_back(std::move(response));
            }

            txn.commit();

        } catch (const std::exception& e) {
            // Fallback to individual queries on error
            return VerificationHandler::verify_batch(chains);
        }

        return responses;
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
    pqxx::connection conn_;

    std::chrono::system_clock::time_point parse_timestamp(const std::string& ts) {
        // Parse timestamp string (implement as needed)
        // ...
    }
};

int main() {
    auto handler = std::make_shared<DatabaseRevocationHandler>(
        "dbname=revocation user=revoker password=secret"
    );

    keylock::verify::ServerConfig config;
    config.host = "0.0.0.0";
    config.port = 50051;

    keylock::verify::Server server(handler, config);

    auto keypair = generate_server_keypair();
    server.set_signing_key(keypair.private_key);

    server.start();
    return 0;
}
```

**Key Handler Features:**
- **In-memory revocation list** (`SimpleRevocationHandler`) - Fast, ephemeral storage
- **Custom handler interface** - Connect to any backend (DB, CRL, LDAP, etc.)
- **Batch optimization** - Override `verify_batch` for efficient bulk queries
- **Health monitoring** - `is_healthy()` for load balancer checks
- **Thread safety** - Handlers must be thread-safe if using multiple server threads

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

### Connection Errors

Netpipe returns `dp::Res<T>` result types. Common error conditions:

| Error | Cause | Action |
|-------|-------|--------|
| Connection refused | Server not running or wrong address | Check server status and address |
| Timeout | Server not responding within configured timeout | Increase timeout or check server load |
| Connection reset | Server closed connection unexpectedly | Check server logs for crashes |
| Network unreachable | Network connectivity issue | Check network configuration |

### Client Error Handling

```cpp
#include <keylock/verify/client.hpp>

keylock::verify::Client client("192.168.1.100:50051");
auto result = client.verify_chain(chain);

if (!result.success) {
    // Network error, timeout, or server error
    std::cerr << "Error: " << result.error << "\n";

    // Handle specific errors
    if (result.error.find("timeout") != std::string::npos) {
        // Retry with longer timeout
        // ...
    } else if (result.error.find("connection refused") != std::string::npos) {
        // Server is down
        // ...
    }

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
            // Server doesn't know about this certificate
            // Could be valid or not in server's database
            break;
    }
}
```

### Server Error Handling

The server should handle errors gracefully:

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
            response.reason = std::string("Server error: ") + e.what();
            response.this_update = std::chrono::system_clock::now();
            response.next_update = response.this_update + std::chrono::minutes(5);
            return response;
        }
    }
};
```

