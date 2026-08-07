# Pure Minima — C++ Node

A C++17 implementation of the Minima blockchain node, translated from the original Java codebase.

## Quick Start

```bash
# Build
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j$(sysctl -n hw.ncpu)

# Run (interactive CLI)
./minima

# Run (daemon mode)
./minima -daemon

# Run with custom seed phrase
./minima -seed "your twenty four word bip39 seed phrase here"
```

## First-Run Security Setup

When you start a new node, a BIP39 seed phrase is auto-generated. **You must back this up immediately** — it is the master key to all your funds.

### Step 1: Export your seed phrase (encrypted)

```
vault action:export password:YOUR_STRONG_PASSWORD file:seed-backup.enc
```

This creates an AES-encrypted file containing your seed phrase. Store this file offline (USB drive, encrypted cloud storage). **Never share your password or seed phrase with anyone.**

### Step 2: Lock your node

```
vault action:passwordlock password:YOUR_STRONG_PASSWORD
```

This encrypts the seed phrase at rest and wipes the plaintext from the SQLite database. Your node can still sign transactions (keys are derived and cached), but the master seed is protected.

### Step 3: Verify

```
vault action:status
```

Should show `locked: true` and `has_encrypted_backup: true`.

### Step 4: View your seed (if needed)

```
vault action:seed password:YOUR_STRONG_PASSWORD
```

## Restoring from Backup

### From an encrypted seed export

```
vault action:import password:YOUR_STRONG_PASSWORD file:seed-backup.enc
```

### From a BIP39 seed phrase

```
vault action:restorekeys phrase:"your twenty four word bip39 seed phrase"
```

## Vault Commands Reference

| Command | Description | Requires Password |
|---------|-------------|-------------------|
| `vault action:status` | Check if seed is locked, if backup exists | No |
| `vault action:seed password:X` | View seed phrase and raw seed | Yes (if locked) |
| `vault action:export password:X file:Y` | Export encrypted seed to file | Yes |
| `vault action:import password:X file:Y` | Restore from encrypted export | Yes |
| `vault action:passwordlock password:X` | Encrypt seed at rest, wipe plaintext | Yes |
| `vault action:passwordunlock password:X` | Decrypt and restore seed | Yes |
| `vault action:wipekeys seed:0x...` | Wipe private keys (keep public) | No (requires seed) |
| `vault action:restorekeys phrase:"..."` | Restore from BIP39 phrase | No |

## RPC Configuration

RPC is **disabled by default**. To enable it securely:

```bash
# Start with RPC and authentication
./minima -daemon -rpcenable -rpcpassword "STRONG_UNIQUE_PASSWORD"
```

### Creating RPC users

```
# Admin user (full write access)
rpc action:newuser username:admin password:admin_pass mode:write

# Read-only monitoring user
rpc action:newuser username:monitor password:monitor_pass mode:read
```

Read-only users can query status, balance, and history but **cannot** send funds, modify keys, or change configuration.

### RPC Security Notes

- Always use `-rpcpassword` when enabling RPC
- Use HTTPS (`-rpcssl`) for non-localhost deployments
- Never expose RPC to the public internet without TLS + auth
- Use the CLI directly for sensitive operations (vault, backup, send)
- CORS is restricted to localhost origins only

## Building

### Prerequisites

- C++17 compiler (Clang 10+, GCC 9+)
- CMake 3.16+
- SQLite3
- OpenSSL 3.x
- zlib
- libcurl
- Boost (multiprecision)

### macOS

```bash
brew install cmake sqlite3 openssl zlib curl boost
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j$(sysctl -n hw.ncpu)
```

### Linux (Ubuntu/Debian)

```bash
sudo apt-get install build-essential cmake libsqlite3-dev libssl-dev zlib1g-dev libcurl4-openssl-dev libboost-dev
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)
```

### Optional Dependencies

```bash
# MySQL archive support
cmake .. -DWITH_MYSQL=ON

# libzip extraction support
cmake .. -DWITH_LIBZIP=ON
```

## Running Tests

```bash
cd build
make test_winternitz test_sha3 test_serialization
./test_winternitz    # Winternitz OTS: 5/5 tests
./test_sha3          # SHA3-256 (FIPS 202): 5/5 tests
./test_serialization # Serialization golden vectors
```

## Mainnet Status

Verified against live Minima mainnet (2026-08-07, v1.0.107): P2P peer discovery, greetings, and Initial Block Download to the tip block all work via the default bootstrap seed `megammr.minima.global:9001`. See `SECURITY.md` §v1.0.107 for the full test record.

## Docker

```bash
docker build -t pureminima .
docker run -d -p 9001-9005:9001-9005 -v ~/.minima:/root/.minima pureminima
```

Or with docker-compose:

```bash
docker-compose up -d
```

## Security

See [SECURITY.md](SECURITY.md) for a complete list of fixed vulnerabilities, remaining known issues, and security best practices.

### Key Security Features (v1.0.101+)

- RPC requires authentication by default (no more anonymous access)
- Read/write authorization enforced on all RPC commands
- Seed phrase encrypted at rest with password-based AES
- Cryptographically secure random number generation (OpenSSL CSPRNG)
- Constant-time password comparison (timing attack resistant)
- Path traversal prevention in all file operations
- TLS certificate validation enabled (no more SSL_VERIFY_NONE)
- HTTP request size limits (10 MB body, 8 KB headers)
- CORS restricted to localhost
- Graceful shutdown instead of hard process termination
- Atomic shutdown flags (thread-safe state transitions)
- MDS/Maxima dead code fully removed (cleaner, smaller binary)
- RPC user passwords hashed at rest (PBKDF2-HMAC-SHA256, salted) — no plaintext credentials in SQLite
- RPC authentication rate-limited per source IP (5 failures / 15 min)
- Backup password mandatory (no hardcoded default)
- KISSVM no longer leaks memory on script execution
- Network message size capped at 16 MB; IBD pending queues bounded
- Peer list advertised in random 20-peer subsets (reduced topology exposure)

## Architecture

```
org/minima/
  objects/       # Core data types (TxPoW, Coin, Address, MMR, etc.)
  database/      # SQLite-backed storage (wallet, txpowdb, cascade, archive)
  kissvm/        # KISSVM smart contract engine
  system/
    brains/      # TxPoW mining, processing, checking
    commands/    # CLI/RPC command implementations
    network/     # P2P networking (NIO, P2P, RPC, webhooks)
    params/      # Configuration and network parameters
  utils/         # Crypto, JSON, BIP39, file I/O, logging
```

## License

Licensed under the [Apache License, Version 2.0](LICENSE). This is a C++17
translation of the Minima node; the original Java implementation is
[Minima Global / Minima](https://github.com/minima-global/Minima), also
Apache-2.0. See [NOTICE](NOTICE) for attribution. See
[CONTRIBUTING.md](CONTRIBUTING.md) and [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)
for contribution guidelines.
