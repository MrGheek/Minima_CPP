## Usage

The release bundle contains two native binaries plus their SHA-256 checksums:

| File | Platform |
|---|---|
| `minima-linux-x86_64` | Ubuntu/Debian (and most x86_64 Linux) |
| `minima-darwin-arm64` | macOS on Apple Silicon (M1/M2/M3/...) |

### macOS (Apple Silicon)

```bash
chmod +x minima-darwin-arm64
./minima-darwin-arm64 -daemon
```

That starts a full mainnet node as a daemon (P2P on port 9001, data in `~/.minima/1.0/`).

Useful variants:

```bash
./minima-darwin-arm64                        # interactive CLI (type commands like status, quit)
./minima-darwin-arm64 -daemon -rpcenable -rpcpassword "yourpass"   # + JSON-RPC on port 9005
./minima-darwin-arm64 -daemon -data ~/my-test-minima               # separate data dir
```

**Gatekeeper:** since these binaries are not notarized, macOS may block the first run. Clear the quarantine attribute:

```bash
xattr -d com.apple.quarantine minima-darwin-arm64
```

**First run:** the node auto-generates a seed wallet, SSL keystore, and SQLCipher database in `~/.minima/1.0/`. It syncs from the default bootstrap seed `megammr.minima.global:9001`; RPC stays read-only unless a `-rpcpassword` is supplied.

### Linux

```bash
chmod +x minima-linux-x86_64
./minima-linux-x86_64 -daemon
```

### Verify checksums

```bash
shasum -a 256 -c minima-darwin-arm64.sha256   # macOS
sha256sum -c minima-linux-x86_64.sha256       # Linux
```

### Shutdown

Interactive mode: type `quit` in the CLI. Daemon mode: `curl -u minima:password http://127.0.0.1:9005/quit` (RPC must be enabled with `-rpcenable -rpcpassword`).
