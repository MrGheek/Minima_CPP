# Contributing to Pure Minima C++

Thanks for your interest in contributing to this project!

## Code of Conduct

By participating you agree to abide by the [Code of Conduct](CODE_OF_CONDUCT.md).

## Ground Rules

- This is a **protocol-compatible C++ node**. Changes that alter consensus,
  the P2P wire format, or any network message structure require a coordinated
  network upgrade and will not be accepted as unilateral patches.
- Follow the existing code style: C++17, `org/minima/` namespace layout that
  mirrors the original Java codebase, and `snake_case` helpers with the
  Java-era method names preserved for compatibility.
- Do not add comments unless they clarify non-obvious logic.
- Never commit secrets, keys, build artifacts, or runtime data (see
  `.gitignore`).

## How to Contribute

1. **Open an issue first** for significant changes (security findings, API
   changes, new features) so maintainers can confirm the approach.
2. Fork the repository and create a feature branch.
3. Make your changes. Add or update tests in `tests/` where applicable.
4. Build and test locally:

   ```bash
   mkdir -p build && cd build
   cmake .. -DCMAKE_BUILD_TYPE=Release
   make -j$(sysctl -n hw.ncpu)
   make test_winternitz test_sha3 test_serialization
   ./test_winternitz && ./test_sha3 && ./test_serialization
   ```

5. Commit with a concise message describing the change (see the existing
   `git log` for style). Reference the issue number where relevant.
6. Submit a pull request.

## Security

Security vulnerabilities should be reported privately, not as public issues.
See [SECURITY.md](SECURITY.md) for the vulnerability reporting workflow and
the complete history of fixed findings.
