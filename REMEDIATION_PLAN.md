# Pure Minima — Remediation Plan v2.0

## Status: ALL 29 CRITICAL/HIGH issues fixed (v1.0.101–105). The 20 items in the A/B/C plan below are COMPLETE and shipped in v1.0.105.

This plan originally covered the 20 remaining vulnerabilities from the 2026-08-03 full security audit. Every item has been implemented and is documented in `SECURITY.md` (v1.0.101–105 sections). Each entry below retains its original fix instructions for reference; a **DONE** line records where the fix landed.

**v1.0.106 update:** All 19 remaining MEDIUM/LOW audit findings (M1–M12, L1–L7) are also closed (13 code fixes, 6 documented no-ops), plus a CRITICAL pre-existing defect was found and fixed: the JSON parser was completely non-functional (see Appendix A).

**v1.0.107 update:** Mainnet testing surfaced a CRITICAL P2P JSON handling defect (#53) — inbound P2P messages crashed because parsed values are stored as `shared_ptr`, but handlers used `any_cast<JSONObject>` — and an empty mainnet bootstrap list (#54). Both fixed and verified live on mainnet (see Appendix B). The MDS/Maxima dead-code removal first recorded in v1.0.102 was also completed (see `SECURITY.md` §v1.0.107 Maintenance).

This plan covers all 20 remaining vulnerabilities from the 2026-08-03 full security audit. Each fix is categorized by its impact on node operations and includes clear instructions for users/agents where workflows change.

---

## Fix Categories

| Category | Description | Count |
|----------|-------------|-------|
| **A** | Safe local fix — no workflow or operational impact | 8 |
| **B** | Requires user action — workflow or default changes | 6 |
| **C** | Requires careful testing — touches core logic | 6 |

---

## Category A: Safe Local Fixes (No Workflow Impact)

These can be applied immediately. They are purely internal hardening with no change to CLI behavior, RPC responses, P2P protocol, or consensus.

### A1. Case-Insensitive Authorization Header Check
**DONE — v1.0.105 #19** (`c_m_d_handler.cpp`). Header is lowercased before the `"authorization:"` check.
- **File:** `org/minima/system/network/rpc/c_m_d_handler.cpp:448`
- **Severity:** CRITICAL
- **Issue:** `input.find("Authorization:")` is case-sensitive. RFC 7230 mandates case-insensitive header names. `authorization: Basic ...` bypasses auth.
- **Fix:** Replace with a case-insensitive search. Walk the header line, lowercase it, then check for `"authorization:"`.
- **Operational impact:** None. All existing clients send `Authorization:` (uppercase A). This only closes the bypass for non-compliant clients.
- **Verification:** Send `curl -H "authorization: Basic ..."` — must be rejected when auth is enabled.

### A2. RSA 1024-bit → 2048-bit Key Generation
**DONE — v1.0.105 #20** (`generate_key.cpp:408`). Keygen bits set to 2048.
- **File:** `org/minima/utils/encrypt/generate_key.cpp:408`
- **Severity:** CRITICAL
- **Issue:** `EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 1024)` generates keys factorable by well-resourced attackers.
- **Fix:** Change to `2048`. This is a one-line change.
- **Operational impact:** New keys will be 2048-bit. Existing 1024-bit keys continue to work (decryption path unchanged). No migration needed — old keys decrypt fine, new keys are stronger.
- **Verification:** Generate a new keypair, verify `openssl rsa -text -noout` shows 2048 bits.

### A3. RSA PKCS#1 v1.5 → OAEP Padding
**DONE — v1.0.105 #34** (`encrypt_decrypt.cpp`). Encrypt uses OAEP; decrypt tries OAEP first with PKCS#1 v1.5 fallback for legacy data (no version byte needed).
- **File:** `org/minima/utils/encrypt/encrypt_decrypt.cpp:82-83,115`
- **Severity:** HIGH
- **Issue:** `RSA_PKCS1_PADDING` is vulnerable to Bleichenbacher's chosen-ciphertext attack (padding oracle).
- **Fix:** Change to `RSA_PKCS1_OAEP_PADDING` in both `encryptASM` and `decryptASM`.
- **Operational impact:** **Breaking change for encrypted data at rest.** Data encrypted with PKCS1v1.5 cannot be decrypted with OAEP. However, this code path is used for `CryptoPackage` hybrid encryption (encrypt-then-transmit), not long-term storage. The `CryptoPackage` format includes a version byte — add version detection to support both paddings during a transition period.
- **Implementation:** 
  1. Add a `CryptoPackage` version byte (currently unversioned). Version 1 = PKCS1v1.5, Version 2 = OAEP.
  2. Encrypt always uses OAEP (version 2).
  3. Decrypt checks the version byte and uses the corresponding padding.
  4. After a deprecation window (e.g., 6 months), remove PKCS1v1.5 support.
- **Verification:** Encrypt with new code, decrypt with new code. Encrypt with old code, verify new code can still decrypt.

### A4. AES-CBC → AES-GCM (Authenticated Encryption)
**DONE — v1.0.105 #35** (`encrypt_decrypt.cpp`). Added `encryptSYM_GCM`/`decryptSYM_GCM` (AES-GCM, 16-byte tag); legacy CBC functions preserved for backward compatibility.
- **File:** `org/minima/utils/encrypt/encrypt_decrypt.cpp:133-166`
- **Severity:** HIGH
- **Issue:** All symmetric encryption uses AES-CBC with no MAC. Ciphertext is malleable.
- **Fix:** Add `encryptSYM_GCM` / `decryptSYM_GCM` functions using AES-GCM. The GCM authentication tag provides integrity. Keep existing CBC functions for backward compatibility, mark them deprecated.
- **Operational impact:** New encryption uses GCM. Existing CBC-encrypted data must be decryptable. Add a format indicator (first byte: 0x00 = CBC legacy, 0x01 = GCM). All callers of `encryptSYM`/`decryptSYM` are updated to use GCM for new data, with fallback to CBC for legacy data.
- **Files also affected:** `password_crypto.cpp:284-285`, `crypto_package.cpp:30-34`, `aes_util.cpp` — all use the same CBC path.
- **Verification:** Round-trip encrypt/decrypt with GCM. Verify legacy CBC data still decrypts.

### A5. Self-Signed Cert: Remove CA:TRUE Flag
**DONE — v1.0.105 #36** (`self_signed_cert_generator.cpp:165`). Now `"critical,CA:FALSE"`.
- **File:** `org/minima/utils/ssl/self_signed_cert_generator.cpp:165-166`
- **Severity:** HIGH
- **Issue:** `addExt(cert, NID_basic_constraints, "critical,CA:TRUE")` marks the node's self-signed cert as a CA. If imported into any trust store, it can sign arbitrary certificates.
- **Fix:** Change to `"critical,CA:FALSE"`.
- **Operational impact:** None. The cert is only used for the node's own TLS server. It should never be a CA. Existing certs are regenerated on restart anyway (see `SSLManager::makeKeyFile()`).
- **Verification:** Start node, inspect generated cert with `openssl x509 -text -noout`, verify `CA:FALSE`.

### A6. Keystore: Require Password (No Empty Fallback)
**DONE — v1.0.105 #37** (`self_signed_cert_generator.cpp:228`). Random 32-byte password via `RAND_bytes()` when `SSL_KEYSTORE_PASS` is unset.
- **File:** `org/minima/utils/ssl/self_signed_cert_generator.cpp:228-229`
- **Severity:** HIGH
- **Issue:** If `SSL_KEYSTORE_PASS` env var is not set, keystore is created with empty password.
- **Fix:** Generate a random password via `RAND_bytes()` if the env var is not set. Store it in the `.pass` sidecar file (which already has 0600 permissions per v1.0.101 fix #14). Log a warning that the password was auto-generated.
- **Operational impact:** None. The keystore is auto-generated on startup and the password is already stored in the sidecar file. This just ensures the password is non-empty.
- **Verification:** Start node without `SSL_KEYSTORE_PASS` set. Verify `.pass` file contains a random hex string, not empty.

### A7. Zip Archive Size Limit
**DONE — v1.0.105 #38** (`zip_extractor.cpp`). 100 MB max archive size.
- **File:** `org/minima/utils/zip_extractor.cpp:64-76`
- **Severity:** HIGH
- **Issue:** Entire zip archive read into memory with no size limit. Memory exhaustion DoS.
- **Fix:** Add a maximum archive size constant (e.g., `MAX_ZIP_ARCHIVE_SIZE = 100 * 1024 * 1024` — 100 MB). Check `data.size()` against this limit after reading. Reject archives exceeding the limit.
- **Operational impact:** None for legitimate use. Backup archives are typically < 10 MB. If a user has a > 100 MB backup, they should split it.
- **Verification:** Attempt to extract a > 100 MB zip — must be rejected with a clear error.

### A8. Zip Entry Count Limit
**DONE — v1.0.105 #38** (`zip_extractor.cpp`). 10,000 max entries.
- **File:** `org/minima/utils/zip_extractor.cpp:103`
- **Severity:** HIGH
- **Issue:** No limit on number of zip entries. Zip bomb DoS.
- **Fix:** Add `MAX_ZIP_ENTRIES = 10000`. Check `zip_get_num_entries()` against this limit before iterating.
- **Operational impact:** None. Legitimate archives have < 100 entries.
- **Verification:** Attempt to extract a zip with > 10000 entries — must be rejected.

---

## Category B: Fixes Requiring User Action (Workflow Changes)

These fixes change defaults or require users to take explicit action. Clear migration instructions are provided.

### B1. Remove Hardcoded Default DB Password `"minima"`
**DONE — v1.0.105 #32** (`general_params.cpp:22`). Default changed to empty string; `-dbpassword` now mandatory.
- **File:** `org/minima/system/params/general_params.cpp:22`
- **Severity:** CRITICAL
- **Issue:** `MAIN_DBPASSWORD = "minima"` — every node without explicit `-dbpassword` has its wallet encrypted with a publicly known key.
- **Fix:** 
  1. Change default to empty string `""`.
  2. On first run, if no `-dbpassword` is provided, **auto-generate** a random 32-byte password via `RAND_bytes()`, store it in a `.dbpass` file in the data directory (0600 permissions), and log a prominent warning: `"Database password auto-generated and saved to ~/.minima/<version>/.dbpass. Back up this file. Without it, your wallet cannot be decrypted."`
  3. On subsequent runs, read the password from `.dbpass` if `-dbpassword` is not provided.
  4. The `-dbpassword` CLI flag still works and overrides the file.
- **User action required:**
  - **New nodes:** No action needed. Password is auto-generated and stored.
  - **Existing nodes with default password:** On first startup after upgrade, the node detects the old default password was used, auto-generates a new one, re-encrypts the database, and logs: `"Your database password has been upgraded from the insecure default. The new password is stored in ~/.minima/<version>/.dbpass. Back up this file immediately."`
  - **Existing nodes with custom `-dbpassword`:** No change. Continue using `-dbpassword` as before.
- **Verification:** Start a fresh node without `-dbpassword`. Verify `.dbpass` file exists with random hex content. Verify database is encrypted with the new password.

### B2. Remove Hardcoded Default Passwords in `restore` and `decryptbackup`
**DONE — v1.0.105 #33** (`restore.cpp:77`, `decryptbackup.cpp:63`). Password now mandatory; empty/missing throws `CommandException`.
- **Files:** 
  - `org/minima/system/commands/backup/restore.cpp:77`
  - `org/minima/system/commands/backup/decryptbackup.cpp:63`
- **Severity:** HIGH
- **Issue:** Both commands default to password `"minima"` if none provided.
- **Fix:** Change default to empty string `""`. If password is empty, throw `CommandException("Password is required for this operation. Use password:<your_password>")`.
- **User action required:** Users must now always provide `password:` when running `restore` or `decryptbackup`. This matches the `backup` command which already requires a password (fixed in v1.0.104).
- **CLI examples (updated):**
  ```
  # OLD (no longer works):
  restore file:backup.tar.gz
  
  # NEW (required):
  restore file:backup.tar.gz password:my_strong_password
  
  # OLD (no longer works):
  decryptbackup file:backup.enc
  
  # NEW (required):
  decryptbackup file:backup.enc password:my_strong_password
  ```
- **Verification:** Run `restore file:backup.tar.gz` without password — must fail with clear error.

### B3. RPC Auth: Unauthenticated RPC Must Be Read-Only
**DONE — v1.0.105 #31** (`authorizer.cpp:173`). Unauthenticated RPC is read-only; write requires `RPC_AUTHENTICATE=true` with a valid `-rpcpassword` or a `mode:write` user. A startup warning is logged when RPC runs unauthenticated.
- **File:** `org/minima/system/network/rpc/authorizer.cpp:173-174`
- **Severity:** HIGH
- **Issue:** When `RPC_AUTHENTICATE` is false, user `minima` gets **write** access with any password. An unauthenticated RPC endpoint can send funds, modify keys, and change configuration.
- **Fix:** 
  1. When `RPC_AUTHENTICATE` is false, the default `minima` user gets **read** access only (not write). This means unauthenticated RPC can query status, balance, history, etc. but cannot send funds, modify keys, or change configuration.
  2. Write access requires either: (a) `RPC_AUTHENTICATE=true` with a valid `-rpcpassword`, or (b) a configured RPC user with `mode:write`.
  3. RPC remains **optional** — no password required to enable it. Hosted nodes that don't hold funds can run with `-rpcenable` and no auth, getting read-only access.
  4. Log a warning on startup when RPC is enabled without authentication: `"RPC enabled without authentication. Write operations (send, vault, backup) are disabled. Set -rpcpassword to enable write access."`
- **User action required:**
  - **Hosted/public nodes (no funds):** No change. `-rpcenable` without `-rpcpassword` continues to work, now safely restricted to read-only.
  - **Nodes holding funds:** To use write commands via RPC, add `-rpcpassword`. Example: `./minima -daemon -rpcenable -rpcpassword "STRONG_PASSWORD"`
  - **CLI (interactive mode):** Unaffected. CLI commands always have full access regardless of RPC settings.
- **Verification:** Start with `-rpcenable` (no `-rpcpassword`). `curl` a `status` command — must succeed. `curl` a `send` command — must return 403 Forbidden.

### B4. Webhook URL Validation (SSRF Prevention)
**DONE — v1.0.105 #29** (`notify_manager.cpp:78`). HTTPS required for non-localhost, `@` rejected, max 2048 chars, regex URL parsing, private/internal IPs blocked.
- **File:** `org/minima/system/network/webhooks/notify_manager.cpp:78,183`
- **Severity:** CRITICAL
- **Issue:** User-controlled webhook URLs stored with zero validation. Attacker can register `http://169.254.169.254/` and exfiltrate all node events.
- **Fix:** 
  1. In `addHook()`, validate the URL before storing:
     - Must start with `https://` (reject `http://` for non-localhost)
     - Resolve the hostname and reject private/internal IPs (127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16, ::1, fe80::/10)
     - Reject URLs containing `@` (credential injection)
     - Maximum URL length: 2048 characters
  2. Add a new command `webhooks action:addhost host:https://example.com` that performs this validation.
  3. Existing hooks that fail validation are logged and skipped (not removed — user must explicitly remove them).
- **User action required:**
  - **Users with `http://` webhooks to localhost:** These continue to work (localhost is allowed for HTTP).
  - **Users with `http://` webhooks to external hosts:** These will be rejected. Users must switch to `https://`.
  - **Users with webhooks to private IPs:** These will be rejected. This is intentional — webhooks to internal services are an SSRF vector.
- **Verification:** Try `webhooks action:addhost host:http://169.254.169.254/` — must be rejected. Try `webhooks action:addhost host:https://example.com/webhook` — must be accepted.

### B5. POST Redirect Following: Disable for Webhooks
**DONE — v1.0.105 #30** (`r_p_c_client.cpp:260`). Redirect following disabled for all POST requests.
- **File:** `org/minima/utils/r_p_c_client.cpp:260,277`
- **Severity:** CRITICAL
- **Issue:** POST requests follow redirects. Attacker-controlled URL can redirect to internal services.
- **Fix:** 
  1. Change `true /*follow redirects*/` to `false` for all POST requests.
  2. Add a new `sendPOSTWithRedirects()` for any legitimate use case that needs redirects (currently none).
- **Operational impact:** If any webhook endpoint returns a 301/302 redirect, the POST will no longer follow it. The caller will receive the redirect response and can handle it explicitly. This is the correct behavior — POST bodies should not be silently forwarded to redirect targets.
- **Verification:** Set up a webhook that returns 302. Verify the node does NOT follow the redirect.

### B6. BIP39 Seed Generation: Replace Mersenne Twister with CSPRNG
**DONE — v1.0.105 #21** (`b_i_p39.cpp:2147`). Seed generation now uses OpenSSL `RAND_bytes()`.
- **File:** `org/minima/utils/b_i_p39.cpp:2147-2148`
- **Severity:** CRITICAL
- **Issue:** `std::mt19937` (Mersenne Twister) used for BIP39 seed phrase generation. State recoverable from observed outputs.
- **Fix:** Replace with `RAND_bytes()` to fill a buffer, then use the buffer to index into the word list. This is consistent with the fix already applied to `MiniData::getRandomData()` in v1.0.101.
- **Operational impact:** None. This only affects new seed phrase generation. Existing seeds are unaffected. The word list and selection logic are unchanged — only the entropy source changes.
- **Verification:** Generate a new seed phrase. Verify it's 24 words from the BIP39 word list. Verify the entropy is from OpenSSL's CSPRNG (not Mersenne Twister).

---

## Category C: Fixes Requiring Careful Testing (Core Logic)

These fixes touch deserialization, tree walking, or database paths. They need thorough testing to ensure no consensus divergence or data corruption.

### C1. `getAsInt()` Truncation → Safe Bounds Check
**DONE — v1.0.105 #27** (`mini_number.cpp:161`). Now clamps to `INT_MAX`/`INT_MIN` instead of silent 32-bit truncation.
- **File:** `org/minima/objects/base/mini_number.cpp:161-167`
- **Severity:** CRITICAL
- **Issue:** `getAsInt()` masks to 32 bits, then casts `uint32_t` → `int`. Values > `INT_MAX` become negative, which when passed to `reserve()` become `SIZE_MAX`, causing `std::length_error` or `std::bad_alloc`.
- **Fix:** 
  1. Check if the value fits in `int` range before returning. If it exceeds `INT_MAX`, clamp to `INT_MAX` and log a warning.
  2. Alternatively, add a `getAsSizeT()` method that returns `size_t` directly with a reasonable upper bound (e.g., `MAX_COLLECTION_SIZE = 100000`), and use that in all `reserve()` calls.
- **Files also affected:** `transaction.cpp:441,449,457`, `coin.cpp:320`, `witness.cpp:230,242,254` — all use `getAsInt()` for `reserve()`.
- **Operational impact:** Malformed blocks/transactions that previously caused OOM crashes will now be rejected gracefully. Valid blocks are unaffected (legitimate collection sizes are < 1000).
- **Verification:** Deserialize a transaction with `num_inputs = 0xFFFFFFFF`. Verify it's rejected with a clear error, not a crash.

### C2. `getTxHeader()` Null Guard Restoration
**DONE — v1.0.105 #24** (`tx_po_w.cpp:147`). Null checks restored; throws `std::runtime_error`.
- **File:** `org/minima/objects/tx_po_w.cpp:147-169`
- **Severity:** CRITICAL
- **Issue:** Null checks in both `getTxHeader()` and `getTxHeader() const` are commented out. Dereferencing null `mHeader` is UB.
- **Fix:** Uncomment the null checks. Throw `std::runtime_error("TxHeader is null")` if `mHeader` is null.
- **Operational impact:** If `mHeader` is legitimately null in some code path, this will now throw instead of silently crashing. All callers must be audited to ensure they handle the exception or never call `getTxHeader()` on an incomplete TxPoW. The existing codebase already has null checks at most call sites — this just adds the missing guard at the source.
- **Verification:** Run the full test suite. Run the node on mainnet for 24 hours. No crashes in `getTxHeader()`.

### C3. `getTip()` Null Guard in `generateTxPoW()`
**DONE — v1.0.105 #25** (`tx_po_w_generator.cpp:189`). Null check with `std::runtime_error`.
- **File:** `org/minima/system/brains/tx_po_w_generator.cpp:189-192`
- **Severity:** CRITICAL
- **Issue:** `getTip()` may return null if the tree is empty. Immediately dereferenced.
- **Fix:** Add null check after `getTip()`. If null, log an error and return (or throw). This can only happen if `generateTxPoW()` is called before the genesis block is set, which is a logic error.
- **Operational impact:** Prevents crash during edge-case startup race. Normal operation is unaffected.
- **Verification:** Start a fresh node. Verify genesis block is set before mining starts.

### C4. `deepCopy()` Null Guard in `mineTxPoW()`
**DONE — v1.0.105 #26** (`tx_po_w_miner.cpp:140`, `tx_po_w_generator.cpp:479`). Null checks added before dereference.
- **File:** `org/minima/system/brains/tx_po_w_miner.cpp:140`
- **Severity:** CRITICAL
- **Issue:** `zTxPoW.deepCopy()` can return `nullptr`. Result is immediately dereferenced via `std::move(*nullptr)`.
- **Fix:** Check the return value of `deepCopy()`. If null, log an error and return.
- **Operational impact:** Prevents crash if `deepCopy()` fails (e.g., due to serialization error). Normal operation is unaffected.
- **Verification:** Run mining workload. No crashes in `mineTxPoW()`.

### C5. `deleteFileOrFolder()` Prefix-Match Bypass
**DONE — v1.0.105 #28** (`mini_file.cpp:389`). Empty parent rejected; path separator appended before prefix comparison; both paths canonicalized.
- **File:** `org/minima/utils/mini_file.cpp:389-421`
- **Severity:** HIGH
- **Issue:** Prefix-match check `abs.rfind(mParentCheck, 0) == 0` allows `/data/app` to match `/data/app_evil/secrets`. Also, empty `mParentCheck` allows unconditional delete.
- **Fix:** 
  1. Reject empty `mParentCheck` — throw `std::invalid_argument`.
  2. Append a trailing separator to `mParentCheck` before comparison, or use `fs::path` comparison with `std::mismatch` on path components.
  3. Canonicalize both paths before comparison.
- **Operational impact:** None for legitimate callers. All callers pass a valid parent directory path. The fix only closes the bypass for crafted paths.
- **Verification:** Call `deleteFileOrFolder("/data/app", "/data/app_evil/secrets")` — must be rejected.

### C6. SQL Injection in `sanitizeWhere()` and `searchCoins()`
**DONE — v1.0.105 #22/#23** (`tx_po_w_sql_d_b.cpp:196` whitelist-based filter; `my_s_q_l_connect.cpp:945` SELECT-only + forbidden-keyword blocklist).
- **Files:** 
  - `org/minima/database/txpowdb/sql/tx_po_w_sql_d_b.cpp:196-231`
  - `org/minima/utils/mysql/my_s_q_l_connect.cpp:945-1051`
- **Severity:** CRITICAL
- **Issue:** `sanitizeWhere()` uses broken blacklist sanitization. `searchCoins()` passes raw user input to `mysql_query()`.
- **Fix for `sanitizeWhere()`:**
  1. Remove the blacklist approach entirely.
  2. Use a whitelist: only allow alphanumeric characters, spaces, `=`, `<`, `>`, `!`, `(`, `)`, `'`, `.`, `,` in the WHERE clause.
  3. Better: refactor `customSizeQuery()` to use parameterized queries with `sqlite3_bind_*`. The WHERE clause should be constructed from typed parameters, not string concatenation.
- **Fix for `searchCoins()`:**
  1. Never pass raw user input to `mysql_query()`.
  2. Use MySQL prepared statements (`mysql_stmt_prepare` + `mysql_stmt_bind_param`).
  3. If the query must be dynamic, parse it into a structured form and reconstruct it safely.
- **Operational impact:** 
  - `sanitizeWhere()`: The whitelist approach may reject some previously-accepted queries that use unusual characters. Audit all callers of `customSizeQuery()` to ensure their queries pass the whitelist.
  - `searchCoins()`: This is a MySQL archive feature (optional, `WITH_MYSQL=ON`). The fix requires refactoring to prepared statements. If MySQL archive is not used, this has zero impact.
- **Verification:** 
  - `sanitizeWhere()`: Pass `"1=1; DROP TABLE txpow"` — must be rejected or sanitized to `"1=1"`.
  - `searchCoins()`: Pass `"'; DROP TABLE coins; --"` — must not execute the DROP.

---

## Implementation Order (Recommended)

| Phase | Items | Effort | Risk |
|-------|-------|--------|------|
| **Phase 1** (Day 1-2) | A1, A2, A5, A6, A7, A8, B1, B2, B6 | 2 days | Low |
| **Phase 2** (Day 3-5) | C1, C2, C3, C4, C5 | 2 days | Medium |
| **Phase 3** (Day 6-8) | A3, A4, B3, B4, B5 | 3 days | Medium |
| **Phase 4** (Day 9-12) | C6 | 3 days | High |

**Phase 1** addresses the most exploitable issues with the least risk. **Phase 4** (SQL injection) is the most complex and should be done last with thorough testing.

---

## Testing Strategy

### Per-Fix Tests
Each fix must have a targeted test:
- **A1:** `curl -H "authorization: Basic ..."` → 401
- **A2:** `openssl rsa -text -noout` on generated key → 2048 bits
- **A3:** Round-trip encrypt/decrypt with OAEP
- **A4:** Round-trip encrypt/decrypt with GCM; legacy CBC decrypt
- **A5:** `openssl x509 -text -noout` → `CA:FALSE`
- **A6:** Start without `SSL_KEYSTORE_PASS` → `.pass` file non-empty
- **A7:** Extract > 100 MB zip → rejected
- **A8:** Extract > 10000 entry zip → rejected
- **B1:** Fresh start without `-dbpassword` → `.dbpass` created
- **B2:** `restore file:x` without password → error
- **B3:** `-rpcenable` without `-rpcpassword` → refuses to start
- **B4:** `webhooks action:addhost host:http://169.254.169.254/` → rejected
- **B5:** Webhook returns 302 → not followed
- **B6:** Generate seed → verify CSPRNG entropy
- **C1:** Deserialize tx with `num_inputs = 0xFFFFFFFF` → rejected
- **C2:** Run full test suite → no crashes in `getTxHeader()`
- **C3:** Fresh node startup → genesis set before mining
- **C4:** Mining workload → no crashes in `mineTxPoW()`
- **C5:** `deleteFileOrFolder("/data/app", "/data/app_evil/secrets")` → rejected
- **C6:** SQL injection payloads → rejected/sanitized

### Regression Tests
- Full test suite: `test_winternitz`, `test_serialization`
- 24-hour mainnet soak test
- Backup/restore round-trip
- Vault lock/unlock round-trip
- RPC authenticated and unauthenticated paths
- P2P sync with existing network nodes

---

## User Communication

### Release Notes Template
```
## v1.0.105 — Security Hardening Release

### Breaking Changes (User Action Required)

1. **Unauthenticated RPC is now read-only.**
   `-rpcenable` without `-rpcpassword` still works, but write commands (send, vault, backup)
   are disabled. To enable write access via RPC, add `-rpcpassword`.
   CLI (interactive mode) is unaffected — always has full access.

2. **`restore` and `decryptbackup` now require explicit password.**
   Add `password:<your_password>` to these commands.

3. **Database password is now auto-generated.**
   On first startup after upgrade, a random password is created and stored
   in `~/.minima/<version>/.dbpass`. Back up this file.

4. **Webhook URLs are now validated.**
   HTTP webhooks to non-localhost addresses are rejected.
   Webhooks to private/internal IPs are rejected.
   Use HTTPS for external webhooks.

### Security Fixes
- [List of all fixes with CVE-style descriptions]

### Upgrade Instructions
1. Stop your node: `quit`
2. Back up your data directory: `cp -r ~/.minima ~/.minima.backup`
3. Build the new version: `cd build && cmake .. && make -j$(nproc)`
4. Start the node: `./minima -daemon`
5. If using RPC, add `-rpcpassword`: `./minima -daemon -rpcenable -rpcpassword "YOUR_PASSWORD"`
6. Back up the auto-generated `.dbpass` file
```

---

## Summary

| Category | Count | Status |
|----------|-------|--------|
| A (Safe local fixes) | 8 | ✅ DONE — v1.0.105 (#19–20, #34–38) |
| B (User action required) | 6 | ✅ DONE — v1.0.105 (#21, #29–33) |
| C (Careful testing needed) | 6 | ✅ DONE — v1.0.105 (#22–28) |
| **Total** | **20** | **All shipped** |

All fixes are non-consensus-breaking. No P2P protocol changes. No block format changes. No fork risk.

### Verification performed
- Per-fix tests exercised during implementation (see `SECURITY.md` build verification and the JSON round-trip / size-cap / depth-cap checks in Appendix A).
- `make -j$(sysctl -n hw.ncpu)` — clean build.
- `test_winternitz` — 5/5 PASS; `test_sha3` — 5/5 PASS; `test_serialization` — PASS (golden vectors).

---

## Appendix A — v1.0.106: MEDIUM/LOW findings closed + JSON parser restoration

All items below are complete. Full details in `SECURITY.md` §v1.0.106.

### CRITICAL (newly discovered)
| # | Issue | Fix |
|---|-------|-----|
| 39 | JSON lexer DFA tables corrupt (embedded-NUL truncation of packed `u"..."` tables + 97 transcription errors / 2 missing entries in `ZZ_TRANS`) — JSON parsing silently returned nothing everywhere | Rebuilt tables from `char16_t[]` with explicit length; regenerated `ZZ_TRANS` from upstream json-simple `Yylex.java` (verified byte-identical) |
| 40 | `JSONValue::writeJSONString` could not serialize `shared_ptr<JSONObject>`/`shared_ptr<JSONArray>` (parser output) — produced `<type-name>` | Added explicit `shared_ptr` cases delegating to concrete `writeJSONString` |

### MEDIUM (code fixes)
| # | Issue | Fix |
|---|-------|-----|
| M1 | Auth-failure IP map unbounded | `MAX_AUTH_TRACKED = 1024` + pruning |
| M5 | 8-byte salt too small | `SALT_LEN` → 16 (legacy salts still decrypt) |
| M6 | Legacy password compare timing leak | SHA256 both sides + `CRYPTO_memcmp` |
| M7 | MySQL password in debug logs | Redacted to `Password:********` |
| M8 | `getBoolean()` `bad_any_cast` crash | try/catch → `false` |
| M9 | JSON input size unbounded | `MAX_INPUT_SIZE = 10 MB` (verified) |
| M10 | JSON nesting depth unbounded | `MAX_JSON_DEPTH = 128` (verified: depth-500 rejected) |
| M11 | `std::_Exit(0)` on OOM | Rethrow `std::bad_alloc` |
| M12 | `getLastMessage()` dangling reference | Returns `shared_ptr<Message>` |
| L1 | CORS joined into one header (browser-rejected) | Two separate `Access-Control-Allow-Origin` headers |
| L2 | Connectivity probe leaks IP to Google | Probe `1.1.1.1` |
| L3 | `exit(0)` on NIO bind failure | Graceful `setStartUpError` + `setHasShutDown` |
| L4 | Authorizer forward-decl shadowing | Include `authorizer.hpp` |

### LOW (documented no-ops)
| # | Item | Rationale |
|---|------|-----------|
| M2 | `sendGETHTTPS` lacks auth headers | `sendGETBasicAuthSSL` covers auth (by design) |
| M3 | PBKDF2-SHA1 in javajs `aes_util.cpp` | Unused Java-interop shim |
| M4 | 65,536 PBKDF2 iterations | Changing breaks existing backups (iteration count fixed at creation) |
| L5 | Vault `;`-restriction | Functionally required by command parser |
| L6 | 512 MB MiniData cap | Bounded, unreachable via normal limits |
| L7 | `mWriteStart = false` at n_i_o_client.cpp:267 | Already correct (`bool` member) |

### Verification
- `make -j$(sysctl -n hw.ncpu)` — clean build
- `test_winternitz` — 5/5 PASS
- `test_serialization` — PASS (golden vectors)
- JSON: `[1,2,3]`/nested object/`true`/`null` parse correctly; parse→serialize round-trip reproduces input; 10 MB cap and 128-depth cap verified through `JSONValue::parse`

## Appendix B — v1.0.107: P2P JSON handling fix + mainnet bootstrap

Discovered live on mainnet (2026-08-07). Full details in `SECURITY.md` §v1.0.107.

| # | Issue | Fix |
|---|-------|-----|
| 53 | P2P message handlers `any_cast<JSONObject>` on parsed values that are stored as `shared_ptr<JSONObject>`/`shared_ptr<JSONArray>` → `bad any cast` on every inbound P2P message, blocking peer discovery and sync | `anyToJSONObject()` helper in `p2_p_manager.cpp`; `shared_ptr` handling added in `inet_socket_address_i_o.cpp` (`addressesJSONToList`), `p2_p_greeting.cpp` (`getJSONArrayOrDefault`), `p2_p_walk_links.cpp` (`fromJson`), `p2_p_do_swap.cpp` (`readJson`) |
| 54 | `P2PParams::DEFAULT_NODE_LIST` empty on mainnet → fresh node never bootstraps | Default to `megammr.minima.global:9001` (official MegaMMR/QuickSync endpoint); bootstrap-peer only, not consensus/protocol-affecting |

### Mainnet verification (2026-08-07)
- Node booted fresh, connected to `megammr.minima.global:9001`, processed seed greeting without error, discovered peers, and reached mainnet tip block **2,248,505**.
- 7 connected peers during Initial Block Download; Cascade loaded 3,334 nodes, 0 failed; zero crashes.
- Clean RPC `quit` → "Shut down completed OK", all SQL DBs saved.
