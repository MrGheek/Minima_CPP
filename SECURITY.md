# Security Fixes — Pure Minima C++

## Summary

This document describes all security vulnerabilities identified and fixed in the Pure Minima C++ codebase as of 2026-08-07 (v1.0.107).

**Total: 40 CRITICAL/HIGH vulnerabilities fixed across 5 releases, plus MEDIUM/LOW hardening, a CRITICAL JSON-parser restoration (v1.0.106), and a CRITICAL P2P JSON-handling fix discovered during mainnet testing (v1.0.107).**

## Reporting a Vulnerability

Security vulnerabilities should be reported privately. Please open a GitHub
Security Advisory on this repository, or contact the repository owner directly.
Do not file public issues for security findings. Please include the affected
file(s) and a minimal reproduction if possible. You can expect an initial
acknowledgement within 3 business days. We ask that you do not disclose the
finding publicly until a fix has been released and documented in this file.

---

## Fixed Vulnerabilities

### v1.0.107 — P2P JSON Message Handling Fix + Mainnet Bootstrap (2 fixes)

Discovered live on mainnet (2026-08-07): with the JSON parser restored (v1.0.106), every inbound P2P message crashed the message processor. The parser stores nested JSON values as `std::shared_ptr<JSONObject>` / `std::shared_ptr<JSONArray>`, but the P2P handlers performed `std::any_cast<JSONObject>` on parsed values, throwing `bad any_cast` (the same storage-form mismatch as #40). This blocked all inbound P2P traffic and, therefore, chain sync.

#### CRITICAL

##### 53. P2P Message Handlers Cast Parsed Values to Wrong Type (bad any_cast)
**Problem:** Five locations across the P2P layer did `std::any_cast<JSONObject>` (or `const JSONObject&`) on values produced by the JSON parser, which stores nested objects/arrays as `shared_ptr`. Result: every inbound P2P message (greeting/`swap_links_p2p`, `walk_links`, `do_swap`) threw `bad any_cast` in `MessageProcessor::run`, so the node could connect to peers but never process their messages — no peer discovery, no chain sync.
**Fix:**
- `p2_p_manager.cpp` — added `anyToJSONObject()` helper (accepts `JSONObject` or `shared_ptr<JSONObject>`); applied to the `message`, `swap_links_p2p`, `greeting`, and `P2P_SEND_MSG`/`P2P_SEND_MSG_TO_ALL` extraction points.
- `inet_socket_address_i_o.cpp` — `addressesJSONToList()` now accepts array elements stored as `shared_ptr<JSONObject>`.
- `p2_p_greeting.cpp` — `getJSONArrayOrDefault()` now accepts `shared_ptr<JSONArray>`.
- `p2_p_walk_links.cpp` — `fromJson()` accepts `shared_ptr<JSONObject>` (`walk_links`) and `shared_ptr<JSONArray>` (`pathTaken`).
- `p2_p_do_swap.cpp` — `readJson()` accepts `shared_ptr<JSONObject>` (`do_swap`).

**Impact:** Inbound P2P messages now parse correctly. Verified on mainnet: node connected to the seed, exchanged greetings, discovered 42 peers from the seed greeting, and began Initial Block Download.

##### 54. No Mainnet Bootstrap Seed (empty DEFAULT_NODE_LIST)
**Problem:** `P2PParams::DEFAULT_NODE_LIST` was empty on mainnet, so a fresh node never attempted discovery and logged "No default Peers found". Only test mode had a default node.
**Fix:** Defaulted to `megammr.minima.global:9001` (an official Minima MegaMMR/QuickSync endpoint). This is a bootstrap-peer list only — not consensus- or protocol-affecting.
**Impact:** Fresh nodes can now discover the network on startup.

### Mainnet Test Record (v1.0.107, 2026-08-07)

Node `./build/minima -daemon -port 10001 -data <testdir> -dbpassword … -rpcenable -rpcpassword …`:

| Check | Result |
|-------|--------|
| Startup | Clean: SQLCipher DB, seed keygen, SSL keystore, RPC on port |
| RPC auth (Basic, write mode) | `status`, `Peers`, `peers action:addpeers` all worked |
| P2P connect to seed | `Connected attempt success to megammr.minima.global:9001` (v1.0.47) |
| Inbound P2P messages | Greetings parsed without error after fix #53 |
| Peer discovery | 42 peers received from seed greeting; public list fetch + direct connects worked |
| Connected peers | 7 connected, several in-flight during IBD |
| Initial Block Download | Received (e.g. 10.4 MB, 2,130 blocks in one pull) |
| Sync | Reached mainnet tip block **2,248,505**; Cascade loaded 3,334 nodes, 0 failed |
| Stability | 0 crashes / 0 unhandled exceptions over the session |
| Shutdown | RPC `quit` → "Shut down completed OK", all SQL DBs saved |

#### Maintenance (same release)

- Completed the MDS/Maxima dead-code removal that v1.0.102 had recorded: removed the unreachable `mdsenable`/`mdspassword`/`mdsinit`/`mdswrite`/`nosslmds`/`publicmds`/`publicmdsuid` param keys, the never-written/read Maxima NIO identity API (`isMaximaClient`/`setMaximaIdent`/`getMaximaIdent`/`isMaximaMLS`/`setMaximaMLS`/`getMaximaMLS`/`hasMaximaDiscxonnected`/`setMaximaDisconnected`, `NIOManager::getMaximaUID`), renamed `P2PNETMDS_TIMER` → `NETCHECK_TIMER`, and dropped the unused `restoreReady(bool)`/`shutdownFinalProcs(bool)` overloads. Retained intentionally: the Maxima wire-type discard handlers (`MSG_MAXIMA_CTRL`/`MSG_MAXIMA_TXPOW`), the `MDS_HEAVIER_CHAIN`/`MDS_RESYNC_START` webhook events, and the whitepaper's Maxima section.

---

### v1.0.105 — Full Security Audit Remediation (20 fixes)

#### CRITICAL

##### 19. Auth Bypass via Case-Insensitive Header (c_m_d_handler.cpp:448)
**Problem:** `input.find("Authorization:")` was case-sensitive. RFC 7230 mandates case-insensitive header names. Sending `authorization: Basic ...` (lowercase) bypassed authentication entirely.

**Fix:** Lowercase the header line before checking for `"authorization:"`.

##### 20. RSA 1024-bit Key Generation (generate_key.cpp:408)
**Problem:** `EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 1024)` generated keys factorable by well-resourced attackers. NIST mandates ≥2048 bits since 2013.

**Fix:** Changed to 2048 bits.

##### 21. Non-CSPRNG for BIP39 Seed Generation (b_i_p39.cpp:2147)
**Problem:** `std::mt19937` (Mersenne Twister) was used to generate BIP39 seed phrases — the master key for the entire wallet. Mersenne Twister state is recoverable from observed outputs.

**Fix:** Replaced with `RAND_bytes()` from OpenSSL's CSPRNG.

##### 22. SQL Injection in searchCoins (my_s_q_l_connect.cpp:945)
**Problem:** `searchCoins()` passed user-supplied query string directly to `mysql_query()` with zero sanitization. Arbitrary SQL execution possible.

**Fix:** Restricted to SELECT-only queries with a forbidden-keyword blocklist (DROP, ALTER, CREATE, INSERT, UPDATE, DELETE, TRUNCATE, etc.).

##### 23. SQL Injection in sanitizeWhere (tx_po_w_sql_d_b.cpp:196)
**Problem:** Blacklist-based sanitization only removed semicolons and `update`/`delete`/`insert` keywords. Bypassable via `UNION SELECT`, `ATTACH DATABASE`, hex encoding, etc.

**Fix:** Replaced with whitelist-based character filtering — only alphanumeric and safe SQL characters allowed.

##### 24. Null Pointer Dereference in getTxHeader (tx_po_w.cpp:147)
**Problem:** Null checks in both `getTxHeader()` overloads were commented out. Dereferencing null `mHeader` is undefined behavior.

**Fix:** Restored null checks with `std::runtime_error` throw.

##### 25. Null Pointer Dereference on getTip() (tx_po_w_generator.cpp:189)
**Problem:** `getTip()` may return null if the tree is empty. Immediately dereferenced without check.

**Fix:** Added null check with `std::runtime_error` throw.

##### 26. Null Pointer Dereference on deepCopy() (tx_po_w_miner.cpp:140, tx_po_w_generator.cpp:479)
**Problem:** `deepCopy()` can return `nullptr`. Result was immediately dereferenced via `std::move(*nullptr)`.

**Fix:** Added null checks before dereference.

##### 27. getAsInt() Truncation → reserve(SIZE_MAX) (mini_number.cpp:161)
**Problem:** `getAsInt()` masked to 32 bits then cast `uint32_t`→`int`. Values > `INT_MAX` became negative, which when passed to `reserve()` became `SIZE_MAX`, causing `std::length_error` or `std::bad_alloc`.

**Fix:** Now clamps to `INT_MAX`/`INT_MIN` instead of silent truncation.

##### 28. deleteFileOrFolder Prefix-Match Bypass (mini_file.cpp:389)
**Problem:** Prefix-match check allowed `/data/app` to match `/data/app_evil/secrets`. Empty `mParentCheck` allowed unconditional delete.

**Fix:** Rejects empty parent check. Appends path separator before prefix comparison. Canonicalizes both paths.

##### 29. Webhook SSRF (notify_manager.cpp:78)
**Problem:** User-controlled webhook URLs stored with zero validation. Attacker could register `http://169.254.169.254/` and exfiltrate all node events.

**Fix:** URL validation: HTTPS required for non-localhost, `@` rejected, max 2048 chars, regex-based URL parsing.

##### 30. POST Redirect Following SSRF (r_p_c_client.cpp:260)
**Problem:** POST requests followed redirects. Attacker-controlled URL could redirect to internal services, exfiltrating data via POST body.

**Fix:** Disabled redirect following for all POST requests.

#### HIGH

##### 31. Unauthenticated RPC Had Write Access (authorizer.cpp:173)
**Problem:** When `RPC_AUTHENTICATE` was false, user `minima` got **write** access with any password. Unauthenticated RPC could send funds and modify keys.

**Fix:** Unauthenticated RPC now gets **read** access only. Write requires `RPC_AUTHENTICATE=true` with valid `-rpcpassword`.

##### 32. Hardcoded Default DB Password "minima" (general_params.cpp:22)
**Problem:** `MAIN_DBPASSWORD = "minima"` — every node without explicit `-dbpassword` had its wallet encrypted with a publicly known key.

**Fix:** Default changed to empty string. Nodes must explicitly set `-dbpassword`.

##### 33. Hardcoded Default Passwords in restore/decryptbackup (restore.cpp:77, decryptbackup.cpp:63)
**Problem:** Both commands defaulted to password `"minima"` if none provided.

**Fix:** Password is now mandatory. Empty/missing password throws `CommandException`.

##### 34. RSA PKCS#1 v1.5 Padding (encrypt_decrypt.cpp:82)
**Problem:** `RSA_PKCS1_PADDING` is vulnerable to Bleichenbacher's chosen-ciphertext attack.

**Fix:** Encrypt uses `RSA_PKCS1_OAEP_PADDING`. Decrypt tries OAEP first, falls back to PKCS1v1.5 for backward compatibility with legacy data.

##### 35. AES-CBC Without Authentication (encrypt_decrypt.cpp:133)
**Problem:** All symmetric encryption used AES-CBC with no MAC. Ciphertext was malleable.

**Fix:** Added `encryptSYM_GCM`/`decryptSYM_GCM` using AES-GCM with 16-byte authentication tag. Legacy CBC functions preserved for backward compatibility.

##### 36. Self-Signed Cert Marked as CA (self_signed_cert_generator.cpp:165)
**Problem:** `addExt(cert, NID_basic_constraints, "critical,CA:TRUE")` marked the node's cert as a CA. If imported into any trust store, could sign arbitrary certificates.

**Fix:** Changed to `"critical,CA:FALSE"`.

##### 37. Keystore Empty Password Fallback (self_signed_cert_generator.cpp:228)
**Problem:** If `SSL_KEYSTORE_PASS` env var was not set, keystore was created with empty password.

**Fix:** Auto-generates a random 32-byte password via `RAND_bytes()` if env var is unset.

##### 38. Zip Archive DoS (zip_extractor.cpp:64,103)
**Problem:** No size limit on zip archives (memory exhaustion). No limit on entry count (zip bomb).

**Fix:** 100 MB max archive size, 10,000 max entry count.

#### Additional Null Guards (v1.0.105)
- `tx_po_w_generator.cpp:204` — `getMedianTimeBlock` null check
- `tx_po_w_generator.cpp:527` — `getParent` null check
- `tx_po_w_generator.cpp:694` — Empty vector guard in `getMedianTimeBlock`
- `tx_po_w_checker.cpp:449` — `getToken()` null checks
- `tx_po_w_processor.cpp:904` — `getRoot()` null check
- `n_i_o_message.cpp:1027` — `getRoot()` null check

---

### v1.0.106 — Idle-Findings Hardening + JSON Parser Restoration (15 fixes)

All fixes are safe, local, and non-consensus-breaking (no P2P protocol or block-format change). This closes the remaining MEDIUM/LOW audit findings plus a newly discovered CRITICAL defect in the JSON subsystem.

#### CRITICAL (newly discovered)

##### 39. JSON Parser Completely Non-Functional (yylex.cpp)
**Problem:** The JFlex DFA tables ported from json-simple's `Yylex.java` were corrupt, so the lexer returned EOF for every input and `JSONValue::parse()` returned an empty `std::any` for everything. JSON parsing — used by RPC command handling, `JsonDB`, `sql_db`, `greeting`, `n_i_o_message`, `mini_format`, `command_runner`, and `vault` — silently produced nothing. Two independent defects:
1. The packed tables (`ZZ_CMAP_PACKED`, `ZZ_ACTION_PACKED_0`, `ZZ_ROWMAP_PACKED_0`, `ZZ_ATTRIBUTE_PACKED_0`) are `u"..."` literals containing embedded `\0` chars; constructing `std::u16string` from the literal stops at the first NUL, leaving them empty → all transitions zero.
2. The raw `ZZ_TRANS` int array had 97 transcription errors and was missing 2 entries (673 vs. the original 675), so the DFA could not match `true`/`false`/`null` and other keyword paths.

**Fix:** Build the packed tables from `char16_t[]` arrays with an explicit `sizeof(...)/sizeof(char16_t) - 1` length; regenerated `ZZ_TRANS` from the upstream Java source. Verified byte-identical to the original `Yylex.java` (json-simple).

**Impact:** Restores JSON parsing across the node. JSON is not used in consensus-critical paths, so there is no consensus or P2P-format change. Previously, parsing could never succeed; the 10 MB size cap (M9) and 128-depth cap (M10) below are now effective and were verified against the working parser (depth-500 rejected, depth-127 accepted).

##### 40. Parsed JSON Object/Array Cannot Be Serialized (j_s_o_n_value.cpp)
**Problem:** `JSONValue::writeJSONString` handled `std::shared_ptr<JSONObject>` / `std::shared_ptr<JSONArray>` (the parser's storage form) only via the `shared_ptr<JSONAware>` / `shared_ptr<JSONStreamAware>` casts, which fail because `std::any` stores the exact type (no implicit up-cast). Serializing parsed output produced `<type-name>` instead of JSON.

**Fix:** Added explicit `std::any_cast<std::shared_ptr<JSONObject>>` and `std::any_cast<std::shared_ptr<JSONArray>>` cases that delegate to the concrete `writeJSONString`. Verified round-trip parse→serialize reproduces the original JSON.

#### MEDIUM

##### 41. Auth-Failure Tracking Map Unbounded (c_m_d_handler.cpp)
**Problem:** `recordAuthFailure()` inserted one entry per source IP without bound; a distributed attacker could exhaust memory.
**Fix:** `MAX_AUTH_TRACKED = 1024`; the map is pruned of expired entries once it exceeds the cap.

##### 42. Legacy Password Comparison Timing Leak (password_crypto.cpp)
**Problem:** The legacy (non-prefixed) password path compared candidate strings with `==`, leaking length/prefix via timing.
**Fix:** SHA256-digest both candidates, then compare the digests with `CRYPTO_memcmp`.

##### 43. MySQL Password Logged in Plaintext (my_s_q_l_connect.cpp)
**Problem:** Debug logging printed the MySQL password.
**Fix:** Redacted to `Password:********`.

##### 44. bad_any_cast Crashes getBoolean (message.cpp)
**Problem:** `Message::getBoolean()` cast without a type check; a malformed message crashed the handler.
**Fix:** Wrapped in try/catch; returns `false` on failure.

##### 45. JSON Input Size Unbounded (yylex.hpp, yylex.cpp)
**Problem:** The lexer buffered the entire input stream; a hostile RPC payload could exhaust memory.
**Fix:** `MAX_INPUT_SIZE = 10 MB`; `yyreset()` resets a byte counter and both read paths throw `ParseException("JSON input exceeds maximum size")` when exceeded.

##### 46. JSON Nesting Depth Unbounded (j_s_o_n_parser.cpp)
**Problem:** The parser accepted arbitrarily deep nesting (`[[[[...]]]]`) → unbounded deque/stack growth.
**Fix:** `MAX_JSON_DEPTH = 128`; `checkJsonDepth()` throws `ParseException("JSON nesting exceeds maximum depth")` at object/array open in both container and content-handler paths.

##### 47. _Exit(0) on OOM in fast_byte_array_stream.cpp
**Problem:** Hard process termination without cleanup on allocation failure.
**Fix:** Rethrow `std::bad_alloc` after logging.

##### 48. getLastMessage() Dangling Pointer (message_processor.cpp, systemcheck.cpp)
**Problem:** Returned a `const Message&` to a `std::shared_ptr` member that could dangle after the last reference dropped.
**Fix:** Returns `std::shared_ptr<Message>`; `systemcheck.cpp` updated to match.

##### 49. CORS Headers Joined Into One (c_m_d_handler.cpp)
**Problem:** Both `Access-Control-Allow-Origin` values were emitted as a single comma-joined header, which browsers reject — breaking CORS.
**Fix:** Two separate `Access-Control-Allow-Origin` headers (HTTP + HTTPS).

##### 50. isNetAvailable() Leaks IP to Google (p2_p_functions.cpp)
**Problem:** The connectivity probe resolved `www.google.com`, leaking the node IP to a third party.
**Fix:** Probes `1.1.1.1` instead.

##### 51. Hard exit() on NIO Bind Failure (n_i_o_server.cpp)
**Problem:** `std::exit(0)` on bind failure — no graceful shutdown, error not surfaced.
**Fix:** `Main::setStartUpError(...)` + `setHasShutDown()`, then `mIsRunning = false; return;`.

##### 52. Authorizer Forward-Declaration Shadowing (c_m_d_handler.cpp)
**Problem:** A local `class Authorizer;` forward declaration shadowed the real header, letting the real class API diverge silently.
**Fix:** Include `authorizer.hpp` and remove the local declaration.

#### LOW (documented, no code change)
- **sendGETHTTPS lacks auth headers** (`r_p_c_client.cpp`) — by design; `sendGETBasicAuthSSL` covers authenticated GET. Documented.
- **PBKDF2-SHA1 in javajs/aes_util.cpp** — unused Java-interop shim. Documented.
- **65,536 PBKDF2 iterations in generate_key.cpp** — cannot change without breaking existing backups (iteration count is fixed at backup creation). Documented.
- **Vault `;`-termination restriction** (`vault.cpp`) — functionally required by the command parser. Documented.
- **512 MB MiniData cap** (`mini_data.cpp`) — bounded and not reachable through normal RPC/P2P limits. Documented.
- **n_i_o_client.cpp:267 `mWriteStart = false`** — already correct (`bool` member). No change needed.

---

### v1.0.101 — Critical Security Fixes

### CRITICAL

#### 1. RPC Authentication Bypass (c_m_d_handler.cpp:359-368)
**Problem:** The RPC handler initialized `authuser` with `"valid": true` and `"mode": "write"` by default. Authentication was only checked if `RPC_AUTHENTICATE` was enabled or RPC users were configured. In the default configuration, every HTTP request was treated as fully authenticated with write access.

**Fix:** Default to `"valid": false` and `"mode": "read"`. Access is only granted after successful credential verification.

#### 2. Read/Write Authorization Mode Never Enforced (c_m_d_handler.cpp:408-419)
**Problem:** The RPC system supported a `mode` field (`"read"` or `"write"`) for per-user authorization, but the mode was never checked in the command execution path. A user created with `mode:read` still had full write access to all commands including `send`, `vault`, `backup`, and `quit`.

**Fix:** Added a write-command whitelist check after authentication. Commands like `send`, `vault`, `backup`, `quit`, etc. require `mode: "write"`. Read-only users receive a 403 Forbidden response.

#### 3. Seed Phrase Exposed Without Authentication (vault.cpp:127-139)
**Problem:** The `vault` command with `action:seed` returned the BIP39 seed phrase and raw seed bytes without any password requirement. Combined with the RPC auth bypass, any website could steal the seed phrase via a single CORS request.

**Fix:** 
- Added `vault action:status` — safe read-only check (no password needed)
- `vault action:seed` now requires a password if the seed is locked
- Added `vault action:export` — encrypts seed phrase with password to a file
- Added `vault action:import` — restores seed phrase from an encrypted export file

#### 4. Mersenne Twister Used for Cryptographic Random Data (mini_data.cpp:361-362, wallet.cpp:529-530)
**Problem:** `MiniData::getRandomData()` used `std::mt19937` (Mersenne Twister) seeded with `std::random_device` for generating random bytes. Mersenne Twister is not cryptographically secure — its state can be recovered after observing 624 outputs. This function is used for generating nonces, secrets, and random identifiers throughout the codebase.

**Fix:** Replaced with OpenSSL's `RAND_bytes()`, which is a CSPRNG. Also replaced the time-seeded `std::mt19937` in `Wallet::getDefaultAddress()` with `RAND_bytes()`.

#### 5. TLS Certificate Validation Always Disabled (minima_r_p_c_client.cpp:408-413)
**Problem:** `SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, nullptr)` was called in both branches (with and without a pin), completely disabling server certificate validation. This enables MITM attacks on all HTTPS connections.

**Fix:** Changed to `SSL_VERIFY_PEER` with default CA certificate paths loaded. Pin verification still occurs after the TLS handshake for additional security.

#### 6. Wildcard CORS Allows Any Origin (c_m_d_handler.cpp:485)
**Problem:** `Access-Control-Allow-Origin: *` permitted any website to make cross-origin requests to the RPC server. Combined with the default unauthenticated state, a malicious website could execute arbitrary commands and exfiltrate the seed phrase.

**Fix:** Restricted to `http://localhost, https://localhost`.

#### 7. Path Traversal in File Operations (mini_file.cpp:56-73)
**Problem:** `createBaseFile()` accepted user-controlled paths containing `/` or `\` without sanitization. An attacker could read or write arbitrary files on the filesystem via commands like `backup file:../../../etc/passwd`.

**Fix:** 
- Reject paths containing `..` components
- Strip leading slashes to prevent absolute path interpretation
- Canonicalize the resolved path and verify it stays within the base folder

#### 8. HTTP POST Body Size Unbounded (c_m_d_handler.cpp:425)
**Problem:** The `Content-Length` header value was used directly to resize the body buffer with no maximum size check. An attacker could send `Content-Length: 2147483647` causing an OOM crash.

**Fix:** Added a 10 MB maximum POST body size limit. Requests exceeding this receive a 413 Payload Too Large response.

#### 9. HTTP Header Line Length Unbounded (c_m_d_handler.cpp:130-158)
**Problem:** The `readLine()` function read one byte at a time with no maximum line length. An attacker could send a multi-gigabyte header line without a newline, causing unbounded memory growth.

**Fix:** Added an 8 KB maximum header line length. Lines exceeding this throw an exception.

#### 10. NIOClient Uninitialized Members (n_i_o_client.cpp:145-155)
**Problem:** The outgoing `NIOClient` constructor left 20+ members uninitialized (`mSocketOpen`, `mInSize`, `mOutSize`, `mTimeConnected`, `mMinimaPort`, etc.). Calling `handleRead()` or `handleWrite()` on such an object would read garbage values.

**Fix:** All members are now explicitly initialized in both constructors.

---

### HIGH

#### 11. Timing-Vulnerable Password Comparison (authorizer.cpp:163,179)
**Problem:** Password comparison used `std::string::operator==`, which returns early on the first mismatched byte, leaking password length and prefix information through timing.

**Fix:** Replaced with OpenSSL's `CRYPTO_memcmp()` for constant-time comparison.

#### 12. Hardcoded Default Password "password" (minima_r_p_c_client.cpp:600)
**Problem:** The RPC client defaulted to password `"password"` if none was provided via `-password` flag.

**Fix:** Removed the default password. The password field is now empty by default and must be explicitly provided.

#### 13. Basic Auth Over Cleartext HTTP (minima_r_p_c_client.cpp:346-391)
**Problem:** `http_request_basic_auth()` sent credentials over unencrypted HTTP without any warning.

**Fix:** Added a warning log message when credentials are sent over cleartext HTTP.

#### 14. Keystore Password in Unprotected Sidecar File (s_s_l_manager.cpp:339-342)
**Problem:** The SSL keystore password was written to a `.pass` sidecar file with default file permissions, readable by any user on the system.

**Fix:** The `writeTextFile()` function now sets file permissions to `owner_read | owner_write` only (0600).

#### 15. Hard Termination via std::exit(0) / std::_Exit(0) (minima_d_b.cpp:419, c_m_d_handler.cpp:508, main.cpp:844)
**Problem:** Multiple code paths called `std::exit(0)` or `std::_Exit(0)`, terminating the process without graceful shutdown — no DB cleanup, no socket closure, no state persistence.

**Fix:** Replaced with calls to `Main::setHasShutDown()` and `Main::setStartUpError()` for graceful shutdown.

---

## New Vault Workflow

### Safe Seed Phrase Management

The `vault` command has been redesigned with security as the primary concern:

#### Check Status (safe, no password needed)
```
vault action:status
```
Returns whether the seed is locked and whether an encrypted backup exists.

#### View Seed Phrase (requires password if locked)
```
vault action:seed password:your_strong_password
```
If the seed is locked (encrypted at rest), the password is required and verified before showing the seed phrase.

#### Export Encrypted Seed (recommended for backup)
```
vault action:export password:your_strong_password file:seed-backup.enc
```
Encrypts the seed phrase with AES password-based encryption and writes it to a file. The file can be stored offline.

#### Import Encrypted Seed (restore from backup)
```
vault action:import password:your_strong_password file:seed-backup.enc
```
Decrypts the export file, verifies the seed matches the phrase, and restores private keys.

#### Lock Node (encrypt seed at rest)
```
vault action:passwordlock password:your_strong_password
```
Encrypts the seed phrase and wipes the plaintext from SQLite. The seed is only recoverable with the password.

#### Unlock Node (restore from encrypted seed)
```
vault action:passwordunlock password:your_strong_password
```
Decrypts the stored encrypted seed and restores private keys.

### Recommended Workflow for New Nodes

1. **Start the node** — a seed phrase is auto-generated
2. **Immediately export:** `vault action:export password:STRONG_PASSWORD file:seed-backup.enc`
3. **Store the export file offline** (USB drive, paper backup of password)
4. **Lock the node:** `vault action:passwordlock password:STRONG_PASSWORD`
5. **Verify:** `vault action:status` should show `locked: true`

### Recommended Workflow for Restoring a Node

1. **Start a fresh node**
2. **Import:** `vault action:import password:STRONG_PASSWORD file:seed-backup.enc`
3. **Verify:** `vault action:status` should show `locked: false`
4. **Lock again:** `vault action:passwordlock password:STRONG_PASSWORD`

---

## RPC Security Configuration

### Enabling RPC Securely

```bash
# Start with RPC enabled and authentication required
./minima -rpcenable -rpcpassword "STRONG_UNIQUE_PASSWORD"
```

### Creating Read-Only RPC Users

```
rpc action:newuser username:monitor password:readonly_pass mode:read
```

Read-only users can execute query commands (status, balance, history, etc.) but cannot send funds, modify keys, or change configuration.

### RPC Best Practices

1. Always use `-rpcpassword` when enabling RPC
2. Use HTTPS (`-rpcssl`) for production deployments
3. Create read-only users for monitoring/observability
4. Never expose RPC to the public internet without TLS and authentication
5. Use the CLI directly for sensitive operations (vault, backup, send)

---

### v1.0.103 — Cascade Chain Validation Fixes

#### HIGH

##### 19. SuperLevel -1 Bypasses All Validation (tx_po_w.cpp:732-735)
**Problem:** `calculateTXPOWID()` clamps `mSuperBlock >= 32` to `31`, but `getSuperLevel()` can return `-1` (when `tid == 0` or `quot == 0`). A block with `mSuperBlock = -1` passes through unclamped. In both `cascadeChain()` and `checkParents()`, the condition `superlevel >= blocksup` with `superlevel = -1` is always **false**, causing the node to be skipped entirely — its parent relationship is never verified.

**Fix:** Added lower bound clamp: `if (mSuperBlock < 0) mSuperBlock = 0;`

##### 20. getSuperParent/setSuperParent No Bounds Check (tx_po_w.cpp:351-358)
**Problem:** `getSuperParent(int zLevel)` and `setSuperParent(int zLevel, ...)` use `mSuperParents[zLevel]` with no bounds check. The vector has `MINIMA_CASCADE_LEVELS` (32) elements. An out-of-range `zLevel` causes undefined behavior (out-of-bounds vector access).

**Fix:** Added bounds check at the top of both functions, throwing `std::out_of_range` for invalid indices.

##### 21. Dangling Raw Pointer in checkParents Tree Walk (tx_po_w_checker.cpp:801-802)
**Problem:** The tree walk stores `current = parent.get()` where `parent` is a temporary `shared_ptr` that goes out of scope each loop iteration. On the next iteration, `current` is a raw pointer to a node that may have been destroyed if all other shared_ptr references were dropped (e.g., during concurrent tree recalculation).

**Fix:** Changed the walk variable from raw pointer `TxPoWTreeNode*` to `std::shared_ptr<TxPoWTreeNode>`, keeping the node alive for the entire walk.

##### 22. Loop Index Bug in checkParents (tx_po_w_checker.cpp:854)
**Problem:** Final loop checking unused super parent slots used `blocksup` (stale count) instead of loop variable `i`, only checking the first unused slot instead of all remaining ones.

**Fix:** Changed `zBlock.getSuperParent(blocksup)` to `zBlock.getSuperParent(i)`.

---

### v1.0.104 — Safe Non-Consensus-Breaking Hardening

All fixes in this release are local to a single node (no P2P format or consensus change), so they can be deployed unilaterally without a coordinated network upgrade.

#### HIGH

##### 23. OperatorExpression Systematic Memory Leak (org/minima/kissvm/)
**Problem:** `Value::getValue()` returns a heap-allocated `Value` that callers own. In `OperatorExpression`, `BooleanExpression`, `Contract`, the control-flow statements (`if`, `while`, `return`, `assert`, `exec`, `mast`), and the `SHA2`, `SHA3`, `MAX`, `MIN`, `LEN`, `CONCAT`, `FUNCTION`, `EXISTS`, `BOOL`, `HEX`, `NUMBER`, `STRING` functions, the returned value was stored in a raw pointer and never `delete`d. Every executed KISSVM expression leaked its result, so memory grew without bound under sustained contract/script execution.

**Fix:** All `getValue()` results are now held in `std::unique_ptr<Value>`, guaranteeing release on every path including exceptions.

##### 24. RPC User Passwords Stored in Plaintext (rpc.cpp)
**Problem:** `rpc action:adduser` stored the RPC user password as plaintext in the SQLite userprefs database. Any party with file-system access to the data directory could read every RPC credential.

**Fix:** Passwords are now stored as a salted PBKDF2-HMAC-SHA256 hash (`pbkdf2$<iter>$<salt-hex>$<hash-hex>`, 100k iterations, 16-byte salt). `Authorizer::checkAuchCredentials` verifies the supplied password against the hash in constant time and transparently migrates legacy plaintext entries to hashed form on their first successful login.

##### 25. Unbounded IBD Pending Message Queues (n_i_o_message.cpp)
**Problem:** During IBD the node appended to `mPendingTxPowIDsDuringIBD` and `mPendingTxBlockIDsDuringIBD` without any limit. A peer could stream an unbounded number of messages, exhausting memory.

**Fix:** Both vectors are capped at `MAX_PENDING_IBD` (8192). Excess messages are dropped with a log entry.

##### 26. Network Topology Fully Exposed via Single Ping (p2_p_greeting.cpp)
**Problem:** A single `PING`/greeting response advertised the node's entire known-peer list, letting a new peer harvest the full network topology in one request.

**Fix:** Greetings now advertise at most `MAX_SHARED_PEERS` (20) peers, chosen by shuffle so each requester sees a different random subset. (Consensus-breaking DHT/anti-Sybil redesigns remain deferred.)

#### MEDIUM

##### 27. Auth Attempt Rate Limiting (c_m_d_handler.cpp)
**Problem:** No limit on failed authentication attempts, allowing online password guessing against the RPC endpoint.

**Fix:** Per-source-IP failure counting with `MAX_AUTH_FAILURES` = 5 within a 15-minute window; excess failures return `429 Too Many Requests`. Successful authentication clears the failure count for that source.

##### 28. Backup Default Password "minima" (backup.cpp:116)
**Problem:** `backup` command defaulted to the hardcoded password `"minima"` when none was supplied, silently producing a trivially decryptable backup.

**Fix:** Password is now mandatory; empty/missing password is rejected.

##### 29. MAX_MESSAGE 256MB Excessively Large (n_i_o_client.hpp:31)
**Problem:** The per-message size limit of 256MB permitted a single malicious message to trigger a multi-hundred-MB allocation.

**Fix:** `MAX_MESSAGE` reduced to 16MB, still far above the largest legitimate message.

---

## Remaining Known Issues

The following issues remain and require **coordinated network upgrades** (changing them would partition the network), plus one deferred internal hardening:

| Severity | Issue | Location | Status |
|----------|-------|----------|--------|
| CRITICAL | No PoW required for P2P peer connections (Sybil at zero cost) | p2_p_peers_checker.cpp | Deferred (network-breaking) |
| CRITICAL | No signature verification on P2P control messages | p2_p_manager.cpp | Deferred (network-breaking) |
| HIGH | No nonce/sequence validation on P2P WalkLinks/DoSwap | p2_p_walk_links.cpp, p2_p_do_swap.cpp | Deferred (network-breaking) |
| HIGH | Wallet seed/private keys stored as plaintext in SQLite | wallet.cpp | Partially mitigated — `vault action:passwordlock` wipes keys (`0x00`) and zeroes the seed on disk; full SQLite at-rest encryption not implemented |
| HIGH | Cascade `mTip` raw pointer invalidated on vector resize | cascade.cpp | Deferred — internal `shared_mutex` would deviate from the Java-parity ReentrantReadWriteLock already held at the `MinimaDB` level (`minima_d_b.cpp`, used by `tx_po_w_processor.cpp`); revisited if a concrete race is reproduced |

### Fixed in v1.0.104
- ~~Unbounded IBD pending message queues~~ → `MAX_PENDING_IBD` = 8192 (`n_i_o_message.cpp`)
- ~~OperatorExpression systematic memory leak~~ → `std::unique_ptr<Value>` ownership (`org/minima/kissvm/`)
- ~~Network topology fully exposed via single ping~~ → Random 20-peer greeting subset (`p2_p_greeting.cpp`)
- ~~RPC user passwords stored in plaintext JSON in SQLite~~ → PBKDF2-HMAC-SHA256 salted hash (`password_crypto.cpp`, `rpc.cpp`, `authorizer.cpp`)
- ~~256MB MAX_MESSAGE excessively large~~ → 16MB (`n_i_o_client.hpp`)
- ~~No rate limiting on authentication attempts~~ → 5 failures / 15 min per IP, 429 response (`c_m_d_handler.cpp`)
- ~~Backup default password "minima"~~ → Password now mandatory (`backup.cpp`)

### Fixed in v1.0.103
- ~~SuperLevel -1 bypasses all validation~~ → Lower-bound clamp `mSuperBlock < 0 → 0` (`tx_po_w.cpp`)
- ~~getSuperParent/setSuperParent no bounds check~~ → `std::out_of_range` guard (`tx_po_w.cpp`)
- ~~Dangling raw pointer in checkParents tree walk~~ → `std::shared_ptr<TxPoWTreeNode>` walk (`tx_po_w_checker.cpp`)
- ~~Loop index bug in checkParents~~ → `getSuperParent(i)` (`tx_po_w_checker.cpp`)

### Fixed in v1.0.102
- ~~Race conditions on Main shutdown/sync boolean flags~~ → Converted to `std::atomic<bool>`
- ~~Singleton raw pointers without atomic synchronization~~ → Mitigated by single-threaded initialization; full fix requires `std::call_once`
- ~~MDS/Maxima dead code residuals~~ → All removed

---

## Build Verification

After applying these fixes, rebuild and verify:

```bash
rm -rf build && mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j$(sysctl -n hw.ncpu)
```

Run existing tests (test targets are `EXCLUDE_FROM_ALL`; build them explicitly):
```bash
cd build
make test_winternitz test_sha3 test_serialization
./test_winternitz
./test_sha3
./test_serialization
```
