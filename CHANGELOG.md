# Changelog

All notable changes to the **SecretProtector** project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.0.6] - 2026-11-12

### Added
- **Raw Key Generation API & CLI**: Added `GenerateKeyBytes() ([]byte, error)` (32 CSPRNG bytes) and `GenerateRawKey() (string, error)` / CLI `-generate-raw` (32-character CSPRNG Base64URL string with 192 bits of entropy) so callers can generate strong raw or hex master keys directly via `secretprotector`.
- **Optional Additional Authenticated Data (AAD)**: Added `EncryptWithAAD`, `DecryptWithAAD`, `EncryptBytesWithAAD`, and `DecryptBytesWithAAD` to cryptographically bind ciphertext to contextual metadata while preserving full compatibility with existing `v1:gcm:` payloads (`aad = nil`).
- **Explicit Version Rejection**: Added `ErrUnsupportedVersion` to distinguish unknown `v<N>:<alg>:` ciphertext format prefixes from corrupted payloads.
- **CLI Raw Decryption Output**: Added `-raw` flag to suppress the trailing newline when decrypting secrets for binary or exact-match pipelines.

### Changed
- **CLI Flag Precedence**: Explicit CLI `-key-file` now takes priority over the ambient default `SECRETPROTECTOR_MASTER_KEY` environment variable unless `-key-env` is specified explicitly (`libsecsecrets.ResolveKey` retains `raw > env > file` precedence for Go library callers).
- **Key Parsing Hygiene**: Consolidated key parsing, stripped only CRLF (`\r\n`) or LF (`\n`) line endings for printable-ASCII (`0x20..0x7E`) 32-byte text keys, and rejected `>32`-byte space-padded, standalone-`\r`, and non-printable binary files ending in `\n`/`\r\n` instead of silently truncating them. `IsEncrypted` and `IsEncryptedBytes` trim surrounding ASCII whitespace consistently.
- **Isolated Dependency Injection**: Replaced exported mutable mock globals and `sync.RWMutex` locking in `pkg/libsecsecrets` with unexported `sysDeps` injection (`cliDeps` + `flag.FlagSet` via `runCLI` in the CLI), eliminating global mutable test hooks and enabling lock-free parallel execution.
- **Context Safety**: Guarded `ctx.Err()` checks in `libsecsecrets` against `nil` `context.Context` values.

### Security
- **TOCTOU-Hardened Single-Open Key Reading**: Replaced `os.Stat` + `os.ReadFile` with a single `os.Open` + `f.Stat()` handle check, regular-file enforcement (`IsRegular()`), and bounded reading (`4096` bytes max for keys; `10 MiB` max for CLI stdin secrets).
- **Unix Ownership & Special Bit Validation**: Enforced effective-UID ownership matching (`syscall.Stat_t.Uid == os.Geteuid()`) alongside `0400`/`0600` mode enforcement and rejection of setuid, setgid, and sticky bits on Unix systems.
- **Windows Path & Symlink Hardening**: Canonicalized Windows key paths via `filepath.EvalSymlinks` (failing closed on symlink resolution errors) before validating exact path-segment boundaries (`Public`, `Temp`, `tmp`).

### Fixed
- **CLI Argument & Exit Code Handling**: Bare invocation, unexpected positional arguments, `-raw` outside `-decrypt`, `-version` combined with other actions, and empty `-encrypt` / `-decrypt` strings now reliably return `ExitUsageError` (`2`). Missing/unreadable key files and stdin/stdout stream errors consistently map to `ExitIOError` (`5`) with stderr diagnostics.

---

## [0.0.5] - 2026-11-11

### Added
- **Provider Architecture Roadmap**: Expanded `DESIGN.md` with the 3-tier `ChainedProvider` vault architecture specification (OS Keyring, Age/PKCS#12 File Vaults, and Cloud KMS / HashiCorp Vault).
- **Automated Dependency Maintenance**: Added `.github/dependabot.yml` for weekly Go module dependency updates.

### Changed
- **Build Metadata Migration**: Migrated build and package configuration from `version.txt` and `main.txt` to `build.json`.

### Fixed
- **Binary Master Key File Resolution**: Preserved exact 32-byte raw master key files loaded from disk without destructive `strings.TrimSpace` stripping of leading or trailing `0x20` whitespace bytes, while retaining support for newline-terminated 64-character hex text key files.

---

## [0.0.4] - 2026-08-04

### Changed
- **Version bump**: Re-released v0.0.3 changes as v0.0.4 due to Go module proxy caching issue.

---

## [0.0.3] - 2026-08-04

### Changed
- **v1:gcm: Encrypted Prefix**: `Encrypt()`/`EncryptBytes()` now output `v1:gcm:<base64>` format for versioned algorithm identification. `Decrypt()`/`DecryptBytes()` accept both prefixed and raw base64 for backwards compatibility.
- **IsEncrypted() Helper**: Added `IsEncrypted(string)` and `IsEncryptedBytes([]byte)` to check for `v1:gcm:` prefix.

---

## [0.0.2] - 2026-07-30

### Added
- **Granular Diagnostic Exit Codes**: Defined explicit status codes in `cmd/secretprotector` to simplify automation and SecOps failure diagnostics:
  - `0` (`ExitSuccess`): Clean execution.
  - `2` (`ExitUsageError`): Invalid arguments or mutually exclusive flag combinations.
  - `3` (`ExitKeyResolutionError`): Unresolved master key or file permission check failure.
  - `4` (`ExitCryptoError`): Base64 decoding, MAC tag verification failure, or AES-GCM decryption error.
  - `5` (`ExitIOError`): I/O failure when reading key files or streaming standard input.
- **Unix Stdin Pipeline Integration**: Added support for reading secrets and key files directly from standard input via `-` (`-encrypt -`, `-decrypt -`, `-key-file -`).
- **Zeroable Byte-Slice Primitives**: Introduced `EncryptBytes` and `DecryptBytes` in `pkg/libsecsecrets` to enable caller-managed memory hygiene via `ZeroBuffer`.
- **E2E Binary Process Test Suite**: Added `cmd/secretprotector/e2e_integration_test.go` to compile the executable and test full binary process lifecycles, stdin pipes, and exit codes.
- **Process Listing Exposure Warnings**: Added stderr warnings when passing sensitive master keys (`-key`) or plaintext secrets (`-encrypt`) directly as CLI flags.

### Changed
- **Zero-Allocation Base64 Trimming**: Updated `DecryptBytes` to use `bytes.TrimSpace` on byte slices, eliminating heap string allocations during decryption.
- **CLI Flag Validation**: Enforced strict mutual exclusivity checks across action flags (`-generate`, `-encrypt`, `-decrypt`) and prevented simultaneous stdin reads (`-encrypt - -key-file -`).

### Security
- **Thread-Safe Mock Synchronization**: Replaced package-level global mock mutations with internal `RWMutex` synchronization in `libsecsecrets.go`, eliminating data races during parallel test execution.
- **Hardened Windows Path Validation**: Refined `validateFilePermissions` using `filepath.Clean` and `filepath.Abs` prefix checking against restricted root directories (`C:\Users\Public`, `%TEMP%`).

### Documentation
- Updated `README.md`, `TESTING.md`, and `ARCHITECTURE.md` to document diagnostic exit codes, stdin pipe usage, byte-slice APIs, and E2E test suites.

---

## [0.0.1] - 2026-03-20

### Added
- **Core Cryptographic Engine (`pkg/libsecsecrets`)**:
  - Implemented AES-256-GCM authenticated encryption (`Encrypt`, `Decrypt`).
  - CSPRNG key generation (`GenerateKey`) utilizing `crypto/rand` and `sync.Pool` for 32-byte key buffer management.
  - Memory zeroing utility (`ZeroBuffer`) to clear sensitive key slices from RAM.
- **Hierarchical Master Key Resolution (`ResolveKey`)**:
  - Precedence order: CLI Flag (`-key`) > Environment Variable (`SECRETPROTECTOR_MASTER_KEY`) > Key File (`-key-file`).
- **Platform Security Boundary Enforcement**:
  - Linux/Unix: Enforced owner-only file permissions (`0400` or `0600`).
  - Windows: Blocked key files in volatile/public directories (`Public`, `Temp`).
- **CLI Utility (`cmd/secretprotector`)**:
  - Administrative tool supporting `-generate`, `-encrypt`, `-decrypt`, and version reporting.
- **Documentation & Examples**:
  - Integration guide (`SAMPLEAPP.md`), architecture specifications (`ARCHITECTURE.md`, `DESIGN.md`), and unit test suite (`TESTING.md`).

---

## [0.0.0] - 2026-03-18

### Added
- Initial project structure, module definition (`go.mod`), and baseline implementation.
