# Changelog

All notable changes to the **SecretProtector** project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
