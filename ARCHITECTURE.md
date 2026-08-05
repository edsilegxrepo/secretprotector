# Architecture & Design: SecretProtector

This document outlines the architectural decisions, design patterns, data flow, control logic and dependencies for the SecretProtector system.

## 1. System Overview

SecretProtector is a professional-grade secret management system designed to eliminate the storage of plaintext passwords on disk or in version control. It consists of three primary layers (using an SFTP client as a common example):
1.  **Core Library (`pkg/libsecsecrets`):** The cryptographic engine.
2.  **CLI Tool (`cmd/secretprotector`):** The administrative interface for key and secret management.
3.  **Application Layer:** Integration via a "Bootstrap" sequence for runtime decryption.

## 2. Architecture & Design Choices

### 2.1 Cryptographic Standard
- **AES-256-GCM (Galois/Counter Mode):** Chosen for authenticated encryption. It provides both confidentiality and integrity, ensuring that any tampering with the ciphertext or nonce will be detected during decryption.
- **Randomness:** Uses `crypto/rand` for cryptographically secure pseudo-random number generation (CSPRNG) for both 32-byte keys and GCM nonces.
- **Memory Security (Zeroing):** All sensitive buffers (Master Keys, Plaintext) are explicitly zeroed out after use using the `ZeroBuffer` utility to minimize the window of exposure in memory.

### 2.2 Package Structure
The project uses a standard Go layout:

```text
secretprotector
├── cmd/
│   └── secretprotector/
│       ├── main.go           # CLI Tool
│       ├── main_test.go      # Integration tests
│       └── e2e_integration_test.go # E2E binary tests
├── pkg/
│   └── libsecsecrets/
│       ├── libsecsecrets.go  # Core Logic
│       └── libsecsecrets_test.go # Unit tests
├── ARCHITECTURE.md           # Technical design
├── CHANGELOG.md              # Project changelog
├── DESIGN.md                 # Specification
├── README.md                 # User guide
├── SAMPLEAPP.md              # Developer integration guide
├── TESTING.md                # Test suite & coverage
└── go.mod
```

- `pkg/`: Internal library code that can be imported by other projects.
- `cmd/`: Entry points for executables.
- **Single Module:** All components reside in `criticalsys/secretprotector` to ensure atomic updates and simplified dependency management.

### 2.3 Key Resolution Strategy
The system implements a hierarchical precedence model for Master Key resolution:
1.  **Direct Input (Flag):** Highest priority for temporary overrides or testing. Supports 64-character hex or 32-byte raw strings.
2.  **Environment Variable:** Standard for CI/CD pipelines and containerized environments. Supports 64-character hex or 32-byte raw strings.
3.  **File Path:** Standard for on-premise deployments or hardware-backed secrets. Supports 64-character hex or 32-byte raw strings (including stdin `-`).

### 2.4 Platform Security Boundaries
- **Linux/Unix:** Enforces `0400` (Read-Only Owner) or `0600` (Read-Write Owner) permissions on key files to prevent unauthorized local access.
- **Windows:** Implements "Insecure Location" detection, preventing the use of master keys stored in shared or volatile directories like `Public` or `\temp\`.

### 2.5 Resource Management & Performance
- **Sync Pool Optimization:** The library utilizes `sync.Pool` for managing sensitive byte slices (e.g., during key generation). This reduces garbage collection (GC) overhead and ensures that buffers are securely zeroed before being returned to the pool.
- **Context Propagation:** All primary API functions (`ResolveKey`, `Encrypt`, `Decrypt`, `EncryptBytes`, `DecryptBytes`) accept `context.Context`, allowing for cancellation support and better integration with modern Go application lifecycles.
- **Custom Error Architecture:** Instead of generic errors, the system uses a structured set of exported error types (e.g., `ErrInvalidKey`, `ErrInsecureLocation`, `ErrNoKeySource`, `ErrInsecurePermissions`, `ErrCiphertextTooShort`) to allow for predictable programmatic error handling by consumers.

### 2.6 System Assumptions
1.  **Entropy Boundary:** Master keys contain 256 bits of entropy (represented as 64-character hex strings or 32 raw bytes).
2.  **Kernel CSPRNG:** Operating system entropy sources (`/dev/urandom`, `RtlGenRandom`) are securely initialized by the OS kernel.
3.  **Local Access Control:** Host OS restricts local access to key files via user profiles or owner-only permission bits (`0400`/`0600`).

### 2.7 Edge Cases & Resiliency
- **Stdin Collision Prevention:** Rejects simultaneous reading of both secret payload (`-encrypt -` / `-decrypt -`) and master key (`-key-file -`) from `os.Stdin` with diagnostic exit code `2` (`ExitUsageError`).
- **Zero-Allocation Byte Trimming:** Automatically trims whitespace and newlines from base64 input using `bytes.TrimSpace` without allocating heap strings.
- **Insecure File Location Block:** Canonicalizes paths (`filepath.Abs`, `filepath.Clean`) and rejects master keys stored in insecure/shared paths (`C:\Users\Public`, `%TEMP%`) with diagnostic exit code `3` (`ExitKeyResolutionError`).

### 2.8 High-Level Architecture Diagram

```mermaid
graph TB
    subgraph AdminLayer["Administrative / Operational Layer"]
        CLI["CLI Tool (cmd/secretprotector)"]
        Flags["Flag Parser & Stdin Reader"]
    end

    subgraph CoreLibrary["Core Cryptographic Library (pkg/libsecsecrets)"]
        KeyResolver["Key Resolver (ResolveKey)"]
        AESGCMEngine["AES-256-GCM Engine"]
        MemManager["Memory & Pool Manager (sync.Pool / ZeroBuffer)"]
        SecurityEnforcer["OS Permission & Path Validator"]
    end

    subgraph ExternalSystems["Operating System & Storage"]
        CSPRNG["Kernel CSPRNG (crypto/rand)"]
        EnvVars["Environment Variables"]
        KeyFiles["Filesystem Key Storage"]
        StdinPipe["Unix Stdin / Pipeline"]
    end

    CLI --> Flags
    Flags --> KeyResolver
    Flags --> AESGCMEngine
    KeyResolver --> SecurityEnforcer
    SecurityEnforcer --> KeyFiles
    KeyResolver --> EnvVars
    KeyResolver --> StdinPipe
    AESGCMEngine --> CSPRNG
    AESGCMEngine --> MemManager
```

## 3. Operational Workflow

1.  **Provisioning:** Admin runs `secretprotector -generate` to create a Master Key.
2.  **Deployment:** The Master Key is stored in an environment variable or a protected file.
3.  **Obfuscation:** Secrets (such as SFTP passwords, API keys, or DB credentials) are encrypted using the CLI and stored in configuration files as Base64 strings.
4.  **Runtime:** The application resolves the Master Key at startup, decrypts the secret into memory, and proceeds with the operation without ever writing the plaintext to disk.

## 4. Data Flow & Control Logic

### 4.1 Operational Flow
The following diagram illustrates the lifecycle of a secret, from master key generation to runtime decryption.

```mermaid
graph TD
    subgraph Provisioning
        A[Admin] -->|generate| B("CLI: secretprotector -generate")
        B -->|crypto/rand| C[Master Key: 32-byte Hex]
    end

    subgraph Deployment
        C -->|Store| D{Storage Strategy}
        D -->|Option 1| E[Env: SECRETPROTECTOR_MASTER_KEY]
        D -->|Option 2| F["File: /etc/secrets/key.txt"]
    end

    subgraph Obfuscation
        G[Plaintext Secret] -->|encrypt| H("CLI: secretprotector -encrypt")
        E & F -.->|ResolveKey| H
        H -->|AES-256-GCM| I[v1:gcm: Ciphertext]
    end

    subgraph Runtime
        I -->|Config| J[Target Application]
        E & F -.->|ResolveKey| K(pkg/libsecsecrets)
        J -->|Decrypt| K
        K -->|Return| L[Plaintext in Memory]
    end
```

### 4.2 Key Resolution Sequence
The `ResolveKey` function implements the following priority logic:

```mermaid
sequenceDiagram
    autonumber
    participant App as Application/CLI
    participant Lib as pkg/libsecsecrets
    participant Env as Environment Variables
    participant File as Filesystem

    App->>Lib: ResolveKey(ctx, flag, envName, filePath)
    alt Flag is provided
        Lib-->>App: Return Flag Value
    else Env Name exists
        Lib->>Env: Lookup envName
        Env-->>Lib: Return Value
        Lib-->>App: Return Env Value
    else File Path is provided
        Lib->>File: Read filePath
        File-->>Lib: Return Content
        Lib-->>App: Return File Content
    else No source found
        Lib-->>App: Return Error
    end
```

## 5. Performance & Scalability

### 5.1 Concurrency Model
- **Stateless Thread Safety**: All core cryptographic functions (`Encrypt`, `Decrypt`, `EncryptBytes`, `DecryptBytes`) are fully thread-safe and re-entrant, allowing concurrent invocation across goroutines without lock contention.
- **RWMutex Synchronization**: Test mocks inside `libsecsecrets.go` utilize `sync.RWMutex` (`mockMu`) to allow concurrent parallel test runs (`t.Parallel()`) without data races.

### 5.2 Channel & Pipeline Structures
- **Non-Blocking Unix Pipelines**: Stdin ingestion utilizes `io.ReadAll(os.Stdin)` for Unix pipe chaining (e.g., `cat secret.txt | secretprotector -encrypt -`), delivering maximum throughput for batch processing scripts.

### 5.3 Memory Pool Management
- **Buffer Recycling**: `bytePool` (`sync.Pool`) manages temporary 32-byte buffers during random key generation, ensuring zeroed buffer recycling and reducing garbage collector overhead under heavy load.

## 6. Dependencies

### 6.1 Standard Library
The implementation relies exclusively on the Go standard library to minimize the attack surface and ensure maximum portability:
- `crypto/aes`, `crypto/cipher`: For encryption/decryption logic.
- `crypto/rand`: For secure random data.
- `encoding/hex`, `encoding/base64`: For data serialization.
- `os`, `flag`: For CLI interactions and system integration.
- `bytes`, `strings`, `sync`, `context`, `errors`: For memory hygiene, concurrency control, and diagnostic error handling.

### 6.2 External Dependencies
None. This project is intentionally designed with **Zero External Dependencies** to facilitate security audits and prevent supply-chain vulnerabilities.

### 6.3 Package Dependency Architecture

```mermaid
graph LR
    subgraph Executable["Executable Entry Points"]
        CMD["cmd/secretprotector"]
    end

    subgraph InternalPkg["Internal Packages"]
        LIB["pkg/libsecsecrets"]
    end

    subgraph StdLib["Go Standard Library"]
        Crypto["crypto (aes, cipher, rand)"]
        Encoding["encoding (base64, hex)"]
        OSLib["os, path/filepath, io, bytes"]
        SyncLib["sync, context, errors"]
    end

    CMD --> LIB
    CMD --> OSLib
    CMD --> SyncLib
    LIB --> Crypto
    LIB --> Encoding
    LIB --> OSLib
    LIB --> SyncLib
```

## 7. Security Architecture

### 7.1 Security Layers & Access Controls
1. **OS Permission Enforcement (RBAC)**: On Unix/Linux, key files are checked using stat modes to guarantee owner-only access (`0400` or `0600`).
2. **Windows Security Boundary**: Rejects keys stored in shared or volatile paths (`C:\Users\Public`, `%TEMP%`).
3. **Process Exposure Prevention**: Warns on `stderr` if sensitive secrets are passed as CLI arguments (which appear in process listings via `ps aux`). Prompts users to prefer environment variables (`-key-env`), key files (`-key-file`), or stdin (`-`).
4. **Structured Exit Diagnostics**: Returns distinct status codes (`0`, `2`, `3`, `4`, `5`) to allow SecOps monitoring without leaking error details.

### 7.2 Security Architecture Diagram

```mermaid
graph TD
    subgraph IngestionBoundary["Input & Argument Security Layer"]
        CLIArgs["CLI Flag Arguments (-key, -encrypt)"]
        EnvVarsInput["Environment Variables (-key-env)"]
        FileStdinInput["Protected Key Files / Stdin (-key-file, -)"]
        ExposureDetector["Process Leakage Detector (ps aux warning)"]
    end

    subgraph AccessControlLayer["Access Control & Path Validator (RBAC / OS Permissions)"]
        UnixChecker["Unix Permission Check (0400/0600 Owner Only)"]
        WinChecker["Windows Location Filter (Block Public/Temp)"]
    end

    subgraph CryptoCore["Cryptographic Isolation Layer"]
        CSPRNGGen["CSPRNG 256-bit Key / Nonce Generator"]
        AESGCMEngine["AES-256-GCM Envelope Engine"]
        MemCleaner["ZeroBuffer Memory Scrubbing"]
    end

    CLIArgs --> ExposureDetector
    FileStdinInput --> UnixChecker
    FileStdinInput --> WinChecker
    UnixChecker --> AccessControlLayer
    WinChecker --> AccessControlLayer
    EnvVarsInput --> AccessControlLayer
    AccessControlLayer --> CryptoCore
    CSPRNGGen --> AESGCMEngine
    AESGCMEngine --> MemCleaner
```
