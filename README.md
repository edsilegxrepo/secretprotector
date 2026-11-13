# SecretProtector

SecretProtector is a password obfuscation system for Go. It ensures that sensitive credentials (such as SFTP passwords, API keys, or database strings) are never stored in plaintext on disk or in version control by using AES-256-GCM authenticated encryption and a multi-source master key resolution strategy.

## Objectives
- **Zero Plaintext Storage:** Eliminate plaintext secrets from configuration files and environment variables.
- **Synchronized Logic:** Use a shared library (`pkg/libsecsecrets`) to ensure the CLI and Application always use the same cryptographic standards.
- **Flexible Key Management:** Support master keys from direct input, environment variables, or protected files.
- **Platform Security:** Enforce OS-level security boundaries (Linux permissions and Windows location checks).

## Security Assessment
- **Encryption Standards**: Implements AES-256-GCM (Galois/Counter Mode) authenticated encryption with 12-byte CSPRNG nonces (`crypto/rand`). Authenticated encryption guarantees both confidentiality and data integrity (detecting MAC tampering).
- **Secret & Memory Management**: Sensitive key buffers and raw plaintext slices are scrubbed immediately after cryptographic operations using `ZeroBuffer`. Zero-allocation byte slice trimming (`bytes.TrimSpace`) avoids leaving lingering copies on the GC heap.
- **Access Control & RBAC**: Key files require owner-only access control on Unix (`0400` or `0600`). On Windows, storage in insecure or shared root directories (`C:\Users\Public`, `%TEMP%`) is blocked.
- **Process Table Exposure Mitigation**: When sensitive master keys (`-key`) or plaintext secrets (`-encrypt`) are passed via CLI flags, the utility outputs a process listing exposure warning on `stderr`, advising users to adopt environment variables (`-key-env`), key files (`-key-file`), or stdin (`-`).
- **Non-Vulnerable Dependencies**: Built using **100% Go Standard Library** components (`crypto/aes`, `crypto/cipher`, `crypto/rand`, `encoding/base64`, `encoding/hex`). It maintains **zero 3rd-party vendor dependencies**, eliminating supply-chain vulnerability surfaces. Passed 100% clean across `Grype`, `GoVulnCheck`, `Gosec`, `Semgrep`, `ast-grep`, and `TruffleHog`.
- **Unprivileged Execution Context**: Operates entirely within standard unprivileged user space without requiring root or Administrator privileges.

> [!NOTE]
> For in-depth cryptographic design choices, threat models, and security layer diagrams, refer to the authoritative [ARCHITECTURE.md Section 7: Security Architecture](./ARCHITECTURE.md#7-security-architecture).

## Code Quality & Best Practices Assessment
- **Zero-Allocation Primitives**: Provides `EncryptBytes`, `DecryptBytes`, `EncryptBytesWithAAD`, and `DecryptBytesWithAAD` operating on byte slices to allow caller-managed zeroing and prevent heap string allocations.
- **Thread Safety**: Core cryptographic functions and production key resolution are stateless and lock-free. Internal tests inject isolated dependency structs (`sysDeps` / `cliDeps`) to run `t.Parallel()` without global mutable hooks or lock contention.
- **Resource Efficiency**: Utilizes `sync.Pool` buffer recycling to minimize GC pressure during high-throughput key generation.
- **Static Analysis Compliance**: Verified with `gofmt`, `go vet`, and standard Go static analysis workflows.

> [!NOTE]
> For complete statement coverage reports, test suite inventory, and execution commands, refer to the authoritative [TESTING.md](./TESTING.md).

## Command Line Arguments

The `secretprotector` CLI utility provides the following flags:

| Flag | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `-version` | bool | `false` | Print the version information and exit. |
| `-generate` | bool | `false` | Generate a new 32-byte Master Key (64-char hex string). |
| `-generate-raw` | bool | `false` | Generate a new 32-character raw Base64URL CSPRNG Master Key (192-bit entropy). |
| `-encrypt` | string | `""` | The plaintext string to obfuscate (pass `-` to read from stdin). |
| `-decrypt` | string | `""` | The `v1:gcm:` (or legacy Base64) ciphertext to decrypt (pass `-` to read from stdin). |
| `-raw` | bool | `false` | Omit the trailing newline from `-decrypt` output (exact plaintext bytes). |
| `-key` | string | `""` | Provide the Master Key directly (64-char hex or 32-byte raw). |
| `-key-env` | string | `SECRETPROTECTOR_MASTER_KEY` | The name of the environment variable containing the Master Key. |
| `-key-file` | string | `""` | Path to a protected file containing the Master Key (pass `-` to read from stdin). |

### Diagnostic Exit Codes

The `secretprotector` CLI returns structured status codes to simplify script automation and SecOps diagnostics:

| Exit Code | Constant | Meaning |
| :--- | :--- | :--- |
| `0` | `ExitSuccess` | Execution completed successfully. |
| `2` | `ExitUsageError` | Invalid arguments, bare/no-op invocation, `-raw` without `-decrypt`, empty `-encrypt`/`-decrypt` value, stdin collision, or mutually exclusive flags (`-version`, `-generate`, `-generate-raw`, `-encrypt`, `-decrypt`). |
| `3` | `ExitKeyResolutionError` | Master key missing, invalid format, or insecure key file permissions/location detected. |
| `4` | `ExitCryptoError` | Cryptographic error (CSPRNG failure, MAC verification failed, unsupported version, invalid Base64). |
| `5` | `ExitIOError` | Key file open/stat/read error or standard I/O stream error. |

**CLI Key Resolution Precedence:**
Explicit CLI key flags always take priority over the ambient default `SECRETPROTECTOR_MASTER_KEY` environment variable:
1. **Direct Key (`-key`)**: Highest precedence.
2. **Explicit Key File (`-key-file`)**: Takes priority over the ambient default environment variable unless `-key-env` is also passed explicitly.
3. **Environment Variable (`-key-env` / default `SECRETPROTECTOR_MASTER_KEY`)**: Used when neither `-key` nor `-key-file` overrides it (or when `-key-env` is passed explicitly). Support for stdin (`-key-file -`).

## CLI Usage Examples

### 1. Building from Source
Build the application with optimized settings for security and size.

**Windows (PowerShell):**
```powershell
# Get the version from build.json
$version = (Get-Content build.json | ConvertFrom-Json).version

# Build the application
go build -buildvcs=false -ldflags "-s -w -X main.version=$version -trimpath" -buildmode=pie -o $env:TEMP/ ./cmd/secretprotector
```

**Linux/Unix (Bash):**
```bash
# Get the version from build.json and build the application
VERSION=$(grep -o '"version": *"[^"]*"' build.json | cut -d'"' -f4)
go build -buildvcs=false -ldflags "-s -w -X main.version=$VERSION -trimpath" -buildmode=pie -o ./secretprotector ./cmd/secretprotector
```

### 2. Initial Setup: Generate a Master Key
Generate a new secure key for your environment. Use `-generate` for a 64-character hex key (full 256-bit entropy) or `-generate-raw` for a 32-character printable Base64URL key (192-bit entropy):

**Windows (PowerShell) or Linux/Unix (Bash):**
```powershell
# Standard 64-character hex key (256-bit entropy)
go run ./cmd/secretprotector -generate
# Output: 4f7e2d9a3b1c4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f

# Compact 32-character printable raw key (192-bit entropy, safe in env vars and key files)
go run ./cmd/secretprotector -generate-raw
# Output: dGhpcy1pcy1hLTI0LWJ5dGUtY3Nwcm5n
```

### 3. Stdin Unix Pipeline Streaming
Stream plaintext secrets or ciphertexts directly via standard input pipes to prevent command history logging.

```bash
# Stream plaintext into encrypt pipe
echo "DatabasePass2026!" | go run ./cmd/secretprotector -key-env SECRETPROTECTOR_MASTER_KEY -encrypt -
# Output: v1:gcm:9A3bF...Base64EncryptedCiphertext==

# Stream ciphertext into decrypt pipe
echo "v1:gcm:9A3bF...Base64EncryptedCiphertext==" | go run ./cmd/secretprotector -key-env SECRETPROTECTOR_MASTER_KEY -decrypt -
# Output: DatabasePass2026!
```

### 4. Obfuscate a Secret (Direct Key: `-key`)
Encrypt a secret (e.g., an SFTP password) by providing the key directly on the command line. This is useful for testing or one-off operations but is less secure than other methods because the key may be visible in process listings or shell history.

**Windows (PowerShell) or Linux/Unix (Bash):**
```powershell
# Use a 64-character hex string as the key - Output: v1:gcm:<base64(nonce + ciphertext)>
go run ./cmd/secretprotector -key "4f7e2d9a3b1c4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f" -encrypt "your_secret_here"
# Output:
# Warning: Passing sensitive master keys directly via CLI flags risks process listing exposure (ps aux). Prefer -key-env or -key-file.
# Warning: Passing plaintext secrets directly via CLI flags risks process listing exposure (ps aux). Prefer stdin (-encrypt -).
# v1:gcm:A1B2C3D4...

# The -key flag also supports a 32-character raw string (less common)
go run ./cmd/secretprotector -key "a_32_character_long_secret_str!!" -encrypt "your_secret_here"
```

### 5. Obfuscate a Secret (Environment Variable: `-key-env`)
The recommended option for containerized or CI/CD workflows where secrets are injected securely at process launch. By default, it looks for `SECRETPROTECTOR_MASTER_KEY`.

> [!WARNING]
> Avoid persisting plaintext master keys in unencrypted login shell profiles (`~/.bashrc`, `~/.profile`) or via `setx` CLI arguments (`setx SECRETPROTECTOR_MASTER_KEY "..." /M`), which expose the key in process listings and store it unencrypted in Windows registry hives. For persistent services, prefer `-key-file` protected by OS permissions/ACLs, systemd `EnvironmentFile` (`0400`), or a dedicated secret manager.

#### 5.1 Set the environment variable (session or service scope)
**Windows (PowerShell):**
```powershell
# Set for current PowerShell session only
$env:SECRETPROTECTOR_MASTER_KEY = "4f7e2d9a3b1c4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f"
$env:MY_APP_KEY = "4f7e2d9a3b1c4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f"

# 32-character raw Base64URL key from -generate-raw also works directly in env vars
$env:SECRETPROTECTOR_MASTER_KEY = "dGhpcy1pcy1hLTI0LWJ5dGUtY3Nwcm5n"
```

**Linux/Unix (Bash):**
```bash
# Set for current session (for hex or Base64URL text keys; use -key-file directly for raw binary keys)
export SECRETPROTECTOR_MASTER_KEY="$(cat /etc/secrets/master.key)"
```

#### 5.2 Encrypt using the default environment variable or a custom environment variable name
```powershell
# Using default (SECRETPROTECTOR_MASTER_KEY)
go run ./cmd/secretprotector -encrypt "your_secret_here"

# Using custom environment variable
go run ./cmd/secretprotector -key-env "MY_APP_KEY" -encrypt "your_secret_here"
```

### 6. Obfuscate a Secret (Key File: `-key-file`)
The most secure way to manage keys at rest. The file must reside in a protected location with restricted access.

**Path Guidance:** Relative paths are resolved and canonicalized cleanly, though **absolute paths are strongly recommended** for production services and scheduled jobs whose working directory may vary.

**Security Requirements:**
- **Linux/Unix:** Regular files only (`IsRegular()`, single `os.Open` + `f.Stat()` check), owner UID matching effective UID, no special mode bits (`setuid`/`setgid`/`sticky`), and owner-only permissions (`0400` or `0600`). Maximum key file size: `4096` bytes.
- **Windows:** Resolves symlinks/junctions (`filepath.EvalSymlinks`) before rejecting shared or volatile path segments (`Public`, `Temp`, `tmp`). Harden file ACLs with `icacls` so only the service/owner account has read access.

**Windows (PowerShell):**
```powershell
# Restrict ACLs to the current owner only, then encrypt using the key file
icacls "C:\ProgramData\SecretProtector\master.key" /inheritance:r /grant:r "${env:USERNAME}:(R)"
go run ./cmd/secretprotector -key-file "C:\ProgramData\SecretProtector\master.key" -encrypt "your_secret_here"
```

**Linux/Unix (Bash):**
```bash
# Ensure owner-only permissions first
chmod 0400 /etc/secrets/master.key

# Encrypt using the key file
go run ./cmd/secretprotector -key-file "/etc/secrets/master.key" -encrypt "your_secret_here"
```

### 7. Decrypt a Secret
Decryption requires the same master key used for encryption. Both `v1:gcm:<base64>` and legacy unprefixed Base64 ciphertexts are accepted. Pass `-raw` to omit the trailing newline.

#### 7.1 Direct Key (`-key`)
**Windows (PowerShell) or Linux/Unix (Bash):**
```bash
go run ./cmd/secretprotector -key "4f7e2d9a3b1c4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f" -decrypt "v1:gcm:A1B2C3D4..."
# Output: your_secret_here
```

#### 7.2 Environment Variable (`-key-env`)
Refer to [Section 5.1](#51-set-the-environment-variable-session-or-service-scope) for instructions on providing these variables safely.

**Windows (PowerShell) or Linux/Unix (Bash):**
```bash
# Using the default environment variable (SECRETPROTECTOR_MASTER_KEY)
go run ./cmd/secretprotector -decrypt "v1:gcm:A1B2C3D4..."
# Output: your_secret_here

# Using a custom environment variable name
go run ./cmd/secretprotector -key-env "MY_APP_KEY" -decrypt "v1:gcm:A1B2C3D4..."
# Output: your_secret_here
```

#### 7.3 Key File (`-key-file`)
**Windows (PowerShell):**
```powershell
go run ./cmd/secretprotector -key-file "C:\ProgramData\SecretProtector\master.key" -decrypt "v1:gcm:A1B2C3D4..."
# Output: your_secret_here
```

**Linux/Unix (Bash):**
```bash
# Ensure secure permissions first
chmod 0400 /etc/secrets/master.key

go run ./cmd/secretprotector -key-file "/etc/secrets/master.key" -decrypt "v1:gcm:A1B2C3D4..." -raw
# Output: your_secret_here (exact bytes without trailing newline)
```

## Library Integration
To integrate SecretProtector into your own Go application, please refer to the [SAMPLEAPP.md](./SAMPLEAPP.md) guide. It details the "Bootstrap Sequence" required to resolve keys and decrypt secrets at runtime securely.

## Architecture
For details on design choices, cryptographic standards, and project structure, see [ARCHITECTURE.md](./ARCHITECTURE.md).

## Testing & Quality Assurance
For test execution procedures, coverage breakdowns, and E2E process testing strategy, see [TESTING.md](./TESTING.md).

## Project Changelog
For version release notes, see [CHANGELOG.md](./CHANGELOG.md).
