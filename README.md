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
> For in-depth cryptographic design choices, threat models, and security layer diagrams, refer to the authoritative [ARCHITECTURE.md Section 6: Security Architecture](./ARCHITECTURE.md#6-security-architecture).

## Code Quality & Best Practices Assessment
- **Zero-Allocation Primitives**: Provides `EncryptBytes` and `DecryptBytes` operating on byte slices to allow caller-managed zeroing and prevent heap string allocations.
- **Thread Safety**: Core cryptographic functions are fully stateless and re-entrant. Internal test mocks use `sync.RWMutex` to support concurrent parallel testing (`t.Parallel()`).
- **Resource Efficiency**: Utilizes `sync.Pool` buffer recycling to minimize GC pressure during high-throughput key generation.
- **Static Analysis Compliance**: 100% compliant with standard Go linter tools (`gofumpt`, `golangci-lint`, `gosec`).

> [!NOTE]
> For complete statement coverage reports, test suite inventory, and execution commands, refer to the authoritative [TESTING.md](./TESTING.md).

## Command Line Arguments

The `secretprotector` CLI utility provides the following flags:

| Flag | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `-version` | bool | `false` | Print the version information and exit. |
| `-generate` | bool | `false` | Generate a new 32-byte Master Key (64-char hex string). |
| `-encrypt` | string | `""` | The plaintext string to obfuscate (pass `-` to read from stdin). |
| `-decrypt` | string | `""` | The Base64-encoded ciphertext to decrypt (pass `-` to read from stdin). |
| `-key` | string | `""` | Provide the Master Key directly (64-char hex or 32-byte raw). |
| `-key-env` | string | `SECRETPROTECTOR_MASTER_KEY` | The name of the environment variable containing the Master Key. |
| `-key-file` | string | `""` | The fully qualified path to a file containing the Master Key (pass `-` to read from stdin). |

### Diagnostic Exit Codes

The `secretprotector` CLI returns structured status codes to simplify script automation and SecOps diagnostics:

| Exit Code | Constant | Meaning |
| :--- | :--- | :--- |
| `0` | `ExitSuccess` | Execution completed successfully. |
| `2` | `ExitUsageError` | Invalid arguments, stdin collision, or mutually exclusive flags passed (`-generate`, `-encrypt`, `-decrypt`). |
| `3` | `ExitKeyResolutionError` | Master key resolution failed or insecure key file permissions detected. |
| `4` | `ExitCryptoError` | Cryptographic error (CSPRNG failure, MAC verification failed, invalid Base64). |
| `5` | `ExitIOError` | File read/write failure or standard I/O error. |

**Key Resolution Precedence:**
If multiple key sources are provided, the application resolves them in the following order:
1. **Direct Key (`-key`)**: Highest precedence.
2. **Environment Variable (`-key-env`)**: Used if `-key` is not provided.
3. **Key File (`-key-file`)**: Lowest precedence; used only if no key is found in the other sources. Support for stdin (`-key-file -`).

## CLI Usage Examples

### 1. Building from Source
Build the application with optimized settings for security and size.

**Windows (PowerShell):**
```powershell
# Get the version from version.txt
$version = Get-Content version.txt -Raw

# Build the application
go build -buildvcs=false -ldflags "-s -w -X main.version=$version -trimpath" -buildmode=pie -o $env:TEMP/ ./cmd/secretprotector
```

**Linux/Unix (Bash):**
```bash
# Get the version from version.txt and build the application
go build -buildvcs=false -ldflags "-s -w -X main.version=$(cat version.txt) -trimpath" -buildmode=pie -o ./secretprotector ./cmd/secretprotector
```

### 2. Initial Setup: Generate a Master Key
Generate a new secure key for your environment.

**Windows (PowerShell) or Linux/Unix (Bash):**
```powershell
go run ./cmd/secretprotector -generate
# Output: 4f7e2d9a3b1c4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f (64 character hex string)
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
# Use a 64-character hex string as the key - Output: Base64 string (nonce + ciphertext)
go run ./cmd/secretprotector -key "4f7e2d9a3b1c4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f" -encrypt "your_secret_here"
# Output:
# Warning: Passing sensitive master keys directly via CLI flags risks process listing exposure (ps aux). Prefer -key-env or -key-file.
# Warning: Passing plaintext secrets directly via CLI flags risks process listing exposure (ps aux). Prefer stdin (-encrypt -).
# A1B2C3D4... (Base64 string)

# The -key flag also supports a 32-character raw string (less common)
go run ./cmd/secretprotector -key "a_32_character_long_secret_str!!" -encrypt "your_secret_here"
```

### 5. Obfuscate a Secret (Environment Variable: `-key-env`)
The recommended way for automated environments. By default, it looks for `SECRETPROTECTOR_MASTER_KEY`.

**Windows Note:** The master key environment variable can be stored in either the **USER** or **SYSTEM** scope. The application retrieves the value from the process environment block, 
where User variables take precedence over System variables.

To ensure variables persist after a server reboot, use the `setx` command:
- **User Scope:** `setx SECRETPROTECTOR_MASTER_KEY "your_hex_key"`
- **System Scope:** `setx SECRETPROTECTOR_MASTER_KEY "your_hex_key" /M` (requires Administrative privileges)

*Note: `setx` updates the registry; you must open a new terminal window for the changes to take effect in your current session.*

#### 5.1 Set the environment variable (default name) with a 64-character hex string
**Windows (PowerShell):**
```powershell
# Set for current session only
$env:SECRETPROTECTOR_MASTER_KEY = "4f7e2d9a3b1c4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f"
$env:MY_APP_KEY = "4f7e2d9a3b1c4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f"

# Set permanently (User scope)
setx SECRETPROTECTOR_MASTER_KEY "4f7e2d9a3b1c4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f"
setx MY_APP_KEY "4f7e2d9a3b1c4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f"

# Set permanently (System scope - Run as Admin)
setx SECRETPROTECTOR_MASTER_KEY "4f7e2d9a3b1c4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f" /M
setx MY_APP_KEY "4f7e2d9a3b1c4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f" /M
```

**Linux/Unix (Bash):**
```bash
# Set for current session
export SECRETPROTECTOR_MASTER_KEY="4f7e2d9a3b1c4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f"
export MY_APP_KEY="4f7e2d9a3b1c4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f"

# To set permanently, add the above lines to your ~/.bashrc or ~/.profile
```

#### 5.2 Encrypt using the default environment variable or a custom environment variable name
```powershell
# Using default (SECRETPROTECTOR_MASTER_KEY)
go run ./cmd/secretprotector -encrypt "your_secret_here"

# Using custom environment variable
go run ./cmd/secretprotector -key-env "MY_APP_KEY" -encrypt "your_secret_here"
```

### 6. Obfuscate a Secret (Key File: `-key-file`)
The most secure way to manage keys. The file must have restricted permissions. 

**Important:** You **must** use absolute paths for the `-key-file` flag. Relative paths are disallowed to prevent path traversal attacks and ensure the application always references the intended secure location.

**Security Requirements:**
- **Windows:** Files cannot be in "Public" or "Temp" directories.
- **Linux/Unix:** Files must have owner-only permissions (e.g., `0400` or `0600`).

**Windows (PowerShell):**
```powershell
# Encrypt using a key stored in a file
go run ./cmd/secretprotector -key-file "C:\Users\Admin\Documents\master.key" -encrypt "your_secret_here"
```

**Linux/Unix (Bash):**
```bash
# Ensure secure permissions first
chmod 0400 /etc/secrets/master.key

# Encrypt using the key file
go run ./cmd/secretprotector -key-file "/etc/secrets/master.key" -encrypt "your_secret_here"
```

### 7. Decrypt a Secret
Decryption requires the same master key used for encryption. Examples are shown by key source.

#### 7.1 Direct Key (`-key`)
**Windows (PowerShell) or Linux/Unix (Bash):**
```bash
go run ./cmd/secretprotector -key "4f7e2d9a3b1c4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f" -decrypt "A1B2C3D4..."
# Output: your_secret_here
```

#### 7.2 Environment Variable (`-key-env`)
Refer to [Section 5.1](#51-set-the-environment-variable-default-name-with-a-64-character-hex-string) for instructions on how to set these variables for Windows and Linux.

**Windows (PowerShell) or Linux/Unix (Bash):**
```bash
# Using the default environment variable (SECRETPROTECTOR_MASTER_KEY)
go run ./cmd/secretprotector -decrypt "A1B2C3D4..."
# Output: your_secret_here

# Using a custom environment variable name
go run ./cmd/secretprotector -key-env "MY_APP_KEY" -decrypt "A1B2C3D4..."
# Output: your_secret_here
```

#### 7.3 Key File (`-key-file`)
**Windows (PowerShell):**
```powershell
go run ./cmd/secretprotector -key-file "C:\Users\Admin\Documents\master.key" -decrypt "A1B2C3D4..."
# Output: your_secret_here
```

**Linux/Unix (Bash):**
```bash
# Ensure secure permissions first
chmod 0400 /etc/secrets/master.key

go run ./cmd/secretprotector -key-file "/etc/secrets/master.key" -decrypt "A1B2C3D4..."
# Output: your_secret_here
```

## Library Integration
To integrate SecretProtector into your own Go application, please refer to the [SAMPLEAPP.md](./SAMPLEAPP.md) guide. It details the "Bootstrap Sequence" required to resolve keys and decrypt secrets at runtime securely.

## Architecture
For details on design choices, cryptographic standards, and project structure, see [ARCHITECTURE.md](./ARCHITECTURE.md).

## Testing & Quality Assurance
For test execution procedures, coverage breakdowns, and E2E process testing strategy, see [TESTING.md](./TESTING.md).

## Project Changelog
For version release notes, see [CHANGELOG.md](./CHANGELOG.md).
