This specification outlines a professional-grade implementation for password and secret obfuscation in Go. By externalizing the logic into a **Library**, you ensure that the **CLI** (used by admins/DevOps) and the **Application** (used by the runtime) stay perfectly synchronized. The library is designed to protect any sensitive credential, using an SFTP client as a primary implementation example.

---

## 1. Core Cryptographic Library (`libsecsecrets`)

> [!WARNING]
> **Breaking Architectural Change (`v0.1.0`+):** The legacy `pkg/` wrapper directory has been removed in alignment with modern Go project layout standards. The cryptographic library now lives directly at the root level (`libsecsecrets/`). All import paths must be updated from `github.com/edsilegxrepo/secretprotector/pkg/libsecsecrets` to `github.com/edsilegxrepo/secretprotector/libsecsecrets`.

The library (`github.com/edsilegxrepo/secretprotector/libsecsecrets`) is the single source of truth for cryptographic operations and AES-256-GCM symmetric obfuscation (`v1:gcm:...`).

### Core Requirements
* **Algorithm:** AES-256-GCM (Galois/Counter Mode) for authenticated encryption.
* **Key Handling:** Must support 32-byte raw strings or 64-character hex strings.
* **Randomness:** Use `crypto/rand` for all key and nonce generation.
* **Encapsulation:** The library should not log or print any sensitive data to `stdout`.

### Exported API
| Function | Input | Output | Purpose |
| :--- | :--- | :--- | :--- |
| `GenerateKey()` | None | `(string, error)` | Returns a 64-char hex string (32 bytes of entropy). Uses `sync.Pool` for efficiency. |
| `ResolveKey(ctx, raw, env, file)` | `Context`, Strings | `([]byte, error)` | Finds and validates the key from 3 sources: CLI flag, environment variable, or file path. Supports 64-char hex or 32-byte raw. Enforces platform security. |
| `Encrypt(ctx, plain, key)` | `Context, string, []byte` | `(string, error)` | Returns `v1:gcm:<base64(nonce + ciphertext)>`. |
| `Decrypt(ctx, encoded, key)` | `Context, string, []byte` | `(string, error)` | Strips prefix, extracts nonce, decrypts, returns plaintext. Accepts with or without `v1:gcm:` prefix. |
| `IsEncrypted(s)` | `string` | `bool` | Returns true if string has `v1:gcm:` prefix. |
| `ZeroBuffer(b)` | `[]byte` | None | Securely clears sensitive data from memory. |

---

## 2. CLI Tool Specification (`/cmd/secretprotector`)
A standalone utility for developers and system administrators to manage secrets.

### Functionality
* **Initialization:** Provide a `-generate` flag to create a new Master Key.
* **Management:** Provide `-encrypt` and `-decrypt` flags.
* **Configuration:** Allow the user to specify where the key is coming from via `-key-env`, `-key-file` or `-key` (direct input).
* **Portability:** Must be cross-compiled for Windows (`.exe`) and Linux.

### Developer Workflow Example
1.  **Generate:** `secretprotector -generate` Copy the Hex string.
2.  **Store:** Save Hex string in `SECRETPROTECTOR_MASTER_KEY` environment variable.
3.  **Obfuscate:** `secretprotector -encrypt "sftp_password_123"` Copy `v1:gcm:...` result.
4.  **Configure:** Paste `v1:gcm:...` result into `config.json`.

---

## 3. Application Implementation Spec
How the main Go application (the SFTP client) consumes the library.

### Bootstrap Sequence
1.  **Key Resolution:** On startup, the app calls `libsecsecrets.ResolveKey(ctx, "", "SECRETPROTECTOR_MASTER_KEY", "/etc/secrets/key.txt")`.
    * If no key is found or the key is invalid, the app **must fail to start** immediately with a clear error.
2.  **Memory Hygiene:** Use `defer libsecsecrets.ZeroBuffer(masterKey)` immediately after resolution.
3.  **Config Loading:** Load the `config.json`.
4.  **On-the-fly Decryption:** When initializing the target connection (e.g., SFTP, API, DB), pass the encrypted string from the config through `libsecsecrets.Decrypt(ctx, encStr, masterKey)`.

### Safety Rules for the App
* **Memory Only:** Never write the decrypted plaintext back to a file or a log.
* **Environment Hygiene:** If using environment variables for the key, ensure the process environment isn't exposed via debug endpoints (like `pprof`).

---

## 4. Integration Diagram
The following flow ensures that the plaintext password is never stored on disk.

```mermaid
sequenceDiagram
    autonumber
    actor Admin as Admin / DevOps
    participant CLI as CLI Tool (/cmd/secretprotector)
    participant Lib as Library (/libsecsecrets)
    participant Storage as OS / Storage
    participant App as Application (SFTP Client)
    participant Target as Target Service (SFTP Server)

    box Phase 1: Provisioning (CLI & Admin)
    Admin->>CLI: Run `-generate`
    CLI->>Lib: GenerateKey()
    Lib-->>CLI: Return Master Key (64-char Hex)
    Admin->>Storage: Save Master Key (Env Var / Key File)
    Admin->>CLI: Run `-encrypt "plaintext_password"`
    CLI->>Lib: Encrypt("plaintext_password", Key)
    Lib-->>CLI: Return "v1:gcm:<base64>"
    Admin->>Storage: Save "v1:gcm:..." to config.json
    end

    box Phase 2: Runtime (App Execution)
    App->>Lib: ResolveKey(ctx, "", "SECRETPROTECTOR_MASTER_KEY", file)
    Lib->>Storage: Read Master Key
    Storage-->>Lib: Key bytes
    Lib-->>App: Master Key ([]byte)
    App->>App: defer ZeroBuffer(masterKey)
    App->>Storage: Read config.json ("v1:gcm:...")
    App->>Lib: Decrypt(ctx, encStr, masterKey)
    Lib-->>App: Plaintext password (in memory only)
    App->>Target: Connect using plaintext password
    end
```

### Summary of Responsibilities
* **Library:** "How" we encrypt (AES-GCM).
* **CLI:** "How" we prepare the data (Manual/Admin).
* **App:** "How" we use the data (Automated/Runtime).
* **Environment:** "Where" we keep the Master Key (OS Level).

---

## 5. The 3-Tier Provider Architecture for `secretprotector`

The `secretprotector` architecture supports two complementary operational modes:
* **Mode A (Direct Secret Resolution):** `ChainedProvider.GetSecret(ctx, "DB_PASSWORD")` resolves raw secrets directly across Tier 1 (OS Keyring), Tier 2 (Age / PKCS#12 File Vault), or Tier 3 (Cloud KMS / Vault).
* **Mode B (Master Key Provider for `libsecsecrets`):** `ChainedProvider` resolves the Master Key from Tier 1, 2, or 3, which is then supplied to `libsecsecrets.Decrypt(ctx, encStr, masterKey)` for decrypting local `v1:gcm:...` configuration payloads.

```text
                                  +---------------------------------------+
                                  |            secretprotector            |
                                  |          ChainedProvider API          |
                                  +-------------------+-------------------+
                                                      |
         +--------------------------------------------+--------------------------------------------+
         |                                            |                                            |
         v                                            v                                            v
+-------------------------------+           +-------------------------------+           +-------------------------------+
|       1. OS Keyring           |           |  2. Age Encrypted File Vault  |           |     3. Remote Vault / KMS     |
|   (Local Confined Secrets)    |           | (Shared Local Staging Secrets)|           |     (Production Servers)      |
+-------------------------------+           +-------------------------------+           +-------------------------------+
| - Linux: systemd-creds        |           | - Pure Go: filippo.io/age     |           | - HashiCorp Vault HTTP API    |
|   ($CREDENTIALS_DIRECTORY)    |           | - Storage: .env.age           |           | - AWS Secrets Manager / KMS   |
| - Windows: DPAPI              |           | - Workflow: Shared team keys, |           | - Azure Key Vault             |
|   (CryptProtectData via SID)  |           |   GitOps, offline staging     |           | - GCP Secret Manager          |
+-------------------------------+           +-------------------------------+           +-------------------------------+

```

---

### Tier 1: OS Keyring — *Best for Local Confined Secrets*

Used when a secret belongs strictly to **one host machine or user account** and does not need to be shared across a fleet.

* **Linux Server (`systemd-creds`):**
  * **At Rest:** Ciphertext encrypted on disk bound to `/etc/machine-id` and the user's UID.
  * **At Runtime:** `systemd` decrypts files into a RAM-backed `ramfs` directory exposed via `$CREDENTIALS_DIRECTORY`.

* **Windows Server (`DPAPI`):**
  * **At Rest:** Binary `.dat` files encrypted on disk using `CryptProtectData`.
  * **At Runtime:** The Windows kernel decrypts the payload in RAM bound to the specific unprivileged Service Account SID.



#### `secretprotector` Integration (`providers/oskeyring`):

```go
package oskeyring

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

type Provider struct{}

func New() *Provider {
	return &Provider{}
}

func (p *Provider) GetSecret(ctx context.Context, key string) ([]byte, error) {
	switch runtime.GOOS {
	case "linux":
		// Check systemd $CREDENTIALS_DIRECTORY
		credDir := os.Getenv("CREDENTIALS_DIRECTORY")
		if credDir == "" {
			return nil, fmt.Errorf("systemd CREDENTIALS_DIRECTORY not set")
		}
		return os.ReadFile(filepath.Join(credDir, key))

	case "windows":
		// Windows DPAPI via golang.org/x/sys/windows (CryptUnprotectData)
		return getDPAPISecret(key)

	default:
		return nil, fmt.Errorf("unsupported OS keyring platform: %s", runtime.GOOS)
	}
}

```

---

### Tier 2: Age Encrypted File Vault — *Best for Shared Local Staging Secrets*

Used for **staging environments, team developer sharing, and GitOps** workflows. Secrets live in an encrypted file that can be committed safely to Git or passed around teams, while remaining decryptable by anyone with the team's private key or passphrase.

#### Age Encrypted File Vault

Secrets are stored in an `.env.age` vault file encrypted with recipient public keys or passphrases.
* **Key Advantage:** Pure Go (`filippo.io/age`), platform-agnostic, zero system daemon dependencies.

`secretprotector` Integration (`providers/agefile`):

```go
package agefile

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"

	"filippo.io/age"
)

type Provider struct {
	VaultPath    string
	IdentityPath string
}

func New(vaultPath, identityPath string) *Provider {
	return &Provider{VaultPath: vaultPath, IdentityPath: identityPath}
}

func (p *Provider) GetSecret(ctx context.Context, key string) ([]byte, error) {
	// 1. Read age private key identity
	identityFile, err := os.Open(p.IdentityPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open age identity key: %w", err)
	}
	defer identityFile.Close()

	identities, err := age.ParseIdentities(identityFile)
	if err != nil {
		return nil, fmt.Errorf("failed to parse age identity: %w", err)
	}

	// 2. Open age encrypted vault file (.env.age)
	vaultFile, err := os.Open(p.VaultPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open age vault file: %w", err)
	}
	defer vaultFile.Close()

	// 3. Decrypt in memory
	r, err := age.Decrypt(vaultFile, identities...)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt age vault: %w", err)
	}

	var decryptedBuf bytes.Buffer
	if _, err := io.Copy(&decryptedBuf, r); err != nil {
		return nil, err
	}

	// 4. Parse key-value payload from decrypted buffer
	return parseKeyFromVault(decryptedBuf.Bytes(), key)
}

```


#### PKCS#12 (`.p12` / `.pfx`) Local Vault

**PKCS#12** (PFX/P12) serves as a local vault format alternative to `age`.

It is ideal for **PKI environments, mTLS client credentials, database SSL keys, and legacy servers**.

---

#### Why Support PKCS#12?

* **Native PKI Integration:** Certificate Authorities (CAs) and security teams frequently issue database client certificates, mTLS keys, and app credentials as password-protected `.p12` or `.pfx` bundles.
* **Standardized Cryptography:** Uses password-based encryption (PBKDF2/TripleDES/AES) to package private keys, x509 certificates, and custom attribute bags into a single portable binary file.
* **Pure Go Implementation:** Supported via standard extended packages ([`golang.org/x/crypto/pkcs12`](https://golang.org/x/crypto/pkcs12) or [`software.sslmate.com/src/go-pkcs12`](https://software.sslmate.com/src/go-pkcs12)), keeping builds zero-Cgo (`CGO_ENABLED=0`).

---

#### PKCS#12 Provider Implementation (`providers/pkcs12/pkcs12.go`)

```go
package pkcs12

import (
	"context"
	"crypto/pem"
	"fmt"
	"os"

	"software.sslmate.com/src/go-pkcs12"
)

type Provider struct {
	P12Path  string
	Password string
}

func New(p12Path, password string) *Provider {
	return &Provider{
		P12Path:  p12Path,
		Password: password,
	}
}

// GetSecret extracts private keys, certificate PEM blocks, or matched key aliases from a .p12 archive
func (p *Provider) GetSecret(ctx context.Context, key string) ([]byte, error) {
	p12Data, err := os.ReadFile(p.P12Path)
	if err != nil {
		return nil, fmt.Errorf("failed to read pkcs12 file %q: %w", p.P12Path, err)
	}

	// 1. Convert safe bags inside P12 bundle into PEM blocks
	blocks, err := pkcs12.ToPEM(p12Data, p.Password)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt pkcs12 vault: %w", err)
	}

	// 2. Resolve target key based on request (e.g., "PRIVATE_KEY", "CERTIFICATE", or specific alias)
	for _, block := range blocks {
		switch key {
		case "PRIVATE_KEY":
			if block.Type == "PRIVATE_KEY" || block.Type == "RSA PRIVATE KEY" || block.Type == "EC PRIVATE KEY" {
				return pem.EncodeToMemory(block), nil
			}
		case "CERTIFICATE":
			if block.Type == "CERTIFICATE" {
				return pem.EncodeToMemory(block), nil
			}
		default:
			// Match custom PEM headers or bag attributes if specified
			if val, ok := block.Headers["friendlyName"]; ok && val == key {
				return pem.EncodeToMemory(block), nil
			}
		}
	}

	return nil, fmt.Errorf("secret key %q not found in pkcs12 bundle", key)
}

```

---

#### Local AES-256-GCM Obfuscated Payload Provider (`providers/aesgcm`)

Integrates Section 1's `libsecsecrets` symmetric obfuscation engine directly into the `Provider` chain. Decrypts `v1:gcm:...` values embedded in local configuration files using a Master Key resolved from the `ChainedProvider` context or environment.

```go
package aesgcm

import (
	"context"
	"fmt"

	"github.com/edsilegxrepo/secretprotector/libsecsecrets"
)

type Provider struct {
	MasterKey []byte
}

func New(masterKey []byte) *Provider {
	return &Provider{MasterKey: masterKey}
}

func (p *Provider) GetSecret(ctx context.Context, encryptedVal string) ([]byte, error) {
	if !libsecsecrets.IsEncrypted(encryptedVal) {
		return nil, fmt.Errorf("value is not a valid v1:gcm: payload")
	}
	plaintext, err := libsecsecrets.Decrypt(ctx, encryptedVal, p.MasterKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt v1:gcm payload: %w", err)
	}
	return []byte(plaintext), nil
}
```

---

### Tier 3: Remote Vault / Cloud KMS — *Best for Production Servers*

Used in **production clusters, cloud-native deployments, and distributed microservices** where secrets need centralized access control, audit logging, and automated dynamic rotation.

* **Supported Backends:** HashiCorp Vault HTTP API, AWS Secrets Manager / KMS, Azure Key Vault, GCP Secret Manager.

#### `secretprotector` Integration (`providers/remote`):

```go
package remote

import (
	"context"
	"fmt"
	
	// Light HTTP client wrapper for HashiCorp Vault API
	vault "github.com/hashicorp/vault/api" 
)

type HashiVaultProvider struct {
	client *vault.Client
	path   string
}

func NewHashiVault(address, token, secretPath string) (*HashiVaultProvider, error) {
	config := vault.DefaultConfig()
	config.Address = address

	client, err := vault.NewClient(config)
	if err != nil {
		return nil, err
	}
	client.SetToken(token)

	return &HashiVaultProvider{client: client, path: secretPath}, nil
}

func (p *HashiVaultProvider) GetSecret(ctx context.Context, key string) ([]byte, error) {
	secret, err := p.client.KVv2(p.path).Get(ctx, key)
	if err != nil {
		return nil, fmt.Errorf("failed fetching remote secret from HashiCorp Vault: %w", err)
	}

	val, ok := secret.Data[key].(string)
	if !ok {
		return nil, fmt.Errorf("key %q not found in remote vault path", key)
	}

	return []byte(val), nil
}

```

---

### Unified Application Setup in `secretprotector`

With this complete 3-tier structure, `secretprotector` resolves secrets using a clean **Chained Fallback Order**:

```go
package main

import (
	"context"
	"fmt"
	"log"

	"github.com/edsilegxrepo/secretprotector"
	"github.com/edsilegxrepo/secretprotector/providers/agefile"
	"github.com/edsilegxrepo/secretprotector/providers/oskeyring"
	"github.com/edsilegxrepo/secretprotector/providers/remote"
)

func main() {
	ctx := context.Background()

	// Initialize remote HashiCorp Vault provider
	hashiProvider, err := remote.NewHashiVault("https://vault.internal:8200", "s.token", "secret/data/myapp")
	if err != nil {
		log.Fatalf("Failed to initialize HashiCorp Vault provider: %v", err)
	}

	// Configure the complete 3-Tier Chained Secret Provider
	vault := secretprotector.NewChainedProvider(
		// 1. Local confined secrets (systemd-creds RAM / Windows DPAPI)
		oskeyring.New(), 

		// 2. Shared local staging secrets (.env.age file)
		agefile.New("./staging.env.age", "~/.config/myapp/identity.txt"), 

		// 3. Distributed Production Servers (HashiCorp / Cloud KMS)
		hashiProvider, 
	)

	// Single call automatically resolves across all 3 tiers
	dbSecret, err := vault.GetSecret(ctx, "DB_PASSWORD")
	if err != nil {
		log.Fatalf("Could not resolve DB_PASSWORD across any tier: %v", err)
	}

	fmt.Printf("Resolved secret successfully (%d bytes)\n", len(dbSecret))
}

```

## 6. Package Structure

Below is the complete project directory tree for `secretprotector`, designed around a pluggable subpackage architecture to keep core dependencies lean while cleanly isolating the 3 tiers.

```text
secretprotector/
├── go.mod
├── go.sum
├── Makefile
├── README.md
│
├── provider.go                   # Core Provider interface & ChainedProvider engine
├── provider_test.go              # Unit tests & mocks for chaining logic
│
├── libsecsecrets/                # Core AES-256-GCM symmetric encryption engine & key resolution
│   ├── libsecsecrets.go
│   └── libsecsecrets_test.go
│
├── providers/                    # Modular provider implementations
│   │
│   ├── oskeyring/                # TIER 1: Local Confined Secrets (Zero external dependencies)
│   │   ├── oskeyring.go          # Platform dispatcher (Linux vs Windows)
│   │   ├── systemd_linux.go      # Linux systemd-creds ($CREDENTIALS_DIRECTORY)
│   │   ├── dpapi_windows.go      # Windows DPAPI (golang.org/x/sys/windows)
│   │   └── oskeyring_test.go
│   │
│   ├── agefile/                  # TIER 2: Shared Local Staging Secrets (filippo.io/age)
│   │   ├── agefile.go            # .env.age vault reader, decryptor & parser
│   │   └── agefile_test.go
│   │
│   ├── pkcs12/                   # TIER 2: Enterprise PKI & Certificate Bundles (PKCS#12 / PFX)
│   │   ├── pkcs12.go             # .p12/.pfx keystore reader & PEM/key extractor
│   │   └── pkcs12_test.go
│   │
│   ├── aesgcm/                   # LOCAL OBFUSCATION: v1:gcm:... payload decryptor
│   │   ├── aesgcm.go             # Wraps libsecsecrets.Decrypt into Provider interface
│   │   └── aesgcm_test.go
│   │
│   ├── remote/                   # TIER 3: Production Remote Vaults / Cloud KMS
│   │   ├── hashivault/
│   │   │   ├── hashivault.go     # HashiCorp Vault HTTP API provider
│   │   │   └── hashivault_test.go
│   │   ├── awssm/
│   │   │   └── awssm.go          # AWS Secrets Manager SDK provider
│   │   └── azure/
│   │       └── azure.go          # Azure Key Vault SDK provider
│   │
│   └── env/                      # Fallback Environment Variable Provider
│       ├── env.go                # os.Getenv wrapper with optional prefix matching
│       └── env_test.go
│
├── examples/                     # Deployment & integration blueprints
│   ├── 3tier_pipeline/
│   │   └── main.go               # Sample app initializing all 3 tiers
│   └── systemd_user_service/
│       ├── myapp.service         # Example systemd user unit configuration
│       └── encrypt_secret.sh     # Helper script for systemd-creds --user
│
└── cmd/
    └── secretprotector/          # CLI tool for generating age/p12 keys & inspecting vaults
        └── main.go

```

---

### Component Breakdown

* **Root Level (`provider.go`)**: Keeps the core interface lightweight (`GetSecret(ctx, key)`). Users who only want standard features pull zero cloud SDK dependencies.
* **`libsecsecrets`**: Provides core AES-256-GCM symmetric encryption/decryption (`v1:gcm:...`) and key zeroing primitives (`ZeroBuffer`).
* **`providers/oskeyring`**: Uses Go build tags (`//go:build linux` / `//go:build windows`) to compile OS-native secret getters without Cgo or GUI keyring daemons.
* **`providers/agefile`**: Encapsulates `filippo.io/age` parsing for local `.env.age` files used in GitOps and staging workflows.
* **`providers/aesgcm`**: Connects Section 1's `libsecsecrets` symmetric obfuscation engine directly into the provider chain.
* **`providers/remote/*`**: Subpackaged independently so pulling in `hashivault` or `awssm` does not force cloud SDK dependencies on light local builds.

---

