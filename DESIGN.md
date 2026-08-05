This specification outlines a professional-grade implementation for password and secret obfuscation in Go. By externalizing the logic into a **Library**, you ensure that the **CLI** (used by admins/DevOps) and the **Application** (used by the runtime) stay perfectly synchronized. The library is designed to protect any sensitive credential, using an SFTP client as a primary implementation example.

---

## 1. Library Specification (`/pkg/libsecsecrets`)
The library is the single source of truth for cryptographic operations.

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



### Summary of Responsibilities
* **Library:** "How" we encrypt (AES-GCM).
* **CLI:** "How" we prepare the data (Manual/Admin).
* **App:** "How" we use the data (Automated/Runtime).
* **Environment:** "Where" we keep the Master Key (OS Level).

---

