# Sample Application Integration Guide

This document explains how to integrate the `libsecsecrets` library into your Go application (e.g., an SFTP client, API consumer, or database connector) for secure, runtime decryption of secrets.

---

## 1. Project Structure

Your application should follow a clean separation of concerns:

```text
/my-sftp-project
├── go.mod
├── config.json
└── main.go
```

---

## 2. Configuration (`config.json`)

Store the obfuscated password and the path to the master key in your configuration file.

```json
{
  "host": "sftp.example.com",
  "user": "deploy_user",
  "encrypted_pass": "v1:gcm:A1B2C3D4...Base64EncryptedCiphertext==",
  "master_key_path": "/etc/secrets/key.txt"
}
```

---

## 3. Bootstrap Sequence (`main.go`)

Follow these steps to safely initialize your application using `libsecsecrets`.

```go
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"time"

	"criticalsys.net/secretprotector/pkg/libsecsecrets"
)

type Config struct {
	Host          string `json:"host"`
	User          string `json:"user"`
	EncryptedPass string `json:"encrypted_pass"`
	MasterKeyPath string `json:"master_key_path"`
}

func main() {
	// 1. Create a Context with Timeout for initialization
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// 2. Load Configuration
	cfg, err := loadConfig("config.json")
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// 3. Resolve Master Key
	// Priority: Flag (if any) > Environment Variable > File Path from config
	// Note: 'masterKey' is a []byte returned by ResolveKey.
	masterKey, err := libsecsecrets.ResolveKey(ctx, "", "SECRETPROTECTOR_MASTER_KEY", cfg.MasterKeyPath)
	if err != nil {
		if errors.Is(err, libsecsecrets.ErrNoKeySource) {
			log.Fatalf("Security failure: No master key source found.")
		} else if errors.Is(err, libsecsecrets.ErrInsecurePermissions) || errors.Is(err, libsecsecrets.ErrInsecureLocation) {
			log.Fatalf("Security boundary violation: %v", err)
		}
		log.Fatalf("Security failure resolving key: %v", err)
	}
	// Immediately defer zeroing the buffer to ensure it's cleared on exit.
	defer libsecsecrets.ZeroBuffer(masterKey)

	// 4. Decrypt Secret at Runtime
	// Approach A: High-Security Zero-Allocation Byte-Slice Pattern (Recommended)
	passBytes, err := libsecsecrets.DecryptBytes(ctx, []byte(cfg.EncryptedPass), masterKey)
	if err != nil {
		log.Fatalf("Decryption failure: %v", err)
	}
	// Zero out secret bytes immediately when function finishes
	defer libsecsecrets.ZeroBuffer(passBytes)

	// Approach B: String-Based Pattern (Convenience)
	// realPass, err := libsecsecrets.Decrypt(ctx, cfg.EncryptedPass, masterKey)

	// 5. Use Secret (Memory Only)
	fmt.Printf("Connecting to %s as %s...\n", cfg.Host, cfg.User)
	performSecureOperation(cfg.Host, cfg.User, passBytes)
}

func loadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func performSecureOperation(host, user string, pass []byte) {
	// Mock operation logic (e.g., SFTP, API, DB)
	// The 'pass' byte slice is never written to logs or disk
	fmt.Println("Secure operation established successfully.")
}
```

---

## 4. Security Best Practices

*   **Memory Hygiene:** Never print decrypted passwords or master keys to `stdout` or log files. Always use `defer libsecsecrets.ZeroBuffer(masterKey)` and `defer libsecsecrets.ZeroBuffer(passBytes)` to clear sensitive keys and plaintext byte buffers from memory as soon as cryptographic operations complete. Note that `libsecsecrets` uses `sync.Pool` internally for efficient buffer management during key generation, but manual zeroing of resolved keys and plaintext byte buffers remains a critical responsibility of the consumer application.
*   **Zero-Allocation Byte API:** Prefer `DecryptBytes(ctx, []byte(ciphertext), masterKey)` over string `Decrypt`, as string decryption allocates heap memory that cannot be explicitly zeroed before garbage collection.
*   **Context Support:** Use `context.Context` (e.g., `context.WithTimeout`) for all library calls to support timeouts and cancellations in production service environments.
*   **Fail Fast & Fail Safe:** If the master key cannot be resolved or decryption fails, the application **must** terminate immediately before attempting any unauthenticated operational connections.
*   **Key File Protection:** On Linux, ensure key files have owner-only `0400` permissions. On Windows, store key files in restricted user profile directories, avoiding shared paths such as `C:\Users\Public` or `%TEMP%`.
