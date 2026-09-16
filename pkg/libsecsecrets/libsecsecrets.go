// Package libsecsecrets provides a professional-grade implementation for password obfuscation in Go.
// It implements AES-256-GCM authenticated encryption and a multi-source master key resolution strategy.
//
// Objective:
// To ensure that sensitive credentials (such as SFTP passwords, API keys, or DB credentials)
// are never stored in plaintext on disk or in version control by using standardized
// cryptographic methods and secure key handling.
//
// Core Components:
// 1. Key Resolution: Hierarchical search (Flag > Env > File) with platform security enforcement.
// 2. Cryptography: AES-256-GCM providing confidentiality and integrity.
// 3. Memory Safety: Utilities for zeroing sensitive buffers to minimize exposure.
// 4. Resource Optimization: sync.Pool for efficient buffer management.
//
// Data Flow:
// 1. Key Generation: CSPRNG -> 32-byte slice -> Hex String.
// 2. Key Resolution: Input (Raw/Env/File) -> Validation -> 32-byte key.
// 3. Encryption: Plaintext + Key -> AES-GCM (Nonce + Seal) -> Base64 String.
// 4. Decryption: Base64 String + Key -> Base64 Decode -> AES-GCM (Open) -> Plaintext.
package libsecsecrets

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
)

// bytePool is a sync.Pool for reducing GC pressure on small byte slices.
var bytePool = sync.Pool{
	New: func() interface{} {
		b := make([]byte, 32)
		return &b
	},
}

var (
	// ErrInvalidKey is returned when the provided key is not a valid 32-byte hex string.
	ErrInvalidKey = errors.New("invalid key: expected 64-char hex or 32-byte raw string")
	// ErrNoKeySource is returned when no master key could be resolved from any source.
	ErrNoKeySource = errors.New("no master key found in provided sources")
	// ErrInsecureLocation is returned when a key file is stored in an insecure location.
	ErrInsecureLocation = errors.New("insecure key location detected")
	// ErrInsecurePermissions is returned when a key file has unsafe permissions.
	ErrInsecurePermissions = errors.New("insecure file permissions")
	// ErrCiphertextTooShort is returned when the data to decrypt is shorter than the nonce.
	ErrCiphertextTooShort = errors.New("ciphertext too short")
)

// ZeroBuffer fills the provided byte slice with zeros to clear sensitive data from memory.
// This is used to minimize the window of exposure for sensitive material in RAM.
func ZeroBuffer(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

var (
	mockMu      sync.RWMutex
	randReader  io.Reader                         = rand.Reader
	osReadFile  func(string) ([]byte, error)      = os.ReadFile
	osStat      func(string) (os.FileInfo, error) = os.Stat
	runtimeGOOS string                            = runtime.GOOS
)

// RandReader is an internal variable that can be mocked for testing.
// Deprecated: Use SetTestMocks helper in tests for thread safety.
var RandReader = rand.Reader

// OsReadFile is an internal variable that can be mocked for testing.
// Deprecated: Use SetTestMocks helper in tests for thread safety.
var OsReadFile = os.ReadFile

// OsStat is an internal variable that can be mocked for testing.
// Deprecated: Use SetTestMocks helper in tests for thread safety.
var OsStat = os.Stat

// RuntimeGOOS is an internal variable that can be mocked for testing.
// Deprecated: Use SetTestMocks helper in tests for thread safety.
var RuntimeGOOS = runtime.GOOS

func getRandReader() io.Reader {
	mockMu.RLock()
	defer mockMu.RUnlock()
	if RandReader != rand.Reader {
		return RandReader
	}
	return randReader
}

func getOsReadFile() func(string) ([]byte, error) {
	mockMu.RLock()
	defer mockMu.RUnlock()
	if fmt.Sprintf("%p", OsReadFile) != fmt.Sprintf("%p", os.ReadFile) {
		return OsReadFile
	}
	return osReadFile
}

func getOsStat() func(string) (os.FileInfo, error) {
	mockMu.RLock()
	defer mockMu.RUnlock()
	if fmt.Sprintf("%p", OsStat) != fmt.Sprintf("%p", os.Stat) {
		return OsStat
	}
	return osStat
}

func getRuntimeGOOS() string {
	mockMu.RLock()
	defer mockMu.RUnlock()
	if RuntimeGOOS != runtime.GOOS {
		return RuntimeGOOS
	}
	return runtimeGOOS
}

// DefaultKeyEnv is the default environment variable name used to store the master key.
const DefaultKeyEnv = "SECRETPROTECTOR_MASTER_KEY"

// EncryptedPrefix is the version/algorithm prefix for encrypted values.
// Format: v1:gcm:<base64-ciphertext>
// - v1: Version identifier for future algorithm upgrades
// - gcm: Algorithm identifier (AES-256-GCM)
const EncryptedPrefix = "v1:gcm:"

// IsEncrypted checks if a string or byte slice has the v1:gcm: encrypted prefix.
func IsEncrypted(s string) bool {
	return len(s) > len(EncryptedPrefix) && s[:len(EncryptedPrefix)] == EncryptedPrefix
}

// IsEncryptedBytes checks if a byte slice has the v1:gcm: encrypted prefix.
func IsEncryptedBytes(b []byte) bool {
	return len(b) > len(EncryptedPrefix) && string(b[:len(EncryptedPrefix)]) == EncryptedPrefix
}

// GenerateKey returns a 64-character hex string representing 32 bytes of entropy.
// It uses crypto/rand for cryptographically secure random number generation.
//
// Data Flow:
// 1. Create a 32-byte slice.
// 2. Populate with random bytes from CSPRNG.
// 3. Return as a hex-encoded string.
func GenerateKey() (string, error) {
	keyPtr := bytePool.Get().(*[]byte)
	key := *keyPtr
	defer func() {
		ZeroBuffer(key)
		bytePool.Put(keyPtr)
	}()

	if _, err := io.ReadFull(getRandReader(), key); err != nil {
		return "", fmt.Errorf("failed to generate random key: %w", err)
	}
	return hex.EncodeToString(key), nil
}

// ResolveKey finds and validates the master key from three possible sources in order of precedence:
// 1. raw: A direct hex string passed as an argument (Highest precedence).
// 2. env: An environment variable name containing the hex key.
// 3. file: A fully qualified file path containing the hex key (Lowest precedence).
//
// Data Flow:
// 1. Check if 'raw' (CLI flag) is provided.
// 2. If not, lookup the environment variable specified by 'env'.
// 3. If still not found, check the file path 'file' after validating permissions.
// 4. Validate the resulting string (must be 64-char hex or 32-byte raw).
// 5. Return the decoded 32-byte master key.
//
// Security Checks:
// - On Linux/Unix, it enforces owner-only permissions (0400/0600) on the key file.
// - On Windows, it prevents reading from insecure locations like "Public" or "Temp" directories.
func ResolveKey(ctx context.Context, raw, env, file string) ([]byte, error) {
	var keyStr string

	// Step 1: Check for raw key override.
	if raw != "" {
		keyStr = raw
	} else if env != "" {
		// Step 2: Resolve from environment variable.
		keyStr = os.Getenv(env)
	}

	// Step 3: Fallback to file resolution if still not found.
	if keyStr == "" && file != "" {
		var data []byte
		var err error
		if file == "-" {
			data, err = io.ReadAll(os.Stdin)
			if err != nil {
				return nil, fmt.Errorf("failed to read key file from stdin: %w", err)
			}
		} else {
			if err := validateFilePermissions(file); err != nil {
				return nil, err
			}
			data, err = getOsReadFile()(file)
			if err != nil {
				return nil, fmt.Errorf("failed to read key file: %w", err)
			}
		}
		keyStr = strings.TrimSpace(string(data))
	}

	if keyStr == "" {
		return nil, ErrNoKeySource
	}

	var key []byte
	var err error

	// Step 4: Validate format and length.
	if len(keyStr) == 64 {
		key, err = hex.DecodeString(keyStr)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrInvalidKey, err)
		}
	} else if len(keyStr) == 32 {
		key = []byte(keyStr)
	} else {
		return nil, fmt.Errorf("%w: got %d chars", ErrInvalidKey, len(keyStr))
	}

	return key, nil
}

// EncryptBytes takes a plaintext byte slice and a 32-byte master key, returning prefixed Base64-encoded bytes.
// Output format: v1:gcm:<base64(nonce + ciphertext)>
//
// Data Flow:
// 1. Validate key length (must be exactly 32 bytes).
// 2. Initialize AES-256 block cipher and GCM mode.
// 3. Generate a 12-byte CSPRNG nonce.
// 4. Encrypt and seal payload, prepending nonce.
// 5. Base64 encode and prepend v1:gcm: prefix.
func EncryptBytes(ctx context.Context, plain, key []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, ErrInvalidKey
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(getRandReader(), nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	ciphertext := gcm.Seal(nonce, nonce, plain, nil)
	base64Len := base64.StdEncoding.EncodedLen(len(ciphertext))
	buf := make([]byte, len(EncryptedPrefix)+base64Len)
	copy(buf, EncryptedPrefix)
	base64.StdEncoding.Encode(buf[len(EncryptedPrefix):], ciphertext)
	return buf, nil
}

// Encrypt takes a plaintext string and a 32-byte key, returning a prefixed Base64-encoded string.
// Output format: v1:gcm:<base64(nonce + ciphertext)>
func Encrypt(ctx context.Context, plain string, key []byte) (string, error) {
	b, err := EncryptBytes(ctx, []byte(plain), key)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// DecryptBytes takes a prefixed or raw Base64-encoded byte slice and a 32-byte master key.
// Accepts both v1:gcm: prefixed values (new format) and raw base64 (backwards compatible).
//
// Data Flow:
// 1. Strip v1:gcm: prefix if present.
// 2. Trim whitespace and newlines from input byte slice.
// 3. Base64 decode raw ciphertext buffer.
// 4. Validate minimum length against AES-GCM nonce size (12 bytes).
// 5. Decrypt and authenticate MAC tag using AES-256-GCM.
// 6. Return original plaintext bytes.
func DecryptBytes(ctx context.Context, encoded, key []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, ErrInvalidKey
	}

	// Trim whitespace first, then strip v1:gcm: prefix if present (backwards compatible with raw base64)
	cleanEncoded := bytes.TrimSpace(encoded)
	if IsEncryptedBytes(cleanEncoded) {
		cleanEncoded = cleanEncoded[len(EncryptedPrefix):]
	}

	data := make([]byte, base64.StdEncoding.DecodedLen(len(cleanEncoded)))
	n, err := base64.StdEncoding.Decode(data, cleanEncoded)
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64: %w", err)
	}
	data = data[:n]

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, ErrCiphertextTooShort
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	return plaintext, nil
}

// Decrypt takes a prefixed or raw Base64-encoded string and a 32-byte master key.
// Accepts both v1:gcm: prefixed values (new format) and raw base64 (backwards compatible).
func Decrypt(ctx context.Context, encoded string, key []byte) (string, error) {
	b, err := DecryptBytes(ctx, []byte(encoded), key)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// validateFilePermissions implements platform-specific security boundaries for key files.
//
// Objective:
// Prevent the use of master keys stored in locations that are accessible to other users
// or are inherently volatile/insecure.
//
// Enforcement:
// - Linux/Unix: Stat the file and check mode. Must be 0400 or 0600.
// - Windows: Path-based detection for "Public", "\temp\", or "/temp/".
func validateFilePermissions(path string) error {
	cleanPath := filepath.Clean(path)
	info, err := getOsStat()(cleanPath)
	if err != nil {
		return err
	}

	if getRuntimeGOOS() != "windows" {
		// Linux/Unix security: Ensure owner-only read (0400) or read/write (0600).
		mode := info.Mode().Perm()
		if mode != 0o400 && mode != 0o600 {
			return fmt.Errorf("%w: %o (expected 0400 or 0600)", ErrInsecurePermissions, mode)
		}
	} else {
		// Windows security: Check path against known insecure public/temp locations.
		absPath, err := filepath.Abs(cleanPath)
		if err != nil {
			absPath = cleanPath
		}
		lowerPath := strings.ToLower(absPath)
		sysTempDir := strings.ToLower(filepath.Clean(os.TempDir()))

		if strings.HasPrefix(lowerPath, strings.ToLower(filepath.Clean(`C:\Users\Public`))) ||
			strings.HasPrefix(lowerPath, strings.ToLower(filepath.Clean(`C:\Windows\Temp`))) ||
			(sysTempDir != "" && strings.HasPrefix(lowerPath, sysTempDir)) ||
			strings.Contains(lowerPath, `\temp\`) || strings.Contains(lowerPath, `/temp/`) ||
			strings.Contains(lowerPath, `c:\users\public`) {
			return fmt.Errorf("%w: %s", ErrInsecureLocation, path)
		}
	}
	return nil
}
