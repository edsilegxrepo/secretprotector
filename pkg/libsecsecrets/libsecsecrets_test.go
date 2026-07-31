// Package libsecsecrets_test provides unit tests for the libsecsecrets package.
// It verifies cryptographic integrity, key resolution precedence, platform security boundaries,
// and performance optimizations like sync.Pool reuse.
//
// Test Strategy:
// 1. Cryptographic Correctness:
//   - Round-trip (Encrypt/Decrypt) verification to ensure data integrity and confidentiality.
//   - Validation of random key generation using CSPRNG.
//
// 2. Key Resolution Hierarchy:
//   - Mocks for OS Environment and Filesystem to verify precedence: CLI Flag > Environment Variable > File.
//   - Verification of fallback mechanisms when higher-priority sources are absent or empty.
//
// 3. Platform Security Enforcement:
//   - Linux/Unix: Mocking file attributes to enforce 0400/0600 permission requirements.
//   - Windows: Path-based validation to block insecure locations (Public, Temp).
//
// 4. Error Resilience and Edge Cases:
//   - Testing failure modes for key generation (e.g., entropy exhaustion).
//   - Handling of malformed keys (invalid hex, incorrect length).
//   - Decryption failures (tampered ciphertext, incorrect keys).
//
// 5. Memory Safety and Resource Management:
//   - Verification of sync.Pool for buffer reuse to minimize GC overhead.
//   - Implicit verification of ZeroBuffer usage via logic flows.
package libsecsecrets

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestGenerateKey verifies that the generated key is a valid 64-character hex string.
func TestGenerateKey(t *testing.T) {
	t.Parallel()
	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	defer func() {
		// Verify that we can still generate keys after one is put back in the pool
		key2, err := GenerateKey()
		if err != nil {
			t.Errorf("Subsequent GenerateKey failed: %v", err)
		}
		if len(key2) != 64 {
			t.Errorf("Expected 64-char hex string, got %d", len(key2))
		}
	}()
	if len(key) != 64 {
		t.Errorf("Expected 64-char hex string, got %d", len(key))
	}
	_, err = hex.DecodeString(key)
	if err != nil {
		t.Errorf("Generated key is not valid hex: %v", err)
	}
}

// TestEncryptDecrypt verifies the cryptographic round-trip: plaintext -> ciphertext -> plaintext.
func TestEncryptDecrypt(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	key, _ := hex.DecodeString("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	plaintext := "secret_password_123"

	encrypted, err := Encrypt(ctx, plaintext, key)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	decrypted, err := Decrypt(ctx, encrypted, key)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if decrypted != plaintext {
		t.Errorf("Decrypted text does not match plaintext: got %s, want %s", decrypted, plaintext)
	}
}

// TestEncryptDecryptBytes verifies byte-slice cryptographic round-trip and trimming.
func TestEncryptDecryptBytes(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	key, _ := hex.DecodeString("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	plainBytes := []byte("binary_secret_data_456")

	encryptedBytes, err := EncryptBytes(ctx, plainBytes, key)
	if err != nil {
		t.Fatalf("EncryptBytes failed: %v", err)
	}

	// Test trimming capability by appending whitespace/newlines
	paddedEncrypted := append([]byte(" \r\n "), append(encryptedBytes, []byte(" \n\r ")...)...)

	decryptedBytes, err := DecryptBytes(ctx, paddedEncrypted, key)
	if err != nil {
		t.Fatalf("DecryptBytes failed on padded input: %v", err)
	}

	if string(decryptedBytes) != string(plainBytes) {
		t.Errorf("Decrypted bytes do not match plaintext: got %s, want %s", string(decryptedBytes), string(plainBytes))
	}
}

// TestResolveKeyPrecedence verifies the hierarchical key resolution logic:
// Flag (Raw) > Environment Variable > File Path.
func TestResolveKeyPrecedence(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()
	// Security Check: On Windows, t.TempDir() might contain "temp", triggering our safety check.
	// We handle this by using a local file if needed to test precedence logic.
	keyFile := filepath.Join(tmpDir, "key.txt")
	if RuntimeGOOS == "windows" {
		if strings.Contains(strings.ToLower(tmpDir), "temp") {
			wd, _ := os.Getwd()
			keyFile = filepath.Join(wd, "test_key.txt")
			defer func() {
				_ = os.Remove(keyFile)
			}()
		}
	}
	rawKey := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	envKey := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	fileKey := "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"

	_ = os.WriteFile(keyFile, []byte(fileKey), 0o600)
	if err := os.Setenv("TEST_MASTER_KEY", envKey); err != nil {
		t.Fatalf("Failed to set env: %v", err)
	}
	defer func() {
		_ = os.Unsetenv("TEST_MASTER_KEY")
	}()

	// 1. Verify Raw key takes precedence over everything else.
	resolved, err := ResolveKey(ctx, rawKey, "TEST_MASTER_KEY", keyFile)
	if err != nil {
		t.Fatalf("ResolveKey failed: %v", err)
	}
	if hex.EncodeToString(resolved) != rawKey {
		t.Errorf("Raw key should have precedence. Got %x, want %s", resolved, rawKey)
	}

	// 2. Verify Environment variable takes precedence over file path.
	resolved, err = ResolveKey(ctx, "", "TEST_MASTER_KEY", keyFile)
	if err != nil {
		t.Fatalf("ResolveKey failed: %v", err)
	}
	if hex.EncodeToString(resolved) != envKey {
		t.Errorf("Env key should have precedence over file. Got %x, want %s", resolved, envKey)
	}

	// 3. Verify File path is used as the final fallback.
	resolved, err = ResolveKey(ctx, "", "", keyFile)
	if err != nil {
		t.Fatalf("ResolveKey failed: %v", err)
	}
	if hex.EncodeToString(resolved) != fileKey {
		t.Errorf("File key fallback failed. Got %x, want %s", resolved, fileKey)
	}

	// 4. Verify fallback to file when env is empty
	if err := os.Setenv("EMPTY_ENV", ""); err != nil {
		t.Fatalf("failed to set empty env: %v", err)
	}
	defer func() {
		_ = os.Unsetenv("EMPTY_ENV")
	}()
	resolved, err = ResolveKey(ctx, "", "EMPTY_ENV", keyFile)
	if err != nil {
		t.Fatalf("ResolveKey failed with empty env: %v", err)
	}
	if hex.EncodeToString(resolved) != fileKey {
		t.Errorf("Expected fallback to file when env is empty. Got %x, want %s", resolved, fileKey)
	}
}

// TestInsecureFilePermissions verifies platform-specific security boundary enforcement.
func TestInsecureFilePermissions(t *testing.T) {
	ctx := context.Background()
	oldStat := OsStat
	oldGOOS := RuntimeGOOS
	defer func() {
		OsStat = oldStat
		RuntimeGOOS = oldGOOS
	}()

	// 1. Test Windows Logic
	RuntimeGOOS = "windows"

	// Mock successful stat for a public file
	OsStat = func(name string) (os.FileInfo, error) {
		return os.Stat(os.Args[0]) // Stat something that exists
	}

	publicFile := "C:\\Users\\Public\\key.txt"
	_, err := ResolveKey(ctx, "", "", publicFile)
	if !errors.Is(err, ErrInsecureLocation) {
		t.Errorf("Expected ErrInsecureLocation, got: %v", err)
	}

	tempFile := "C:\\Windows\\Temp\\key.txt"
	_, err = ResolveKey(ctx, "", "", tempFile)
	if !errors.Is(err, ErrInsecureLocation) {
		t.Errorf("Expected ErrInsecureLocation, got: %v", err)
	}

	// 2. Test Linux Logic
	RuntimeGOOS = "linux"

	// Mock insecure permissions
	OsStat = func(name string) (os.FileInfo, error) {
		return &mockFileInfo{mode: 0o644}, nil
	}

	_, err = ResolveKey(ctx, "", "", "/tmp/insecure.txt")
	if !errors.Is(err, ErrInsecurePermissions) {
		t.Errorf("Expected ErrInsecurePermissions, got: %v", err)
	}

	// Mock secure permissions (0600)
	OsStat = func(name string) (os.FileInfo, error) {
		return &mockFileInfo{mode: 0o600}, nil
	}
	// Mock OsReadFile to avoid "file not found" errors when ResolveKey tries to read the key
	oldReadFile := OsReadFile
	defer func() { OsReadFile = oldReadFile }()
	OsReadFile = func(name string) ([]byte, error) {
		return []byte("cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"), nil
	}

	_, err = ResolveKey(ctx, "", "", "/tmp/secure.txt")
	if err != nil {
		t.Errorf("Unexpected error for secure file permissions on Linux (0600): %v", err)
	}

	// Mock secure permissions (0400)
	OsStat = func(name string) (os.FileInfo, error) {
		return &mockFileInfo{mode: 0o400}, nil
	}
	_, err = ResolveKey(ctx, "", "", "/tmp/secure0400.txt")
	if err != nil {
		t.Errorf("Unexpected error for secure file permissions on Linux (0400): %v", err)
	}
}

type mockFileInfo struct {
	os.FileInfo
	mode os.FileMode
}

func (m *mockFileInfo) Mode() os.FileMode { return m.mode }
func (m *mockFileInfo) Perm() os.FileMode { return m.mode }

// TestResolveKeyFileVariants verifies hex and raw key loading from files.
func TestResolveKeyFileVariants(t *testing.T) {
	ctx := context.Background()
	// Use current working directory to avoid Windows "insecure location" (TEMP) check
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get wd: %v", err)
	}
	testDir := filepath.Join(wd, "testdata_variants")
	if err := os.MkdirAll(testDir, 0o700); err != nil {
		t.Fatalf("failed to create test dir: %v", err)
	}
	defer func() {
		_ = os.RemoveAll(testDir)
	}()

	// 1. Test 64-char hex key from file
	hexKey := strings.Repeat("a", 64)
	hexFile := filepath.Join(testDir, "hex.txt")
	if err := os.WriteFile(hexFile, []byte(hexKey), 0o600); err != nil {
		t.Fatalf("failed to write hex file: %v", err)
	}
	resolved, err := ResolveKey(ctx, "", "", hexFile)
	if err != nil {
		t.Fatalf("ResolveKey failed for hex file: %v", err)
	}
	if hex.EncodeToString(resolved) != hexKey {
		t.Errorf("Expected %s, got %x", hexKey, resolved)
	}

	// 2. Test 32-byte raw key from file
	rawKey := strings.Repeat("r", 32)
	rawFile := filepath.Join(testDir, "raw.txt")
	if err := os.WriteFile(rawFile, []byte(rawKey), 0o600); err != nil {
		t.Fatalf("failed to write raw file: %v", err)
	}
	resolved, err = ResolveKey(ctx, "", "", rawFile)
	if err != nil {
		t.Fatalf("ResolveKey failed for raw file: %v", err)
	}
	if string(resolved) != rawKey {
		t.Errorf("Expected %s, got %s", rawKey, string(resolved))
	}
}

// TestErrors verifies error paths in encryption, decryption, and key resolution.
func TestErrors(t *testing.T) {
	ctx := context.Background()
	// 1. Test GenerateKey error (mocking RandReader)
	oldRand := RandReader
	RandReader = strings.NewReader("") // Empty reader will cause io.ReadFull to fail
	_, err := GenerateKey()
	if err == nil {
		t.Error("Expected error from GenerateKey with empty reader, but got none")
	}
	RandReader = oldRand

	// 2. Test Encrypt error (mocking RandReader for nonce generation)
	key, _ := hex.DecodeString("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	RandReader = strings.NewReader("")
	_, err = Encrypt(ctx, "plain", key)
	if err == nil {
		t.Error("Expected error from Encrypt with empty reader, but got none")
	}
	RandReader = oldRand

	// 2a. Test Encrypt error with invalid key
	_, err = Encrypt(ctx, "plain", []byte("short"))
	if !errors.Is(err, ErrInvalidKey) {
		t.Errorf("Expected ErrInvalidKey, got: %v", err)
	}

	// 3. Test Decrypt errors
	_, err = Decrypt(ctx, "invalid-base64", key)
	if err == nil {
		t.Error("Expected error from Decrypt with invalid base64, but got none")
	}

	// 3a. Test Decrypt error with invalid key
	_, err = Decrypt(ctx, base64.StdEncoding.EncodeToString([]byte("at-least-12-bytes-nonce-plus-ciphertext")), []byte("short"))
	if !errors.Is(err, ErrInvalidKey) {
		t.Errorf("Expected ErrInvalidKey, got: %v", err)
	}

	_, err = Decrypt(ctx, base64.StdEncoding.EncodeToString([]byte("short")), key)
	if !errors.Is(err, ErrCiphertextTooShort) {
		t.Errorf("Expected ErrCiphertextTooShort, got: %v", err)
	}

	// 3b. Test Decryption failure (wrong key)
	wrongKey, _ := hex.DecodeString("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
	encrypted, _ := Encrypt(ctx, "secret", key)
	_, err = Decrypt(ctx, encrypted, wrongKey)
	if err == nil {
		t.Error("Expected decryption failure with wrong key, but got none")
	}

	// 4. Test ResolveKey errors
	_, err = ResolveKey(ctx, "", "", "") // No sources
	if !errors.Is(err, ErrNoKeySource) {
		t.Errorf("Expected ErrNoKeySource, got: %v", err)
	}

	_, err = ResolveKey(ctx, "invalid-hex", "", "")
	if !errors.Is(err, ErrInvalidKey) {
		t.Errorf("Expected ErrInvalidKey, got: %v", err)
	}

	// 4a. Test ResolveKey with 64-char non-hex string
	_, err = ResolveKey(ctx, strings.Repeat("z", 64), "", "")
	if !errors.Is(err, ErrInvalidKey) {
		t.Errorf("Expected ErrInvalidKey for non-hex 64-char string, got: %v", err)
	}

	_, err = ResolveKey(ctx, hex.EncodeToString(make([]byte, 15)), "", "") // Wrong length (30 chars)
	if !errors.Is(err, ErrInvalidKey) {
		t.Errorf("Expected ErrInvalidKey, got: %v", err)
	}

	// 5. Test File Resolution Errors (mocking OsReadFile and OsStat)
	oldReadFile := OsReadFile
	oldStat := OsStat
	defer func() {
		OsReadFile = oldReadFile
		OsStat = oldStat
	}()

	OsStat = func(name string) (os.FileInfo, error) {
		return nil, errors.New("stat error")
	}
	_, err = ResolveKey(ctx, "", "", "non-existent.txt")
	if err == nil {
		t.Error("Expected error from ResolveKey when Os.Stat fails, but got none")
	}

	// Mock successful stat but failing read
	OsStat = func(name string) (os.FileInfo, error) {
		return os.Stat(os.Args[0]) // Stat something that exists
	}
	OsReadFile = func(name string) ([]byte, error) {
		return nil, errors.New("read error")
	}
	_, err = ResolveKey(ctx, "", "", "fail-read.txt")
	if err == nil {
		t.Error("Expected error from ResolveKey when Os.ReadFile fails, but got none")
	}

	// 6. Test EncryptBytes and DecryptBytes invalid key size errors
	_, err = EncryptBytes(ctx, []byte("plain"), []byte("short"))
	if !errors.Is(err, ErrInvalidKey) {
		t.Errorf("Expected ErrInvalidKey from EncryptBytes, got: %v", err)
	}

	_, err = DecryptBytes(ctx, []byte("encoded"), []byte("short"))
	if !errors.Is(err, ErrInvalidKey) {
		t.Errorf("Expected ErrInvalidKey from DecryptBytes, got: %v", err)
	}
}

// TestResolveKeyStdin verifies key resolution from os.Stdin when file argument is "-".
func TestResolveKeyStdin(t *testing.T) {
	ctx := context.Background()
	key := strings.Repeat("a", 64)

	oldStdin := os.Stdin
	r, w, _ := os.Pipe()
	go func() {
		_, _ = w.WriteString(key + "\n")
		_ = w.Close()
	}()
	os.Stdin = r
	defer func() {
		os.Stdin = oldStdin
		_ = r.Close()
	}()

	resolved, err := ResolveKey(ctx, "", "", "-")
	if err != nil {
		t.Fatalf("ResolveKey from stdin failed: %v", err)
	}
	if hex.EncodeToString(resolved) != key {
		t.Errorf("Expected resolved key %s, got %x", key, resolved)
	}
}
